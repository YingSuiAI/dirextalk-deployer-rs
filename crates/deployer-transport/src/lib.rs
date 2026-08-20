//! Narrow, in-process SSH/SFTP transport for the GCP deployer.
//!
//! The public API intentionally has no stringly typed remote-command method.
#![allow(clippy::missing_errors_doc)]

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ssh2::{ExtendedData, Session};
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const IO_TIMEOUT: Duration = Duration::from_mins(1);
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;
const MAX_BOOTSTRAP_RECEIPT: usize = 64 * 1024;
const PRODUCT_BOOTSTRAP_PATH: &str = "/var/dirextalk-message-server/p2p/bootstrap.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeyPin {
    pub algorithm: HostKeyAlgorithm,
    pub sha256: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyAlgorithm {
    Rsa,
    Dss,
    Ecdsa256,
    Ecdsa384,
    Ecdsa521,
    Ed25519,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, TransportError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TransportError::InvalidDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn calculate(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteArtifact {
    HostInstaller,
    InstallRequest,
    ReleaseBundle,
    ReceiptKey,
}

impl RemoteArtifact {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::HostInstaller => "/var/tmp/dirextalk-host-installer",
            Self::InstallRequest => "/var/tmp/dirextalk-install-request.json",
            Self::ReleaseBundle => "/var/tmp/dirextalk-release-bundle.tar",
            Self::ReceiptKey => "/var/tmp/dirextalk-receipt.key",
        }
    }

    const fn mode(self) -> i32 {
        match self {
            Self::HostInstaller => 0o700,
            Self::InstallRequest | Self::ReleaseBundle | Self::ReceiptKey => 0o600,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixedRemoteCommand {
    RunHostInstaller { request_sha256: Sha256Digest },
    VerifyCanonicalRuntime,
    VerifyHttps { name: DnsName },
    VerifyUpdater,
    AuthoritativeDns { server: IpAddr, name: DnsName },
    RecursiveDns { resolver: IpAddr, name: DnsName },
}

impl FixedRemoteCommand {
    fn command(&self) -> String {
        match self {
            Self::RunHostInstaller { request_sha256 } => format!(
                "/usr/bin/sudo --non-interactive {} --request-sha256 {}",
                RemoteArtifact::HostInstaller.path(),
                request_sha256
            ),
            Self::VerifyCanonicalRuntime => String::from(
                "/usr/bin/sudo --non-interactive /usr/bin/docker compose --project-name dirextalk-p2p --file /var/dirextalk-message-server/docker-compose.yml ps --format json",
            ),
            Self::VerifyHttps { name } => format!(
                "/usr/bin/curl --fail --silent --show-error --max-time 10 https://{}/_matrix/client/versions",
                name.hostname()
            ),
            Self::VerifyUpdater => String::from(
                "/usr/bin/sudo --non-interactive /usr/bin/systemctl is-active dirextalk-updater.service",
            ),
            Self::AuthoritativeDns { server, name } => {
                format!("/usr/bin/dig +time=5 +tries=1 +short A @{server} {name}")
            }
            Self::RecursiveDns { resolver, name } => {
                format!("/usr/bin/dig +time=5 +tries=1 +short A @{resolver} {name}")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsName(String);

impl DnsName {
    pub fn parse(value: impl Into<String>) -> Result<Self, TransportError> {
        let value = value.into();
        let normalized = value.trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() > 253
            || normalized.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(TransportError::InvalidDnsName);
        }
        Ok(Self(format!("{normalized}.")))
    }

    fn hostname(&self) -> &str {
        self.0
            .strip_suffix('.')
            .expect("validated DNS name is absolute")
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: i32,
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsProofRequest {
    pub name: DnsName,
    pub expected_ipv4: Ipv4Addr,
    pub authoritative_server: IpAddr,
    pub public_recursive_resolver: IpAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsProof {
    pub name: DnsName,
    pub expected_ipv4: Ipv4Addr,
    pub authoritative_answers: Vec<Ipv4Addr>,
    pub recursive_answers: Vec<Ipv4Addr>,
}

pub trait HostTransport {
    fn upload(&mut self, artifact: RemoteArtifact, bytes: &[u8]) -> Result<(), TransportError>;
    fn execute(&mut self, command: &FixedRemoteCommand) -> Result<CommandOutput, TransportError>;
    fn read_product_bootstrap(&mut self) -> Result<SecretBytes, TransportError>;

    fn prove_dns(&mut self, request: &DnsProofRequest) -> Result<DnsProof, TransportError> {
        if request.authoritative_server == request.public_recursive_resolver
            || !is_public_ip(request.authoritative_server)
            || !is_public_ip(request.public_recursive_resolver)
        {
            return Err(TransportError::InvalidDnsProofServers);
        }
        let authoritative = self.execute(&FixedRemoteCommand::AuthoritativeDns {
            server: request.authoritative_server,
            name: request.name.clone(),
        })?;
        let recursive = self.execute(&FixedRemoteCommand::RecursiveDns {
            resolver: request.public_recursive_resolver,
            name: request.name.clone(),
        })?;
        let authoritative_answers = parse_dns_answers(&authoritative)?;
        let recursive_answers = parse_dns_answers(&recursive)?;
        if !authoritative_answers.contains(&request.expected_ipv4)
            || !recursive_answers.contains(&request.expected_ipv4)
        {
            return Err(TransportError::DnsProofMismatch);
        }
        Ok(DnsProof {
            name: request.name.clone(),
            expected_ipv4: request.expected_ipv4,
            authoritative_answers,
            recursive_answers,
        })
    }
}

pub struct SshClient {
    session: Session,
}

impl SshClient {
    /// Connects and authenticates only after the server key exactly matches `pin`.
    pub fn connect_with_private_key(
        address: SocketAddr,
        username: &str,
        private_key: &Path,
        pin: &HostKeyPin,
    ) -> Result<Self, TransportError> {
        validate_username(username)?;
        let tcp = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.set_timeout(u32::try_from(IO_TIMEOUT.as_millis()).unwrap_or(u32::MAX));
        session.handshake()?;
        let observed = observed_pin(&session)?;
        verify_host_key(pin, &observed)?;
        session.userauth_pubkey_file(username, None, private_key, None)?;
        if !session.authenticated() {
            return Err(TransportError::Authentication);
        }
        Ok(Self { session })
    }

    /// Reads a host key without authenticating. Callers may show and persist this first-use pin,
    /// but must reconnect with `connect_with_private_key` before any upload or command.
    pub fn observe_host_key(address: SocketAddr) -> Result<HostKeyPin, TransportError> {
        let tcp = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.set_timeout(u32::try_from(IO_TIMEOUT.as_millis()).unwrap_or(u32::MAX));
        session.handshake()?;
        observed_pin(&session)
    }
}

impl HostTransport for SshClient {
    fn upload(&mut self, artifact: RemoteArtifact, bytes: &[u8]) -> Result<(), TransportError> {
        let final_path = Path::new(artifact.path());
        let temporary = PathBuf::from(format!("{}.upload", artifact.path()));
        let sftp = self.session.sftp()?;
        let mut file = sftp.create(&temporary)?;
        file.setstat(ssh2::FileStat {
            size: None,
            uid: None,
            gid: None,
            perm: Some(u32::try_from(artifact.mode()).expect("fixed mode is non-negative")),
            atime: None,
            mtime: None,
        })?;
        file.write_all(bytes)?;
        file.fsync()?;
        drop(file);
        sftp.rename(&temporary, final_path, None)?;
        let mut uploaded = sftp.open(final_path)?;
        let mut hasher = Sha256::new();
        let mut total = 0usize;
        let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = uploaded.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count)
                .ok_or(TransportError::UploadVerification)?;
            if total > bytes.len() {
                return Err(TransportError::UploadVerification);
            }
            hasher.update(&buffer[..count]);
        }
        if total != bytes.len()
            || format!("{:x}", hasher.finalize()) != Sha256Digest::calculate(bytes).as_str()
        {
            return Err(TransportError::UploadVerification);
        }
        Ok(())
    }

    fn execute(&mut self, command: &FixedRemoteCommand) -> Result<CommandOutput, TransportError> {
        self.execute_bounded(&command.command(), MAX_COMMAND_OUTPUT)
    }

    fn read_product_bootstrap(&mut self) -> Result<SecretBytes, TransportError> {
        let output = self.execute_bounded(
            &format!("/usr/bin/sudo --non-interactive /usr/bin/cat {PRODUCT_BOOTSTRAP_PATH}"),
            MAX_BOOTSTRAP_RECEIPT,
        )?;
        if output.exit_status != 0 {
            return Err(TransportError::BootstrapRead(output.exit_status));
        }
        Ok(SecretBytes(Zeroizing::new(output.stdout)))
    }
}

impl SshClient {
    fn execute_bounded(
        &mut self,
        command: &str,
        maximum_bytes: usize,
    ) -> Result<CommandOutput, TransportError> {
        let mut channel = self.session.channel_session()?;
        channel.handle_extended_data(ExtendedData::Merge)?;
        channel.exec(command)?;
        channel.send_eof()?;
        let mut stdout = Vec::new();
        Read::by_ref(&mut channel)
            .take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut stdout)?;
        if stdout.len() > maximum_bytes {
            return Err(TransportError::OutputTooLarge(maximum_bytes));
        }
        channel.wait_close()?;
        Ok(CommandOutput {
            stdout,
            stderr: Vec::new(),
            exit_status: channel.exit_status()?,
        })
    }
}

pub fn verify_host_key(expected: &HostKeyPin, observed: &HostKeyPin) -> Result<(), TransportError> {
    if expected == observed {
        Ok(())
    } else {
        Err(TransportError::HostKeyMismatch {
            expected: expected.clone(),
            observed: observed.clone(),
        })
    }
}

fn observed_pin(session: &Session) -> Result<HostKeyPin, TransportError> {
    let (key, kind) = session.host_key().ok_or(TransportError::MissingHostKey)?;
    if matches!(kind, ssh2::HostKeyType::Dss | ssh2::HostKeyType::Unknown) {
        return Err(TransportError::UnsupportedHostKeyAlgorithm);
    }
    Ok(HostKeyPin {
        algorithm: match kind {
            ssh2::HostKeyType::Rsa => HostKeyAlgorithm::Rsa,
            ssh2::HostKeyType::Dss => HostKeyAlgorithm::Dss,
            ssh2::HostKeyType::Ecdsa256 => HostKeyAlgorithm::Ecdsa256,
            ssh2::HostKeyType::Ecdsa384 => HostKeyAlgorithm::Ecdsa384,
            ssh2::HostKeyType::Ecdsa521 => HostKeyAlgorithm::Ecdsa521,
            ssh2::HostKeyType::Ed25519 => HostKeyAlgorithm::Ed25519,
            ssh2::HostKeyType::Unknown => HostKeyAlgorithm::Unknown,
        },
        sha256: Sha256Digest::calculate(key),
    })
}

fn parse_dns_answers(output: &CommandOutput) -> Result<Vec<Ipv4Addr>, TransportError> {
    if output.exit_status != 0 {
        return Err(TransportError::DnsProofCommand(output.exit_status));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| TransportError::InvalidDnsOutput)?;
    let answers: Result<Vec<_>, _> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().parse::<Ipv4Addr>())
        .collect();
    let answers = answers.map_err(|_| TransportError::InvalidDnsOutput)?;
    if answers.is_empty() {
        return Err(TransportError::InvalidDnsOutput);
    }
    Ok(answers)
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast())
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local())
        }
    }
}

fn validate_username(username: &str) -> Result<(), TransportError> {
    if username.is_empty()
        || username.len() > 32
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(TransportError::InvalidUsername)
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("SSH host key mismatch (expected {expected:?}, observed {observed:?})")]
    HostKeyMismatch {
        expected: HostKeyPin,
        observed: HostKeyPin,
    },
    #[error("server did not present an SSH host key")]
    MissingHostKey,
    #[error("server uses an unsupported SSH host-key algorithm")]
    UnsupportedHostKeyAlgorithm,
    #[error("SSH authentication failed")]
    Authentication,
    #[error("uploaded artifact size or digest verification failed")]
    UploadVerification,
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid DNS name")]
    InvalidDnsName,
    #[error("invalid SSH username")]
    InvalidUsername,
    #[error("DNS proof requires distinct public authoritative and recursive servers")]
    InvalidDnsProofServers,
    #[error("DNS proof command exited with status {0}")]
    DnsProofCommand(i32),
    #[error("DNS proof returned invalid or empty A records")]
    InvalidDnsOutput,
    #[error("authoritative and recursive DNS did not both return the expected address")]
    DnsProofMismatch,
    #[error("remote command output exceeded the {0}-byte limit")]
    OutputTooLarge(usize),
    #[error("product bootstrap receipt read exited with status {0}")]
    BootstrapRead(i32),
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("SSH failed: {0}")]
    Ssh(#[from] ssh2::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn pin(byte: u8) -> HostKeyPin {
        HostKeyPin {
            algorithm: HostKeyAlgorithm::Ed25519,
            sha256: Sha256Digest::parse(format!("{byte:02x}").repeat(32)).unwrap(),
        }
    }

    #[test]
    fn rejects_host_key_mismatch() {
        assert!(matches!(
            verify_host_key(&pin(1), &pin(2)),
            Err(TransportError::HostKeyMismatch { .. })
        ));
    }

    #[test]
    fn accepts_exact_host_key_pin() {
        verify_host_key(&pin(1), &pin(1)).unwrap();
    }

    #[test]
    fn rejects_dns_shell_metacharacters() {
        assert!(DnsName::parse("example.com; id").is_err());
        assert!(DnsName::parse("$(id).example.com").is_err());
    }

    #[test]
    fn command_surface_is_fixed_and_typed() {
        let command = FixedRemoteCommand::RunHostInstaller {
            request_sha256: Sha256Digest::parse("ab".repeat(32)).unwrap(),
        };
        assert_eq!(
            command.command(),
            format!(
                "/usr/bin/sudo --non-interactive /var/tmp/dirextalk-host-installer --request-sha256 {}",
                "ab".repeat(32)
            )
        );
    }

    struct FakeTransport {
        outputs: VecDeque<CommandOutput>,
    }

    impl HostTransport for FakeTransport {
        fn upload(
            &mut self,
            _artifact: RemoteArtifact,
            _bytes: &[u8],
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn execute(
            &mut self,
            _command: &FixedRemoteCommand,
        ) -> Result<CommandOutput, TransportError> {
            Ok(self.outputs.pop_front().unwrap())
        }

        fn read_product_bootstrap(&mut self) -> Result<SecretBytes, TransportError> {
            Ok(SecretBytes(Zeroizing::new(b"{}".to_vec())))
        }
    }

    #[test]
    fn dns_proof_requires_expected_authoritative_and_recursive_answer() {
        let output = |answer: &str| CommandOutput {
            stdout: format!("{answer}\n").into_bytes(),
            stderr: Vec::new(),
            exit_status: 0,
        };
        let request = DnsProofRequest {
            name: DnsName::parse("service.example.com").unwrap(),
            expected_ipv4: "203.0.113.10".parse().unwrap(),
            authoritative_server: "9.9.9.9".parse().unwrap(),
            public_recursive_resolver: "8.8.8.8".parse().unwrap(),
        };
        let mut transport = FakeTransport {
            outputs: VecDeque::from([output("203.0.113.10"), output("203.0.113.11")]),
        };
        assert!(matches!(
            transport.prove_dns(&request),
            Err(TransportError::DnsProofMismatch)
        ));
    }

    #[test]
    fn bootstrap_bytes_are_redacted_from_debug_output() {
        let secret = SecretBytes(Zeroizing::new(b"syt_secret".to_vec()));
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    }
}
