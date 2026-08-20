use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{GcpError, Result};

const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const SANITIZED_ENVIRONMENT: [&str; 7] = [
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_CORE_ACCOUNT",
    "CLOUDSDK_CORE_DISABLE_PROMPTS",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
];

#[derive(Clone)]
pub struct OAuthToken {
    pub access_token: SecretString,
    /// Stable Google OIDC subject (`sub`) used for authorization and persisted
    /// identity comparisons. It must never be included in public output.
    pub principal: String,
    pub expires_at: Option<Instant>,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthToken")
            .field("access_token", &"[REDACTED]")
            .field("principal", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Fails closed when a deployment is resumed by a different Google account.
/// The returned error deliberately omits both opaque subjects.
pub fn require_oauth_principal(expected: &str, observed: &str) -> Result<()> {
    if expected == observed {
        Ok(())
    } else {
        Err(GcpError::Authentication(
            "authenticated Google account changed".into(),
        ))
    }
}

/// Official `gcloud` authentication broker using a private configuration tree.
pub struct GcloudAuthBroker {
    home: PathBuf,
    config_dir: PathBuf,
    process: Arc<dyn GcloudProcess>,
    subject_resolver: Arc<dyn SubjectResolver>,
}

impl std::fmt::Debug for GcloudAuthBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GcloudAuthBroker")
            .field("config_dir", &self.config_dir)
            .finish_non_exhaustive()
    }
}

impl GcloudAuthBroker {
    pub fn for_home(home: &Path) -> Result<Self> {
        crate::ensure_tls_provider();
        let subject_resolver = GoogleSubjectResolver::new()?;
        Ok(Self {
            home: home.to_path_buf(),
            config_dir: home.join(".dirextalk/gcloud"),
            process: Arc::new(RealGcloudProcess),
            subject_resolver: Arc::new(subject_resolver),
        })
    }

    pub async fn login(&self) -> Result<OAuthToken> {
        let output = self
            .run(&["auth", "login", "--brief"], OutputMode::Interactive)
            .await?;
        if !output.success {
            return Err(GcpError::GcloudUnauthenticated);
        }
        self.token().await?.ok_or(GcpError::GcloudUnauthenticated)
    }

    pub async fn token(&self) -> Result<Option<OAuthToken>> {
        if !self.has_active_account().await? {
            return Ok(None);
        }
        let output = self
            .run(&["auth", "print-access-token"], OutputMode::Captured)
            .await?;
        if !output.success {
            return Err(GcpError::GcloudUnauthenticated);
        }
        let access_token = parse_access_token(&output.stdout)?;
        let principal = self.subject_resolver.resolve(&access_token).await?;
        Ok(Some(OAuthToken {
            access_token,
            principal,
            expires_at: None,
        }))
    }

    pub async fn logout(&self) -> Result<()> {
        if !self.has_active_account().await? {
            return Ok(());
        }
        let output = self
            .run(
                &["auth", "revoke", "--all", "--quiet"],
                OutputMode::Interactive,
            )
            .await?;
        if output.success {
            Ok(())
        } else {
            Err(GcpError::Infrastructure(
                "gcloud authentication revoke failed".into(),
            ))
        }
    }

    async fn has_active_account(&self) -> Result<bool> {
        let output = self
            .run(
                &[
                    "auth",
                    "list",
                    "--filter=status:ACTIVE",
                    "--format=value(status)",
                ],
                OutputMode::Captured,
            )
            .await?;
        if !output.success {
            return Err(GcpError::Infrastructure(
                "gcloud authentication status failed".into(),
            ));
        }
        if output.stdout.len() > 1024 {
            return Err(GcpError::Contract(
                "gcloud authentication status output is invalid".into(),
            ));
        }
        let status = std::str::from_utf8(&output.stdout).map_err(|_| {
            GcpError::Contract("gcloud authentication status output is invalid".into())
        })?;
        let status = status.trim();
        if status.is_empty() {
            Ok(false)
        } else if status.lines().all(|line| line.trim() == "ACTIVE") {
            Ok(true)
        } else {
            Err(GcpError::Contract(
                "gcloud authentication status output is invalid".into(),
            ))
        }
    }

    async fn run(&self, args: &[&'static str], output: OutputMode) -> Result<GcloudProcessOutput> {
        prepare_isolated_config(&self.home, &self.config_dir)?;
        self.process
            .run(GcloudInvocation {
                args: args.to_vec(),
                config_dir: self.config_dir.clone(),
                output,
            })
            .await
    }

    #[cfg(test)]
    fn with_components(
        home: &Path,
        process: Arc<dyn GcloudProcess>,
        subject_resolver: Arc<dyn SubjectResolver>,
    ) -> Self {
        Self {
            home: home.to_path_buf(),
            config_dir: home.join(".dirextalk/gcloud"),
            process,
            subject_resolver,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Interactive,
    Captured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GcloudInvocation {
    args: Vec<&'static str>,
    config_dir: PathBuf,
    output: OutputMode,
}

struct GcloudProcessOutput {
    success: bool,
    stdout: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for GcloudProcessOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GcloudProcessOutput")
            .field("success", &self.success)
            .field("stdout", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
trait GcloudProcess: Send + Sync {
    async fn run(&self, invocation: GcloudInvocation) -> Result<GcloudProcessOutput>;
}

#[derive(Debug, Clone, Copy)]
struct RealGcloudProcess;

#[async_trait]
impl GcloudProcess for RealGcloudProcess {
    async fn run(&self, invocation: GcloudInvocation) -> Result<GcloudProcessOutput> {
        tokio::task::spawn_blocking(move || run_gcloud(&invocation))
            .await
            .map_err(|_| GcpError::Infrastructure("gcloud process task failed".into()))?
    }
}

fn run_gcloud(invocation: &GcloudInvocation) -> Result<GcloudProcessOutput> {
    let mut command = Command::new("gcloud");
    command.args(&invocation.args);
    command.env("CLOUDSDK_CONFIG", &invocation.config_dir);
    for name in SANITIZED_ENVIRONMENT {
        command.env_remove(name);
    }

    match invocation.output {
        OutputMode::Interactive => {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            let mut child = command
                .spawn()
                .map_err(|error| classify_process_error(&error))?;
            let mut stdout = child.stdout.take().ok_or_else(|| {
                GcpError::Infrastructure("gcloud interactive output is unavailable".into())
            })?;
            let copy_result = std::io::copy(&mut stdout, &mut std::io::stderr().lock());
            let status = child
                .wait()
                .map_err(|error| classify_process_error(&error))?;
            copy_result.map_err(|_| {
                GcpError::Infrastructure("could not relay gcloud interactive output".into())
            })?;
            Ok(GcloudProcessOutput {
                success: status.success(),
                stdout: Zeroizing::new(Vec::new()),
            })
        }
        OutputMode::Captured => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let output = command
                .output()
                .map_err(|error| classify_process_error(&error))?;
            Ok(GcloudProcessOutput {
                success: output.status.success(),
                stdout: Zeroizing::new(output.stdout),
            })
        }
    }
}

fn classify_process_error(error: &std::io::Error) -> GcpError {
    if error.kind() == std::io::ErrorKind::NotFound {
        GcpError::GcloudUnavailable
    } else {
        GcpError::Infrastructure("could not execute gcloud".into())
    }
}

fn parse_access_token(stdout: &[u8]) -> Result<SecretString> {
    if stdout.is_empty() || stdout.len() > 16 * 1024 {
        return Err(GcpError::GcloudUnauthenticated);
    }
    let token = stdout
        .strip_suffix(b"\n")
        .unwrap_or(stdout)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| stdout.strip_suffix(b"\n").unwrap_or(stdout));
    if token.is_empty() || !token.iter().all(u8::is_ascii_graphic) {
        return Err(GcpError::GcloudUnauthenticated);
    }
    let token = std::str::from_utf8(token).map_err(|_| GcpError::GcloudUnauthenticated)?;
    Ok(SecretString::from(token.to_owned()))
}

#[async_trait]
trait SubjectResolver: Send + Sync {
    async fn resolve(&self, access_token: &SecretString) -> Result<String>;
}

#[derive(Debug, Clone)]
struct GoogleSubjectResolver {
    client: reqwest::Client,
}

impl GoogleSubjectResolver {
    fn new() -> Result<Self> {
        let client = reqwest::Client::builder().build().map_err(|_| {
            GcpError::Infrastructure("could not initialize Google identity client".into())
        })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SubjectResolver for GoogleSubjectResolver {
    async fn resolve(&self, access_token: &SecretString) -> Result<String> {
        #[derive(Deserialize)]
        struct UserInfo {
            sub: String,
        }

        let response = self
            .client
            .get(USERINFO_ENDPOINT)
            .bearer_auth(access_token.expose_secret())
            .send()
            .await
            .map_err(|_| GcpError::Infrastructure("Google identity request failed".into()))?;
        if !response.status().is_success() {
            return Err(GcpError::Authentication(
                "Google identity rejected the gcloud access token".into(),
            ));
        }
        let info: UserInfo = response
            .json()
            .await
            .map_err(|_| GcpError::Infrastructure("Google identity response was invalid".into()))?;
        if info.sub.is_empty()
            || info.sub.len() > 255
            || !info.sub.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(GcpError::Contract(
                "Google identity subject is invalid".into(),
            ));
        }
        Ok(info.sub)
    }
}

fn prepare_isolated_config(home: &Path, config_dir: &Path) -> Result<()> {
    if !home.is_absolute() || config_dir != home.join(".dirextalk/gcloud") {
        return Err(GcpError::Contract(
            "isolated gcloud configuration path is invalid".into(),
        ));
    }
    reject_symlink_components(home)?;
    validate_owned_directory(home)?;
    let private_root = home.join(".dirextalk");
    require_directory(&private_root, true, false)?;
    require_directory(config_dir, true, true)?;
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(OsStr::new("/"))),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(GcpError::Contract(
                    "isolated gcloud configuration path is invalid".into(),
                ));
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata = std::fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(GcpError::Contract(
                        "isolated gcloud configuration path is not a real directory".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_directory(path: &Path, create: bool, restrict: bool) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(GcpError::Contract(
                    "isolated gcloud configuration path is not a real directory".into(),
                ));
            }
        }
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(GcpError::Contract(
                    "isolated gcloud configuration path is not a real directory".into(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    validate_owned_directory(path)?;
    if restrict {
        restrict_directory(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owned_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.uid() == rustix::process::geteuid().as_raw() {
        Ok(())
    } else {
        Err(GcpError::Contract(
            "isolated gcloud configuration directory has the wrong owner".into(),
        ))
    }
}

#[cfg(not(unix))]
fn validate_owned_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(GcpError::Contract(
            "isolated gcloud configuration directory has the wrong owner".into(),
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use secrecy::{ExposeSecret as _, SecretString};

    use super::{
        GcloudAuthBroker, GcloudInvocation, GcloudProcess, GcloudProcessOutput, OAuthToken,
        OutputMode, SubjectResolver, require_oauth_principal,
    };
    use crate::{GcpError, Result};

    #[derive(Default)]
    struct FakeProcess {
        outputs: Mutex<VecDeque<Result<GcloudProcessOutput>>>,
        invocations: Mutex<Vec<GcloudInvocation>>,
    }

    impl FakeProcess {
        fn new(outputs: impl IntoIterator<Item = Result<GcloudProcessOutput>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                invocations: Mutex::new(Vec::new()),
            }
        }

        fn invocations(&self) -> Vec<GcloudInvocation> {
            self.invocations.lock().expect("invocations").clone()
        }
    }

    #[async_trait::async_trait]
    impl GcloudProcess for FakeProcess {
        async fn run(&self, invocation: GcloudInvocation) -> Result<GcloudProcessOutput> {
            self.invocations
                .lock()
                .expect("invocations")
                .push(invocation);
            self.outputs
                .lock()
                .expect("outputs")
                .pop_front()
                .expect("queued process output")
        }
    }

    struct FakeSubject(&'static str);

    #[async_trait::async_trait]
    impl SubjectResolver for FakeSubject {
        async fn resolve(&self, _access_token: &SecretString) -> Result<String> {
            Ok(self.0.into())
        }
    }

    fn success(stdout: &[u8]) -> GcloudProcessOutput {
        GcloudProcessOutput {
            success: true,
            stdout: zeroize::Zeroizing::new(stdout.to_vec()),
        }
    }

    fn failure() -> GcloudProcessOutput {
        GcloudProcessOutput {
            success: false,
            stdout: zeroize::Zeroizing::new(Vec::new()),
        }
    }

    fn broker(
        home: &std::path::Path,
        process: Arc<FakeProcess>,
        subject: &'static str,
    ) -> GcloudAuthBroker {
        GcloudAuthBroker::with_components(home, process, Arc::new(FakeSubject(subject)))
    }

    #[tokio::test]
    async fn token_uses_isolated_fixed_commands_and_preserves_subject() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([
            Ok(success(b"ACTIVE\n")),
            Ok(success(b"secret-access-token\n")),
        ]));
        let auth = broker(home.path(), Arc::clone(&process), "opaque-subject-1");

        let token = auth.token().await.expect("token").expect("authenticated");
        assert_eq!(token.access_token.expose_secret(), "secret-access-token");
        assert_eq!(token.principal, "opaque-subject-1");
        assert_eq!(
            process.invocations(),
            [
                GcloudInvocation {
                    args: vec![
                        "auth",
                        "list",
                        "--filter=status:ACTIVE",
                        "--format=value(status)",
                    ],
                    config_dir: home.path().join(".dirextalk/gcloud"),
                    output: OutputMode::Captured,
                },
                GcloudInvocation {
                    args: vec!["auth", "print-access-token"],
                    config_dir: home.path().join(".dirextalk/gcloud"),
                    output: OutputMode::Captured,
                },
            ]
        );
    }

    #[tokio::test]
    async fn empty_active_account_is_expected_unauthenticated_state() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([Ok(success(b"\n"))]));
        let auth = broker(home.path(), Arc::clone(&process), "unused");

        assert!(auth.token().await.expect("status").is_none());
        assert_eq!(process.invocations().len(), 1);
    }

    #[tokio::test]
    async fn process_failures_are_distinct_from_unauthenticated_state() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([Err(GcpError::Infrastructure(
            "simulated process failure".into(),
        ))]));
        let auth = broker(home.path(), process, "unused");
        assert!(matches!(
            auth.token().await,
            Err(GcpError::Infrastructure(_))
        ));

        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([Ok(success(b"ACTIVE\n")), Ok(failure())]));
        let auth = broker(home.path(), process, "unused");
        assert!(matches!(
            auth.token().await,
            Err(GcpError::GcloudUnauthenticated)
        ));
    }

    #[tokio::test]
    async fn unavailable_gcloud_error_is_preserved() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([Err(GcpError::GcloudUnavailable)]));
        let auth = broker(home.path(), process, "unused");
        assert!(matches!(
            auth.token().await,
            Err(GcpError::GcloudUnavailable)
        ));
    }

    #[tokio::test]
    async fn login_is_interactive_then_returns_a_short_lived_token() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([
            Ok(success(b"")),
            Ok(success(b"ACTIVE\n")),
            Ok(success(b"secret-access-token\n")),
        ]));
        let auth = broker(home.path(), Arc::clone(&process), "opaque-subject");

        auth.login().await.expect("login");
        let invocations = process.invocations();
        assert_eq!(invocations[0].args, ["auth", "login", "--brief"]);
        assert_eq!(invocations[0].output, OutputMode::Interactive);
    }

    #[tokio::test]
    async fn logout_revokes_only_the_isolated_configuration() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([
            Ok(success(b"ACTIVE\n")),
            Ok(success(b"")),
        ]));
        let auth = broker(home.path(), Arc::clone(&process), "unused");

        auth.logout().await.expect("logout");
        assert_eq!(
            process.invocations(),
            [
                GcloudInvocation {
                    args: vec![
                        "auth",
                        "list",
                        "--filter=status:ACTIVE",
                        "--format=value(status)",
                    ],
                    config_dir: home.path().join(".dirextalk/gcloud"),
                    output: OutputMode::Captured,
                },
                GcloudInvocation {
                    args: vec!["auth", "revoke", "--all", "--quiet"],
                    config_dir: home.path().join(".dirextalk/gcloud"),
                    output: OutputMode::Interactive,
                },
            ]
        );
    }

    #[tokio::test]
    async fn logout_is_idempotent_without_an_isolated_session() {
        let home = tempfile::tempdir().expect("home");
        let process = Arc::new(FakeProcess::new([Ok(success(b"\n"))]));
        let auth = broker(home.path(), Arc::clone(&process), "unused");

        auth.logout().await.expect("logout");
        assert_eq!(process.invocations().len(), 1);
    }

    #[test]
    fn account_switch_and_debug_output_do_not_disclose_identity_or_token() {
        let error = require_oauth_principal("old-subject", "new-subject").expect_err("switch");
        let error_text = error.to_string();
        assert!(!error_text.contains("old-subject"));
        assert!(!error_text.contains("new-subject"));

        let token = OAuthToken {
            access_token: SecretString::from("secret-access-token"),
            principal: "new-subject".into(),
            expires_at: None,
        };
        let debug = format!("{token:?}");
        assert!(!debug.contains("secret-access-token"));
        assert!(!debug.contains("new-subject"));

        let output = GcloudProcessOutput {
            success: true,
            stdout: zeroize::Zeroizing::new(b"operator@example.test\n".to_vec()),
        };
        assert!(!format!("{output:?}").contains("operator@example.test"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_config_parent_is_rejected_before_process_execution() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().expect("home");
        let target = tempfile::tempdir().expect("target");
        symlink(target.path(), home.path().join(".dirextalk")).expect("symlink");
        let process = Arc::new(FakeProcess::new([Ok(success(b"\n"))]));
        let auth = broker(home.path(), Arc::clone(&process), "unused");

        assert!(matches!(auth.token().await, Err(GcpError::Contract(_))));
        assert!(process.invocations().is_empty());
        assert!(!target.path().join("gcloud").exists());
    }
}
