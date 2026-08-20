use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use deployer_connect::Redactor;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::json;
use tokio::time::{Duration, timeout};
use uuid::Uuid;

use crate::engine::{EngineError, Result};
use crate::live_product::restrictive_replace;

const MCP_SERVER_NAME: &str = "dirextalk";
const MCP_TOKEN_ENV: &str = "DIREXTALK_MCP_AGENT_TOKEN";
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostMcpCommand {
    program: PathBuf,
    args: Vec<String>,
}

impl HostMcpCommand {
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    pub(crate) fn args(&self) -> impl Iterator<Item = &str> {
        self.args.iter().map(String::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostMcpOutput {
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[async_trait]
pub(crate) trait HostMcpExecutor: Send + Sync {
    async fn execute(&self, command: &HostMcpCommand) -> std::io::Result<HostMcpOutput>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProcessHostMcpExecutor;

#[async_trait]
impl HostMcpExecutor for ProcessHostMcpExecutor {
    async fn execute(&self, command: &HostMcpCommand) -> std::io::Result<HostMcpOutput> {
        let output = tokio::process::Command::new(command.program())
            .args(command.args())
            .kill_on_drop(true)
            .output()
            .await?;
        Ok(HostMcpOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostMcpEvidence {
    pub(crate) profile: String,
    pub(crate) server_name: &'static str,
    pub(crate) tool_count: Option<u64>,
}

pub(crate) struct OpenClawRegistry<E> {
    executor: E,
    binary: PathBuf,
    profile: String,
    env_path: PathBuf,
    redactor: Redactor,
}

impl<E: HostMcpExecutor> OpenClawRegistry<E> {
    pub(crate) fn new(
        executor: E,
        binary: PathBuf,
        home: &Path,
        deployment_uuid: Uuid,
        secrets: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        if !binary.is_absolute() {
            return Err(EngineError::State(
                "OpenClaw executable path is not absolute".into(),
            ));
        }
        if !home.is_absolute() {
            return Err(EngineError::State(
                "current user home is not absolute".into(),
            ));
        }
        let profile = format!("dirextalk-{}", deployment_uuid.simple());
        let env_path = home.join(format!(".openclaw-{profile}")).join(".env");
        Ok(Self {
            executor,
            binary,
            profile,
            env_path,
            redactor: Redactor::new(secrets),
        })
    }

    pub(crate) fn binary(&self) -> &Path {
        &self.binary
    }

    pub(crate) fn profile(&self) -> &str {
        &self.profile
    }

    pub(crate) async fn install(
        &self,
        mcp_url: &str,
        agent_token: &SecretString,
    ) -> Result<HostMcpEvidence> {
        validate_mcp_url(mcp_url)?;
        let token = agent_token.expose_secret();
        if !valid_bearer_token(token) {
            return Err(EngineError::State(
                "stored MCP bearer token has an invalid wire format".into(),
            ));
        }
        restrictive_replace(
            &self.env_path,
            format!("{MCP_TOKEN_ENV}={token}\n").as_bytes(),
        )?;

        let server = serde_json::to_string(&json!({
            "url": mcp_url,
            "transport": "streamable-http",
            "headers": {
                "Authorization": format!("Bearer ${{{MCP_TOKEN_ENV}}}"),
            },
        }))
        .map_err(|_| EngineError::State("OpenClaw MCP entry could not be encoded".into()))?;
        self.run_plain(
            "OpenClaw MCP set",
            ["mcp", "set", MCP_SERVER_NAME, server.as_str()],
        )
        .await?;

        match self.doctor().await {
            Ok(evidence) => Ok(evidence),
            Err(error) => {
                let _ = self
                    .run_plain("OpenClaw MCP rollback", ["mcp", "unset", MCP_SERVER_NAME])
                    .await;
                Err(error)
            }
        }
    }

    pub(crate) async fn status(&self) -> Result<HostMcpEvidence> {
        let output = self
            .run_json(
                "OpenClaw MCP status",
                ["mcp", "doctor", MCP_SERVER_NAME, "--json"],
            )
            .await?;
        validate_doctor(&output)?;
        Ok(HostMcpEvidence {
            profile: self.profile.clone(),
            server_name: MCP_SERVER_NAME,
            tool_count: None,
        })
    }

    pub(crate) async fn doctor(&self) -> Result<HostMcpEvidence> {
        let doctor = self
            .run_json(
                "OpenClaw MCP doctor",
                ["mcp", "doctor", MCP_SERVER_NAME, "--probe", "--json"],
            )
            .await?;
        validate_doctor(&doctor)?;
        let probe = self
            .run_json(
                "OpenClaw MCP probe",
                ["mcp", "probe", MCP_SERVER_NAME, "--json"],
            )
            .await?;
        let tool_count = validate_probe(&probe)?;
        Ok(HostMcpEvidence {
            profile: self.profile.clone(),
            server_name: MCP_SERVER_NAME,
            tool_count: Some(tool_count),
        })
    }

    async fn run_plain<'a>(
        &self,
        operation: &str,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<HostMcpOutput> {
        let mut args_with_profile = vec!["--profile".to_owned(), self.profile.clone()];
        args_with_profile.extend(args.into_iter().map(str::to_owned));
        let command = HostMcpCommand {
            program: self.binary.clone(),
            args: args_with_profile,
        };
        let output = timeout(COMMAND_TIMEOUT, self.executor.execute(&command))
            .await
            .map_err(|_| EngineError::Backend(format!("{operation} timed out")))?
            .map_err(|_| EngineError::Backend(format!("{operation} could not be started")))?;
        if output.stdout.len().saturating_add(output.stderr.len()) > MAX_COMMAND_OUTPUT_BYTES {
            return Err(EngineError::Backend(format!(
                "{operation} returned excessive output"
            )));
        }
        if output.exit_code != Some(0) {
            return Err(EngineError::Backend(format!(
                "{operation} failed: stdout={} stderr={}",
                self.redactor.redact(&output.stdout),
                self.redactor.redact(&output.stderr),
            )));
        }
        Ok(output)
    }

    async fn run_json<'a>(
        &self,
        operation: &str,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<serde_json::Value> {
        let output = self.run_plain(operation, args).await?;
        serde_json::from_str(&output.stdout)
            .map_err(|_| EngineError::Backend(format!("{operation} returned invalid JSON")))
    }
}

#[derive(Deserialize)]
struct DoctorOutput {
    ok: bool,
    servers: Vec<DoctorServer>,
}

#[derive(Deserialize)]
struct DoctorServer {
    name: String,
    ok: bool,
}

fn validate_doctor(value: &serde_json::Value) -> Result<()> {
    let output: DoctorOutput = serde_json::from_value(value.clone())
        .map_err(|_| EngineError::Backend("OpenClaw MCP doctor evidence is invalid".into()))?;
    let matching: Vec<_> = output
        .servers
        .iter()
        .filter(|server| server.name == MCP_SERVER_NAME)
        .collect();
    if !output.ok || !matches!(matching.as_slice(), [server] if server.ok) {
        return Err(EngineError::Backend(
            "OpenClaw MCP doctor did not attest the exact Dirextalk entry".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct ProbeOutput {
    servers: BTreeMap<String, ProbeServer>,
    #[serde(default)]
    diagnostics: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct ProbeServer {
    tools: u64,
}

fn validate_probe(value: &serde_json::Value) -> Result<u64> {
    let output: ProbeOutput = serde_json::from_value(value.clone())
        .map_err(|_| EngineError::Backend("OpenClaw MCP probe evidence is invalid".into()))?;
    let server = output.servers.get(MCP_SERVER_NAME).ok_or_else(|| {
        EngineError::Backend("OpenClaw MCP probe omitted the Dirextalk entry".into())
    })?;
    if !output.diagnostics.is_empty() || server.tools == 0 {
        return Err(EngineError::Backend(
            "OpenClaw MCP probe did not prove a usable Dirextalk tool registry".into(),
        ));
    }
    Ok(server.tools)
}

fn validate_mcp_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value)
        .map_err(|_| EngineError::State("stored MCP URL is invalid".into()))?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/mcp"
    {
        return Err(EngineError::State(
            "stored MCP URL is not the canonical HTTPS endpoint".into(),
        ));
    }
    Ok(())
}

fn valid_bearer_token(value: &str) -> bool {
    let body_len = value.trim_end_matches('=').len();
    body_len > 0
        && value[..body_len].bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && value[body_len..].bytes().all(|byte| byte == b'=')
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct FakeExecutor {
        outputs: Arc<Mutex<VecDeque<HostMcpOutput>>>,
        commands: Arc<Mutex<Vec<HostMcpCommand>>>,
    }

    impl FakeExecutor {
        fn with_outputs(outputs: impl IntoIterator<Item = HostMcpOutput>) -> Self {
            Self {
                outputs: Arc::new(Mutex::new(outputs.into_iter().collect())),
                commands: Arc::default(),
            }
        }
    }

    #[async_trait]
    impl HostMcpExecutor for FakeExecutor {
        async fn execute(&self, command: &HostMcpCommand) -> std::io::Result<HostMcpOutput> {
            self.commands.lock().unwrap().push(command.clone());
            self.outputs.lock().unwrap().pop_front().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no fake output")
            })
        }
    }

    fn success(stdout: &str) -> HostMcpOutput {
        HostMcpOutput {
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn registry(
        executor: FakeExecutor,
        home: &Path,
        token: &str,
    ) -> OpenClawRegistry<FakeExecutor> {
        OpenClawRegistry::new(
            executor,
            home.join("bin/openclaw"),
            home,
            Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap(),
            [token.to_owned()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn install_uses_service_profile_placeholder_and_json_evidence() {
        let executor = FakeExecutor::with_outputs([
            success("saved\n"),
            success(r#"{"ok":true,"servers":[{"name":"dirextalk","ok":true,"future":1}]}"#),
            success(r#"{"servers":{"dirextalk":{"tools":3}},"diagnostics":[],"future":1}"#),
        ]);
        let temp = tempfile::tempdir().unwrap();
        let token = "header.payload.signature";
        let registry = registry(executor.clone(), temp.path(), token);

        let evidence = registry
            .install(
                "https://talk.example.com/mcp",
                &SecretString::from(token.to_owned()),
            )
            .await
            .unwrap();

        assert_eq!(evidence.server_name, "dirextalk");
        assert_eq!(evidence.tool_count, Some(3));
        let commands = executor.commands.lock().unwrap();
        assert_eq!(commands.len(), 3);
        assert_eq!(
            commands[0].args,
            [
                "--profile",
                "dirextalk-12345678123456789abcdef012345678",
                "mcp",
                "set",
                "dirextalk",
                r#"{"headers":{"Authorization":"Bearer ${DIREXTALK_MCP_AGENT_TOKEN}"},"transport":"streamable-http","url":"https://talk.example.com/mcp"}"#,
            ]
        );
        assert!(
            commands
                .iter()
                .all(|command| !command.args.join(" ").contains(token))
        );
        assert_eq!(
            std::fs::read_to_string(&registry.env_path).unwrap(),
            format!("{MCP_TOKEN_ENV}={token}\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&registry.env_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(registry.env_path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[tokio::test]
    async fn failed_live_proof_removes_only_the_owned_entry_and_redacts() {
        let token = "secret-token";
        let executor = FakeExecutor::with_outputs([
            success("saved\n"),
            HostMcpOutput {
                exit_code: Some(1),
                stdout: format!("Authorization: Bearer {token}"),
                stderr: token.into(),
            },
            success("removed\n"),
        ]);
        let temp = tempfile::tempdir().unwrap();
        let registry = registry(executor.clone(), temp.path(), token);

        let error = registry
            .install(
                "https://talk.example.com/mcp",
                &SecretString::from(token.to_owned()),
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(!error.contains(token));
        assert!(error.contains("[REDACTED]"));
        let commands = executor.commands.lock().unwrap();
        assert_eq!(commands[2].args[2..], ["mcp", "unset", "dirextalk"]);
    }

    #[test]
    fn bearer_and_endpoint_validation_fail_closed() {
        for token in [
            "",
            "Bearer token",
            "token with space",
            "token#comment",
            "=token",
        ] {
            assert!(!valid_bearer_token(token), "{token}");
        }
        for token in ["abc", "a.b-c_d~e+f/g=="] {
            assert!(valid_bearer_token(token), "{token}");
        }
        for url in [
            "http://talk.example.com/mcp",
            "https://user@talk.example.com/mcp",
            "https://talk.example.com/mcp?token=x",
            "https://talk.example.com/other",
        ] {
            assert!(validate_mcp_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn evidence_requires_the_exact_healthy_entry() {
        assert!(
            validate_doctor(&json!({
                "ok": true,
                "servers": [{"name": "other", "ok": true}],
            }))
            .is_err()
        );
        assert!(
            validate_probe(&json!({
                "servers": {"dirextalk": {"tools": 0}},
                "diagnostics": [],
            }))
            .is_err()
        );
        assert!(
            validate_probe(&json!({
                "servers": {"dirextalk": {"tools": 1}},
                "diagnostics": [{"message": "failed"}],
            }))
            .is_err()
        );
    }
}
