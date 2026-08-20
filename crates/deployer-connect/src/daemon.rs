use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::paths::validate_service_id;
use crate::{ConnectError, Redactor};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedCommand {
    program: PathBuf,
    args: Vec<OsString>,
}

impl FixedCommand {
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> impl Iterator<Item = &OsStr> {
        self.args.iter().map(OsString::as_os_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn execute(&self, command: &FixedCommand) -> std::io::Result<CommandOutput>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessExecutor;

#[async_trait]
impl CommandExecutor for ProcessExecutor {
    async fn execute(&self, command: &FixedCommand) -> std::io::Result<CommandOutput> {
        let output = tokio::process::Command::new(command.program())
            .args(command.args())
            .kill_on_drop(true)
            .output()
            .await?;
        Ok(CommandOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonState {
    Running,
    Stopped,
    NotInstalled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonEvidence {
    pub state: DaemonState,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub struct DaemonController<E> {
    executor: E,
    binary: PathBuf,
    config: PathBuf,
    service_id: String,
    redactor: Redactor,
}

impl<E: CommandExecutor> DaemonController<E> {
    /// Creates a controller for one validated service.
    ///
    /// # Errors
    ///
    /// Returns an error when the service identifier is unsafe.
    pub fn new(
        executor: E,
        binary: impl Into<PathBuf>,
        config: impl Into<PathBuf>,
        service_id: impl Into<String>,
        redactor: Redactor,
    ) -> Result<Self, ConnectError> {
        let service_id = service_id.into();
        validate_service_id(&service_id)?;
        Ok(Self {
            executor,
            binary: binary.into(),
            config: config.into(),
            service_id,
            redactor,
        })
    }

    /// Runs fixed install argv and then requires running status and clean logs.
    ///
    /// # Errors
    ///
    /// Returns redacted evidence when execution or verification fails.
    pub async fn install(&self) -> Result<DaemonEvidence, ConnectError> {
        let install = self
            .run(vec![
                "daemon".into(),
                "install".into(),
                "--config".into(),
                self.config.as_os_str().into(),
                "--service-name".into(),
                self.service_id.clone().into(),
                "--force".into(),
            ])
            .await?;
        if install.exit_code != Some(0) {
            return Err(self.failure("daemon install", &install));
        }
        self.doctor().await
    }

    /// Runs fixed status argv and classifies its output.
    ///
    /// # Errors
    ///
    /// Returns redacted evidence when execution fails.
    pub async fn status(&self) -> Result<DaemonEvidence, ConnectError> {
        let output = self
            .run(vec![
                "daemon".into(),
                "status".into(),
                "--service-name".into(),
                self.service_id.clone().into(),
            ])
            .await?;
        if output.exit_code != Some(0) {
            return Err(self.failure("daemon status", &output));
        }
        let state = if output.stdout.contains("Status:    Running")
            || output.stdout.contains("Status: Running")
        {
            DaemonState::Running
        } else if output.stdout.contains("Not installed") {
            DaemonState::NotInstalled
        } else {
            DaemonState::Stopped
        };
        Ok(self.evidence(state, &output))
    }

    /// Requires running status and clean recent startup logs.
    ///
    /// # Errors
    ///
    /// Returns redacted evidence for startup, authentication, or agent failures.
    pub async fn doctor(&self) -> Result<DaemonEvidence, ConnectError> {
        let status = self.status().await?;
        if status.state != DaemonState::Running {
            return Err(ConnectError::Daemon(format!(
                "daemon is not running: {}",
                status.stdout
            )));
        }
        let logs = self
            .run(vec![
                "daemon".into(),
                "logs".into(),
                "--service-name".into(),
                self.service_id.clone().into(),
                "-n".into(),
                "120".into(),
            ])
            .await?;
        if logs.exit_code != Some(0) {
            return Err(self.failure("daemon logs", &logs));
        }
        let combined = format!("{}\n{}", logs.stdout, logs.stderr).to_ascii_lowercase();
        let failures = [
            "command not found",
            "executable not found",
            "agent cli missing",
            "failed to start agent",
            "not logged in",
            "not authenticated",
            "unauthorized",
            "authentication failed",
            "login required",
            "trust this workspace",
            "workspace trust",
            "acp startup",
            "acp initialization",
            "agent offline",
        ];
        if let Some(marker) = failures.iter().find(|marker| combined.contains(**marker)) {
            return Err(ConnectError::Daemon(format!(
                "daemon startup evidence contains {marker:?}: stdout={} stderr={}",
                self.redactor.redact(&logs.stdout),
                self.redactor.redact(&logs.stderr)
            )));
        }
        if !combined.contains("dirextalk-connect is running") {
            return Err(ConnectError::Daemon(format!(
                "daemon logs lack the running marker: stdout={} stderr={}",
                self.redactor.redact(&logs.stdout),
                self.redactor.redact(&logs.stderr)
            )));
        }
        Ok(self.evidence(DaemonState::Running, &logs))
    }

    async fn run(&self, args: Vec<OsString>) -> Result<CommandOutput, ConnectError> {
        self.executor
            .execute(&FixedCommand {
                program: self.binary.clone(),
                args,
            })
            .await
            .map_err(ConnectError::Filesystem)
    }

    fn evidence(&self, state: DaemonState, output: &CommandOutput) -> DaemonEvidence {
        DaemonEvidence {
            state,
            exit_code: output.exit_code,
            stdout: self.redactor.redact(&output.stdout),
            stderr: self.redactor.redact(&output.stderr),
        }
    }

    fn failure(&self, operation: &str, output: &CommandOutput) -> ConnectError {
        ConnectError::Daemon(format!(
            "{operation} exited {:?}: stdout={} stderr={}",
            output.exit_code,
            self.redactor.redact(&output.stdout),
            self.redactor.redact(&output.stderr)
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct FakeExecutor {
        outputs: Mutex<VecDeque<CommandOutput>>,
        commands: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait]
    impl CommandExecutor for FakeExecutor {
        async fn execute(&self, command: &FixedCommand) -> std::io::Result<CommandOutput> {
            self.commands.lock().unwrap().push(
                command
                    .args()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            );
            Ok(self.outputs.lock().unwrap().pop_front().unwrap())
        }
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> CommandOutput {
        CommandOutput {
            exit_code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[tokio::test]
    async fn doctor_uses_fixed_argv_and_rejects_failure_evidence() {
        let executor = FakeExecutor {
            outputs: Mutex::new(VecDeque::from([
                output(0, "Status:    Running", ""),
                output(0, "authentication failed for very-secret", ""),
            ])),
            commands: Mutex::new(Vec::new()),
        };
        let controller = DaemonController::new(
            executor,
            "/service/dirextalk-connect",
            "/service/config.toml",
            "node.example.com",
            Redactor::new(["very-secret".into()]),
        )
        .unwrap();
        let error = controller.doctor().await.unwrap_err().to_string();
        assert!(error.contains("authentication failed"));
        assert!(!error.contains("very-secret"));
        let commands = controller.executor.commands.lock().unwrap();
        assert_eq!(
            commands.as_slice(),
            [
                vec!["daemon", "status", "--service-name", "node.example.com"],
                vec![
                    "daemon",
                    "logs",
                    "--service-name",
                    "node.example.com",
                    "-n",
                    "120"
                ],
            ]
        );
    }

    #[tokio::test]
    async fn install_requires_running_status_and_startup_log() {
        let executor = FakeExecutor {
            outputs: Mutex::new(VecDeque::from([
                output(0, "installed", ""),
                output(0, "Status:    Running", ""),
                output(0, "dirextalk-connect is running", ""),
            ])),
            commands: Mutex::new(Vec::new()),
        };
        let controller = DaemonController::new(
            executor,
            "/service/dirextalk-connect",
            "/service/config.toml",
            "node.example.com",
            Redactor::default(),
        )
        .unwrap();
        assert_eq!(
            controller.install().await.unwrap().state,
            DaemonState::Running
        );
        let commands = controller.executor.commands.lock().unwrap();
        assert_eq!(
            commands[0],
            vec![
                "daemon",
                "install",
                "--config",
                "/service/config.toml",
                "--service-name",
                "node.example.com",
                "--force",
            ]
        );
        assert_eq!(
            commands[1..],
            [
                vec!["daemon", "status", "--service-name", "node.example.com"],
                vec![
                    "daemon",
                    "logs",
                    "--service-name",
                    "node.example.com",
                    "-n",
                    "120"
                ]
            ]
        );
    }

    #[tokio::test]
    async fn install_fails_when_handoff_logs_show_agent_failure() {
        let executor = FakeExecutor {
            outputs: Mutex::new(VecDeque::from([
                output(0, "installed", ""),
                output(0, "Status:    Running", ""),
                output(0, "agent CLI missing: daemon-secret", ""),
            ])),
            commands: Mutex::new(Vec::new()),
        };
        let controller = DaemonController::new(
            executor,
            "/service/dirextalk-connect",
            "/service/config.toml",
            "node.example.com",
            Redactor::new(["daemon-secret".into()]),
        )
        .unwrap();
        let error = controller.install().await.unwrap_err().to_string();
        assert!(error.contains("agent cli missing"));
        assert!(!error.contains("daemon-secret"));
    }
}
