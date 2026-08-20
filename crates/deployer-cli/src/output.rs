#![allow(clippy::missing_errors_doc)]

use std::io::{self, Write};

use deployer_core::ProgressEvent;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::cli::OutputFormat;

pub const OUTPUT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Success,
    WaitingUser,
    Failed,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandEnvelope {
    pub schema_version: u32,
    pub command: String,
    pub status: OutcomeStatus,
    pub code: String,
    pub message: String,
    pub data: Value,
    #[serde(skip)]
    pub human_initialization_code: Option<SecretString>,
    #[serde(skip)]
    pub progress: Vec<ProgressEvent>,
}

impl PartialEq for CommandEnvelope {
    fn eq(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.command == other.command
            && self.status == other.status
            && self.code == other.code
            && self.message == other.message
            && self.data == other.data
            && self.progress == other.progress
            && match (
                &self.human_initialization_code,
                &other.human_initialization_code,
            ) {
                (Some(left), Some(right)) => left.expose_secret() == right.expose_secret(),
                (None, None) => true,
                _ => false,
            }
    }
}

impl CommandEnvelope {
    pub fn success(
        command: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(command, OutcomeStatus::Success, code, message)
    }

    pub fn waiting(
        command: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(command, OutcomeStatus::WaitingUser, code, message)
    }

    pub fn failed(
        command: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(command, OutcomeStatus::Failed, code, message)
    }

    pub fn with_data(mut self, data: impl Serialize) -> Result<Self, serde_json::Error> {
        self.data = serde_json::to_value(data)?;
        Ok(self)
    }

    #[must_use]
    pub fn with_human_initialization_code(mut self, code: SecretString) -> Self {
        self.human_initialization_code = Some(code);
        self
    }

    #[must_use]
    pub fn with_progress(mut self, progress: Vec<ProgressEvent>) -> Self {
        self.progress = progress;
        self
    }

    fn new(
        command: impl Into<String>,
        status: OutcomeStatus,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: OUTPUT_SCHEMA_VERSION,
            command: command.into(),
            status,
            code: code.into(),
            message: message.into(),
            data: Value::Object(Map::new()),
            human_initialization_code: None,
            progress: Vec::new(),
        }
    }

    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.status {
            OutcomeStatus::Success => 0,
            OutcomeStatus::WaitingUser => 2,
            OutcomeStatus::Failed => 1,
        }
    }
}

pub fn render(
    envelope: &CommandEnvelope,
    format: OutputFormat,
    mut writer: impl Write,
) -> io::Result<()> {
    match format {
        OutputFormat::Human => render_human(envelope, &mut writer),
        OutputFormat::Json => {
            serde_json::to_writer(&mut writer, envelope)?;
            writeln!(writer)
        }
        OutputFormat::Jsonl => {
            for event in &envelope.progress {
                serde_json::to_writer(&mut writer, event)?;
                writeln!(writer)?;
            }
            serde_json::to_writer(&mut writer, envelope)?;
            writeln!(writer)
        }
    }
}

fn render_human(envelope: &CommandEnvelope, writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "{}", envelope.message)?;
    if let Value::Object(fields) = &envelope.data {
        for (key, value) in fields {
            match value {
                Value::Null => {}
                Value::String(value) => writeln!(writer, "{key}: {value}")?,
                value => writeln!(writer, "{key}: {value}")?,
            }
        }
    }
    if let Some(code) = &envelope.human_initialization_code {
        writeln!(writer, "initialization_code: {}", code.expose_secret())?;
    }
    Ok(())
}

pub fn stdout(envelope: &CommandEnvelope, format: OutputFormat) -> io::Result<()> {
    render(envelope, format, io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CommandEnvelope, OutcomeStatus, render};
    use crate::cli::OutputFormat;

    #[test]
    fn machine_output_is_one_stable_secret_free_envelope() {
        let envelope = CommandEnvelope::waiting(
            "deploy.apply",
            "DNS_RECORD_REQUIRED",
            "Create the required external DNS record.",
        )
        .with_data(json!({"record_type":"A","name":"chat.example.com","value":"203.0.113.2"}))
        .expect("serializable")
        .with_progress(vec![deployer_core::ProgressEvent {
            timestamp_unix_ms: 1,
            operation: deployer_core::ProgressOperation::Apply,
            status: deployer_core::ProgressStatus::Started,
            resource_kind: None,
        }]);
        let mut output = Vec::new();
        render(&envelope, OutputFormat::Jsonl, &mut output).expect("render");
        let lines: Vec<_> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        let _: deployer_core::ProgressEvent = serde_json::from_slice(lines[0]).expect("progress");
        let decoded: CommandEnvelope = serde_json::from_slice(lines[1]).expect("valid JSON");
        assert_eq!(decoded.status, OutcomeStatus::WaitingUser);
        assert_eq!(decoded.exit_code(), 2);
    }
}
