use serde::Serialize;

use crate::AgentCapability;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectStatus {
    pub service_id: String,
    pub capability: String,
    pub config_path: String,
    pub daemon: String,
    pub mcp: String,
}

impl ConnectStatus {
    pub fn new(
        service_id: impl Into<String>,
        capability: AgentCapability,
        config_path: impl Into<String>,
        daemon: impl Into<String>,
        mcp: impl Into<String>,
    ) -> Self {
        Self {
            service_id: service_id.into(),
            capability: capability.as_str().to_owned(),
            config_path: config_path.into(),
            daemon: daemon.into(),
            mcp: mcp.into(),
        }
    }
}

#[derive(Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        Self {
            secrets: secrets
                .into_iter()
                .filter(|secret| !secret.is_empty())
                .collect(),
        }
    }

    #[must_use]
    pub fn redact(&self, value: &str) -> String {
        const LIMIT: usize = 8 * 1024;
        let mut redacted = redact_bearer_values(value);
        for secret in &self.secrets {
            redacted = redacted.replace(secret, "[REDACTED]");
        }
        if redacted.len() > LIMIT {
            redacted.truncate(redacted.floor_char_boundary(LIMIT));
            redacted.push_str("…[truncated]");
        }
        redacted
    }
}

fn redact_bearer_values(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find("Bearer ") {
        let (before, token_and_after) = rest.split_at(index);
        result.push_str(before);
        result.push_str("Bearer [REDACTED]");
        let after_prefix = &token_and_after["Bearer ".len()..];
        let boundary = after_prefix
            .find(char::is_whitespace)
            .unwrap_or(after_prefix.len());
        rest = &after_prefix[boundary..];
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_evidence_omit_secrets() {
        let status = ConnectStatus::new(
            "node.example.com",
            AgentCapability::Session,
            "/safe/config.toml",
            "running",
            "verified",
        );
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("password"));

        let redactor = Redactor::new(["known-secret".to_owned()]);
        let evidence = redactor.redact("known-secret Authorization: Bearer other-secret\nok");
        assert_eq!(evidence, "[REDACTED] Authorization: Bearer [REDACTED]\nok");
    }
}
