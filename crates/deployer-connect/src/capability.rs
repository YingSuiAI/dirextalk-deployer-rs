use crate::ConnectError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentCapability {
    Session,
    HostManaged,
    Unsupported,
}

impl AgentCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::HostManaged => "host-managed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectAgent {
    Acp,
    Antigravity,
    ClaudeCode,
    Codex,
    Copilot,
    Cursor,
    Devin,
    Gemini,
    IFlow,
    Kimi,
    OpenCode,
    Pi,
    Qoder,
    Reasonix,
    Tmux,
}

impl ConnectAgent {
    /// Parses one exact backend name from the frozen registry.
    ///
    /// # Errors
    ///
    /// Returns an error for aliases, unknown names, or different casing.
    pub fn parse(value: &str) -> Result<Self, ConnectError> {
        match value {
            "acp" => Ok(Self::Acp),
            "antigravity" => Ok(Self::Antigravity),
            "claudecode" => Ok(Self::ClaudeCode),
            "codex" => Ok(Self::Codex),
            "copilot" => Ok(Self::Copilot),
            "cursor" => Ok(Self::Cursor),
            "devin" => Ok(Self::Devin),
            "gemini" => Ok(Self::Gemini),
            "iflow" => Ok(Self::IFlow),
            "kimi" => Ok(Self::Kimi),
            "opencode" => Ok(Self::OpenCode),
            "pi" => Ok(Self::Pi),
            "qoder" => Ok(Self::Qoder),
            "reasonix" => Ok(Self::Reasonix),
            "tmux" => Ok(Self::Tmux),
            other => Err(ConnectError::UnsupportedAgent(other.to_owned())),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acp => "acp",
            Self::Antigravity => "antigravity",
            Self::ClaudeCode => "claudecode",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
            Self::Devin => "devin",
            Self::Gemini => "gemini",
            Self::IFlow => "iflow",
            Self::Kimi => "kimi",
            Self::OpenCode => "opencode",
            Self::Pi => "pi",
            Self::Qoder => "qoder",
            Self::Reasonix => "reasonix",
            Self::Tmux => "tmux",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRuntime {
    Direct,
    OpenClaw,
    Hermes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentSelection {
    pub connect_agent: ConnectAgent,
    pub host_runtime: HostRuntime,
}

/// Resolves MCP ownership for an effective bridge/host pair.
///
/// # Errors
///
/// Returns an error if an `OpenClaw` or `Hermes` host does not use ACP.
pub fn resolve_capability(selection: AgentSelection) -> Result<AgentCapability, ConnectError> {
    if matches!(
        selection.host_runtime,
        HostRuntime::OpenClaw | HostRuntime::Hermes
    ) {
        if selection.connect_agent != ConnectAgent::Acp {
            return Err(ConnectError::InvalidAgentSelection(format!(
                "{} hosts require the acp conversation bridge",
                match selection.host_runtime {
                    HostRuntime::OpenClaw => "OpenClaw",
                    HostRuntime::Hermes => "Hermes",
                    HostRuntime::Direct => unreachable!(),
                }
            )));
        }
        return Ok(AgentCapability::HostManaged);
    }

    Ok(match selection.connect_agent {
        ConnectAgent::Acp
        | ConnectAgent::ClaudeCode
        | ConnectAgent::Codex
        | ConnectAgent::Copilot
        | ConnectAgent::Gemini
        | ConnectAgent::Kimi
        | ConnectAgent::OpenCode
        | ConnectAgent::Qoder => AgentCapability::Session,
        ConnectAgent::Antigravity | ConnectAgent::Cursor | ConnectAgent::IFlow => {
            AgentCapability::HostManaged
        }
        ConnectAgent::Devin | ConnectAgent::Pi | ConnectAgent::Reasonix | ConnectAgent::Tmux => {
            AgentCapability::Unsupported
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_exact_and_fail_closed() {
        let cases = [
            ("acp", AgentCapability::Session),
            ("antigravity", AgentCapability::HostManaged),
            ("claudecode", AgentCapability::Session),
            ("codex", AgentCapability::Session),
            ("copilot", AgentCapability::Session),
            ("cursor", AgentCapability::HostManaged),
            ("devin", AgentCapability::Unsupported),
            ("gemini", AgentCapability::Session),
            ("iflow", AgentCapability::HostManaged),
            ("kimi", AgentCapability::Session),
            ("opencode", AgentCapability::Session),
            ("pi", AgentCapability::Unsupported),
            ("qoder", AgentCapability::Session),
            ("reasonix", AgentCapability::Unsupported),
            ("tmux", AgentCapability::Unsupported),
        ];
        for (name, expected) in cases {
            let agent = ConnectAgent::parse(name).unwrap();
            assert_eq!(
                resolve_capability(AgentSelection {
                    connect_agent: agent,
                    host_runtime: HostRuntime::Direct,
                })
                .unwrap(),
                expected,
                "{name}"
            );
        }
        assert!(ConnectAgent::parse("generic").is_err());
        assert!(ConnectAgent::parse("Codex").is_err());
    }

    #[test]
    fn openclaw_and_hermes_require_acp_and_are_host_managed() {
        for host_runtime in [HostRuntime::OpenClaw, HostRuntime::Hermes] {
            assert_eq!(
                resolve_capability(AgentSelection {
                    connect_agent: ConnectAgent::Acp,
                    host_runtime,
                })
                .unwrap(),
                AgentCapability::HostManaged
            );
            assert!(
                resolve_capability(AgentSelection {
                    connect_agent: ConnectAgent::Codex,
                    host_runtime,
                })
                .is_err()
            );
        }
    }
}
