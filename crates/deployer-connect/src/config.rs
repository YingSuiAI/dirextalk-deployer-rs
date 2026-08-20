use serde::Serialize;
use url::Url;

use crate::{AgentCapability, AgentSelection, ConnectError, HostRuntime, resolve_capability};

#[derive(Clone)]
pub struct MatrixSession {
    pub homeserver: String,
    pub access_token: String,
    pub user_id: String,
    pub device_id: String,
    pub room_id: String,
    pub admin_from: String,
}

#[derive(Clone)]
pub struct McpInjection {
    pub url: String,
    pub server_name: String,
    pub agent_token: String,
    pub node_id: String,
}

#[derive(Clone)]
pub struct ProjectConfig {
    pub name: String,
    pub selection: AgentSelection,
    pub work_dir: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub matrix: MatrixSession,
    pub mcp: Option<McpInjection>,
}

#[derive(Clone)]
pub struct ConnectConfig {
    pub data_dir: String,
    pub project: ProjectConfig,
}

#[derive(Serialize)]
struct RenderedConfig<'a> {
    language: &'static str,
    data_dir: &'a str,
    projects: Vec<RenderedProject<'a>>,
}

#[derive(Serialize)]
struct RenderedProject<'a> {
    name: &'a str,
    admin_from: &'a str,
    agent: RenderedAgent<'a>,
    platforms: Vec<RenderedPlatform<'a>>,
}

#[derive(Serialize)]
struct RenderedAgent<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    options: RenderedAgentOptions<'a>,
}

#[derive(Serialize)]
struct RenderedAgentOptions<'a> {
    work_dir: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cmd: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: &'a Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_server_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_agent_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_node_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_capability: Option<&'a str>,
}

#[derive(Serialize)]
struct RenderedPlatform<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    options: RenderedMatrixOptions<'a>,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct RenderedMatrixOptions<'a> {
    homeserver: &'a str,
    access_token: &'a str,
    user_id: &'a str,
    device_id: &'a str,
    room_id: &'a str,
    share_session_in_channel: bool,
    group_reply_all: bool,
    auto_join: bool,
    auto_verify: bool,
}

/// Validates and renders the one-project, one-Matrix-platform config.
///
/// # Errors
///
/// Returns an error for invalid identities/endpoints, pseudo room IDs,
/// unsupported agents, or missing canonical session MCP credentials.
pub fn render_matrix_config(config: &ConnectConfig) -> Result<String, ConnectError> {
    validate(config)?;
    let capability = resolve_capability(config.project.selection)?;
    if capability == AgentCapability::Unsupported {
        return Err(ConnectError::InvalidConfig(format!(
            "agent {} has no remote MCP support",
            config.project.selection.connect_agent.as_str()
        )));
    }

    let mcp = match capability {
        AgentCapability::Session => config.project.mcp.as_ref(),
        AgentCapability::HostManaged => None,
        AgentCapability::Unsupported => unreachable!(),
    };
    if capability == AgentCapability::Session && mcp.is_none() {
        return Err(ConnectError::InvalidConfig(
            "session-capable agents require complete canonical MCP configuration".to_owned(),
        ));
    }
    let options = RenderedAgentOptions {
        work_dir: &config.project.work_dir,
        cmd: config.project.command.as_deref(),
        args: &config.project.args,
        mcp_url: mcp.map(|value| value.url.as_str()),
        mcp_server_name: mcp.map(|value| value.server_name.as_str()),
        mcp_agent_token: mcp.map(|value| value.agent_token.as_str()),
        mcp_node_id: mcp.map(|value| value.node_id.as_str()),
        mcp_capability: mcp.map(|_| capability.as_str()),
    };
    let rendered = RenderedConfig {
        language: "auto",
        data_dir: &config.data_dir,
        projects: vec![RenderedProject {
            name: &config.project.name,
            admin_from: &config.project.matrix.admin_from,
            agent: RenderedAgent {
                kind: config.project.selection.connect_agent.as_str(),
                options,
            },
            platforms: vec![RenderedPlatform {
                kind: "matrix",
                options: RenderedMatrixOptions {
                    homeserver: &config.project.matrix.homeserver,
                    access_token: &config.project.matrix.access_token,
                    user_id: &config.project.matrix.user_id,
                    device_id: &config.project.matrix.device_id,
                    room_id: &config.project.matrix.room_id,
                    share_session_in_channel: true,
                    group_reply_all: true,
                    auto_join: false,
                    auto_verify: false,
                },
            }],
        }],
    };
    Ok(toml::to_string_pretty(&rendered)?)
}

fn validate(config: &ConnectConfig) -> Result<(), ConnectError> {
    let project = &config.project;
    for (name, value) in [
        ("data_dir", config.data_dir.as_str()),
        ("project name", project.name.as_str()),
        ("work_dir", project.work_dir.as_str()),
        ("Matrix access_token", project.matrix.access_token.as_str()),
        ("Matrix device_id", project.matrix.device_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ConnectError::InvalidConfig(format!("{name} is required")));
        }
    }
    if !is_absolute_portable(&config.data_dir) || !is_absolute_portable(&project.work_dir) {
        return Err(ConnectError::InvalidConfig(
            "data_dir and work_dir must be absolute local paths".to_owned(),
        ));
    }
    if project
        .command
        .as_deref()
        .is_some_and(|command| command.trim().is_empty())
    {
        return Err(ConnectError::InvalidConfig(
            "agent command must not be empty when provided".to_owned(),
        ));
    }

    let homeserver = canonical_https(&project.matrix.homeserver, "Matrix homeserver", false)?;
    let host = homeserver
        .host_str()
        .ok_or_else(|| ConnectError::InvalidConfig("Matrix homeserver has no host".to_owned()))?;
    require_matrix_id(&project.matrix.user_id, "@agent:", host, "Matrix user_id")?;
    require_matrix_id(&project.matrix.admin_from, "@owner:", host, "admin_from")?;
    require_real_room_id(&project.matrix.room_id, host)?;

    if let Some(mcp) = &project.mcp {
        let mcp_url = canonical_https(&mcp.url, "MCP URL", true)?;
        if mcp_url.scheme() != homeserver.scheme()
            || mcp_url.host_str() != homeserver.host_str()
            || mcp_url.port_or_known_default() != homeserver.port_or_known_default()
        {
            return Err(ConnectError::InvalidConfig(
                "MCP URL must use the deployed Matrix homeserver origin".to_owned(),
            ));
        }
        for (name, value) in [
            ("MCP server name", mcp.server_name.as_str()),
            ("MCP agent token", mcp.agent_token.as_str()),
            ("MCP node id", mcp.node_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ConnectError::InvalidConfig(format!("{name} is required")));
            }
        }
        if !canonical_mcp_server_name(&mcp.server_name) {
            return Err(ConnectError::InvalidConfig(
                "MCP server name must already be canonical lowercase ASCII".to_owned(),
            ));
        }
        if mcp.agent_token.trim() != mcp.agent_token
            || mcp.agent_token.chars().any(char::is_whitespace)
            || mcp.agent_token.to_ascii_lowercase().starts_with("bearer ")
        {
            return Err(ConnectError::InvalidConfig(
                "MCP agent token must be one raw non-whitespace token".to_owned(),
            ));
        }
        if mcp.node_id != project.name {
            return Err(ConnectError::InvalidConfig(
                "MCP node id must equal the generated project name".to_owned(),
            ));
        }
    }
    validate_host_bridge(project, &config.data_dir)?;
    Ok(())
}

fn validate_host_bridge(project: &ProjectConfig, data_dir: &str) -> Result<(), ConnectError> {
    match project.selection.host_runtime {
        HostRuntime::Direct => {
            if project.selection.connect_agent == crate::ConnectAgent::Acp
                && project.command.is_none()
            {
                return Err(ConnectError::InvalidConfig(
                    "generic ACP requires an explicit agent command".to_owned(),
                ));
            }
            Ok(())
        }
        HostRuntime::OpenClaw => {
            let command = project.command.as_deref().ok_or_else(|| {
                ConnectError::InvalidConfig(
                    "OpenClaw requires its resolved absolute host CLI path".to_owned(),
                )
            })?;
            if !is_absolute_portable(command) {
                return Err(ConnectError::InvalidConfig(
                    "OpenClaw command must be absolute".to_owned(),
                ));
            }
            validate_openclaw_args(&project.args)
        }
        HostRuntime::Hermes => {
            let command = project.command.as_deref().ok_or_else(|| {
                ConnectError::InvalidConfig(
                    "Hermes requires the absolute service-scoped dirextalk-connect binary"
                        .to_owned(),
                )
            })?;
            if !is_absolute_portable(command) || !is_service_connect_binary(command, data_dir) {
                return Err(ConnectError::InvalidConfig(
                    "Hermes cmd must be the absolute service-scoped dirextalk-connect binary"
                        .to_owned(),
                ));
            }
            validate_hermes_args(&project.args)
        }
    }
}

fn validate_openclaw_args(args: &[String]) -> Result<(), ConnectError> {
    let acp_index = match args {
        [acp, ..] if acp == "acp" => 0,
        [profile_flag, profile, acp, ..]
            if profile_flag == "--profile" && !profile.is_empty() && acp == "acp" =>
        {
            2
        }
        _ => {
            return Err(ConnectError::InvalidConfig(
                "OpenClaw args must retain [--profile <profile>] acp".to_owned(),
            ));
        }
    };
    let options = &args[acp_index + 1..];
    let mut url = None;
    let mut token_file = None;
    let mut session = None;
    for pair in options.chunks_exact(2) {
        let target = match pair[0].as_str() {
            "--url" => &mut url,
            "--token-file" => &mut token_file,
            "--session" => &mut session,
            other => {
                return Err(ConnectError::InvalidConfig(format!(
                    "OpenClaw ACP option {other} is not allowed"
                )));
            }
        };
        if target.replace(pair[1].as_str()).is_some() || pair[1].is_empty() {
            return Err(ConnectError::InvalidConfig(
                "OpenClaw ACP options must be unique and non-empty".to_owned(),
            ));
        }
    }
    if !options.len().is_multiple_of(2) || session.is_none() {
        return Err(ConnectError::InvalidConfig(
            "OpenClaw ACP requires --session and flag/value pairs".to_owned(),
        ));
    }
    if url.is_some() != token_file.is_some() {
        return Err(ConnectError::InvalidConfig(
            "OpenClaw explicit Gateway requires both --url and --token-file".to_owned(),
        ));
    }
    if token_file.is_some_and(|path| !is_absolute_portable(path)) {
        return Err(ConnectError::InvalidConfig(
            "OpenClaw --token-file must be absolute".to_owned(),
        ));
    }
    Ok(())
}

fn validate_hermes_args(args: &[String]) -> Result<(), ConnectError> {
    if args.len() < 6
        || args[0] != "hermes-acp-adapter"
        || args[1] != "--"
        || !is_absolute_portable(&args[2])
        || args[3] != "-p"
        || args[4].is_empty()
        || args[5] != "acp"
    {
        return Err(ConnectError::InvalidConfig(
            "Hermes args must retain hermes-acp-adapter -- <absolute-hermes> -p <profile> acp"
                .to_owned(),
        ));
    }
    Ok(())
}

fn is_service_connect_binary(command: &str, data_dir: &str) -> bool {
    let Some(connect_dir) = data_dir
        .trim_end_matches(['/', '\\'])
        .strip_suffix("/data")
        .or_else(|| {
            data_dir
                .trim_end_matches(['/', '\\'])
                .strip_suffix("\\data")
        })
    else {
        return false;
    };
    let mut normalized_command = command.replace('\\', "/");
    let mut normalized_dir = connect_dir.replace('\\', "/");
    if normalized_command.as_bytes().get(1) == Some(&b':')
        && normalized_dir.as_bytes().get(1) == Some(&b':')
    {
        normalized_command.make_ascii_lowercase();
        normalized_dir.make_ascii_lowercase();
    }
    normalized_command == format!("{normalized_dir}/dirextalk-connect")
        || normalized_command == format!("{normalized_dir}/dirextalk-connect.exe")
}

fn is_absolute_portable(path: &str) -> bool {
    path.starts_with('/')
        || path.as_bytes().get(1..3).is_some_and(|pair| {
            path.as_bytes()[0].is_ascii_alphabetic()
                && pair[0] == b':'
                && matches!(pair[1], b'/' | b'\\')
        })
}

fn canonical_mcp_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn canonical_https(value: &str, name: &str, mcp: bool) -> Result<Url, ConnectError> {
    let url = Url::parse(value)
        .map_err(|error| ConnectError::InvalidConfig(format!("{name}: {error}")))?;
    let expected_path = if mcp { "/mcp" } else { "/" };
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != expected_path
    {
        return Err(ConnectError::InvalidConfig(format!(
            "{name} must be canonical HTTPS at {expected_path}"
        )));
    }
    Ok(url)
}

fn require_matrix_id(
    value: &str,
    prefix: &str,
    host: &str,
    name: &str,
) -> Result<(), ConnectError> {
    if value == format!("{prefix}{host}") {
        Ok(())
    } else {
        Err(ConnectError::InvalidConfig(format!(
            "{name} must be {prefix}{host}"
        )))
    }
}

fn require_real_room_id(value: &str, host: &str) -> Result<(), ConnectError> {
    let suffix = format!(":{host}");
    let local = value
        .strip_prefix('!')
        .and_then(|room| room.strip_suffix(&suffix))
        .ok_or_else(|| {
            ConnectError::InvalidConfig(
                "room_id must be a Matrix room id on the service".to_owned(),
            )
        })?;
    if local.is_empty() || local == "agent" {
        return Err(ConnectError::InvalidConfig(
            "room_id must be the real persisted agent_room_id".to_owned(),
        ));
    }
    if local.chars().any(char::is_whitespace) {
        return Err(ConnectError::InvalidConfig(
            "room_id must not contain whitespace".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectAgent, HostRuntime};

    fn config(agent: ConnectAgent) -> ConnectConfig {
        ConnectConfig {
            data_dir: "/home/a/.dirextalk/nodes/node.example.com/dirextalk-connect/data".into(),
            project: ProjectConfig {
                name: "agent-node".into(),
                selection: AgentSelection {
                    connect_agent: agent,
                    host_runtime: HostRuntime::Direct,
                },
                work_dir: "/home/a/work".into(),
                command: None,
                args: Vec::new(),
                matrix: MatrixSession {
                    homeserver: "https://node.example.com/".into(),
                    access_token: "matrix-secret".into(),
                    user_id: "@agent:node.example.com".into(),
                    device_id: "DEVICE".into(),
                    room_id: "!real-room:node.example.com".into(),
                    admin_from: "@owner:node.example.com".into(),
                },
                mcp: Some(McpInjection {
                    url: "https://node.example.com/mcp".into(),
                    server_name: "dirextalk-node_example_com".into(),
                    agent_token: "agent-secret".into(),
                    node_id: "agent-node".into(),
                }),
            },
        }
    }

    #[test]
    fn renders_exactly_one_matrix_platform_and_canonical_session_mcp() {
        let text = render_matrix_config(&config(ConnectAgent::Codex)).unwrap();
        let parsed: toml::Value = toml::from_str(&text).unwrap();
        let projects = parsed["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0]["platforms"].as_array().unwrap().len(), 1);
        assert_eq!(projects[0]["platforms"][0]["type"].as_str(), Some("matrix"));
        assert_eq!(
            projects[0]["agent"]["options"]["mcp_capability"].as_str(),
            Some("session")
        );
        assert_eq!(
            projects[0]["admin_from"].as_str(),
            Some("@owner:node.example.com")
        );
    }

    #[test]
    fn host_managed_omits_all_mcp_secrets_and_fields() {
        let text = render_matrix_config(&config(ConnectAgent::Cursor)).unwrap();
        for forbidden in [
            "agent-secret",
            "mcp_url",
            "mcp_server_name",
            "mcp_agent_token",
            "mcp_node_id",
            "mcp_capability",
        ] {
            assert!(!text.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn rejects_owner_identity_and_pseudo_room() {
        let mut value = config(ConnectAgent::Codex);
        value.project.matrix.user_id = "@owner:node.example.com".into();
        assert!(render_matrix_config(&value).is_err());
        value.project.matrix.user_id = "@agent:node.example.com".into();
        value.project.matrix.room_id = "!agent:node.example.com".into();
        assert!(render_matrix_config(&value).is_err());
        value.project.matrix.room_id = "!not real:node.example.com".into();
        assert!(render_matrix_config(&value).is_err());
    }

    #[test]
    fn rejects_cross_service_or_ambiguous_mcp_binding() {
        let mut value = config(ConnectAgent::Codex);
        value.project.mcp.as_mut().unwrap().url = "https://other.example.com/mcp".into();
        assert!(render_matrix_config(&value).is_err());

        value.project.mcp.as_mut().unwrap().url = "https://node.example.com/mcp".into();
        value.project.mcp.as_mut().unwrap().node_id = "other-node".into();
        assert!(render_matrix_config(&value).is_err());

        value.project.mcp.as_mut().unwrap().node_id = "agent-node".into();
        value.project.mcp.as_mut().unwrap().server_name = "Dirextalk node".into();
        assert!(render_matrix_config(&value).is_err());

        value.project.mcp.as_mut().unwrap().server_name = "dirextalk-node".into();
        value.project.mcp.as_mut().unwrap().agent_token = "Bearer embedded-secret".into();
        let error = render_matrix_config(&value).unwrap_err().to_string();
        assert!(!error.contains("embedded-secret"));
    }

    #[test]
    fn openclaw_retains_fixed_acp_shape_and_uses_host_managed_mcp() {
        let mut value = config(ConnectAgent::Acp);
        value.project.selection.host_runtime = HostRuntime::OpenClaw;
        value.project.command = Some("/opt/openclaw/bin/openclaw".into());
        value.project.args = vec![
            "--profile".into(),
            "dirextalk-node".into(),
            "acp".into(),
            "--session".into(),
            "agent:main:main".into(),
        ];
        let rendered = render_matrix_config(&value).unwrap();
        assert!(!rendered.contains("agent-secret"));

        value.project.args = vec!["gateway".into(), "--token".into(), "secret".into()];
        assert!(render_matrix_config(&value).is_err());
    }

    #[test]
    fn hermes_requires_service_binary_and_adapter_prefix() {
        let mut value = config(ConnectAgent::Acp);
        value.project.selection.host_runtime = HostRuntime::Hermes;
        value.project.command = Some(
            "/home/a/.dirextalk/nodes/node.example.com/dirextalk-connect/dirextalk-connect".into(),
        );
        value.project.args = vec![
            "hermes-acp-adapter".into(),
            "--".into(),
            "/home/a/.local/bin/hermes".into(),
            "-p".into(),
            "dirextalk-node".into(),
            "acp".into(),
        ];
        assert!(render_matrix_config(&value).is_ok());

        value.project.command = Some("/usr/local/bin/dirextalk-connect".into());
        assert!(render_matrix_config(&value).is_err());
    }

    #[test]
    fn every_registry_class_renders_or_fails_as_declared() {
        for agent in [
            ConnectAgent::Acp,
            ConnectAgent::ClaudeCode,
            ConnectAgent::Codex,
            ConnectAgent::Copilot,
            ConnectAgent::Gemini,
            ConnectAgent::Kimi,
            ConnectAgent::OpenCode,
            ConnectAgent::Qoder,
        ] {
            let mut value = config(agent);
            if agent == ConnectAgent::Acp {
                value.project.command = Some("/usr/local/bin/acp-agent".into());
            }
            let rendered = render_matrix_config(&value).unwrap();
            assert!(rendered.contains("mcp_capability = \"session\""));
        }

        for agent in [
            ConnectAgent::Antigravity,
            ConnectAgent::Cursor,
            ConnectAgent::IFlow,
        ] {
            let rendered = render_matrix_config(&config(agent)).unwrap();
            assert!(!rendered.contains("mcp_agent_token"));
            assert!(!rendered.contains("mcp_capability"));
        }

        for agent in [
            ConnectAgent::Devin,
            ConnectAgent::Pi,
            ConnectAgent::Reasonix,
            ConnectAgent::Tmux,
        ] {
            assert!(render_matrix_config(&config(agent)).is_err());
        }
    }

    #[test]
    fn generic_acp_requires_explicit_command() {
        let value = config(ConnectAgent::Acp);
        assert!(render_matrix_config(&value).is_err());
    }
}
