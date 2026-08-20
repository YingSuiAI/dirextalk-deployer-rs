use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MCP_SERVER_NAME: &str = "dirextalk-message-server";
const MAX_MCP_RESPONSE_BYTES: usize = 1024 * 1024;
const CANONICAL_READ_ONLY_TOOLS: &[&str] = &[
    "dirextalk_contacts_list",
    "dirextalk_contacts_search",
    "dirextalk_rooms_search",
    "dirextalk_messages_list",
    "dirextalk_room_members_list",
    "dirextalk_channel_posts_list",
    "dirextalk_channel_comments_list",
];
const CANONICAL_WRITE_TOOLS: &[&str] = &[
    "dirextalk_messages_send",
    "dirextalk_channel_comments_create",
];

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("invalid MCP endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("MCP transport failed: {0}")]
    Transport(String),
    #[error("MCP protocol failed: {0}")]
    Protocol(String),
    #[error("MCP server returned JSON-RPC error {code}")]
    Rpc { code: i64 },
    #[error("MCP smoke tool is not a canonical read-only tool")]
    NotReadOnly,
}

#[async_trait]
pub trait McpTransport: Send + Sync {
    async fn post(&self, request: Value) -> Result<Value, McpError>;
}

pub struct HttpMcpTransport {
    client: reqwest::Client,
    endpoint: Url,
    agent_token: String,
}

impl HttpMcpTransport {
    /// Creates a direct Streamable HTTP transport.
    ///
    /// # Errors
    ///
    /// Returns an error unless the endpoint is canonical HTTPS `/mcp`, the
    /// token is non-empty, and an HTTPS client can be built.
    pub fn new(endpoint: &str, agent_token: impl Into<String>) -> Result<Self, McpError> {
        crate::ensure_tls_provider();
        let endpoint =
            Url::parse(endpoint).map_err(|error| McpError::InvalidEndpoint(error.to_string()))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || endpoint.path() != "/mcp"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(McpError::InvalidEndpoint(
                "expected an absolute HTTPS URL with path exactly /mcp".to_owned(),
            ));
        }
        let agent_token = agent_token.into();
        if agent_token.is_empty() {
            return Err(McpError::InvalidEndpoint(
                "agent token must not be empty".to_owned(),
            ));
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| McpError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            agent_token,
        })
    }
}

#[async_trait]
impl McpTransport for HttpMcpTransport {
    async fn post(&self, request: Value) -> Result<Value, McpError> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.agent_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|error| McpError::Transport(error.to_string()))?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MCP_RESPONSE_BYTES as u64)
        {
            return Err(McpError::Protocol("MCP response is too large".to_owned()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| McpError::Transport(error.to_string()))?;
        if body.len() > MAX_MCP_RESPONSE_BYTES {
            return Err(McpError::Protocol("MCP response is too large".to_owned()));
        }
        if !status.is_success() {
            return Err(McpError::Transport(format!("HTTP {status}")));
        }
        serde_json::from_slice(&body).map_err(|error| McpError::Protocol(error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(default)]
    pub annotations: ToolAnnotations,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct ToolAnnotations {
    #[serde(default, rename = "readOnlyHint")]
    read_only_hint: bool,
    #[serde(default, rename = "destructiveHint")]
    destructive_hint: bool,
}

impl McpTool {
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.annotations.read_only_hint && !self.annotations.destructive_hint
    }
}

#[derive(Clone, Debug)]
pub struct ReadOnlySmoke {
    pub tool_name: String,
    pub arguments: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct McpCheck {
    pub protocol_version: String,
    pub server_name: String,
    pub tools: Vec<String>,
    pub smoke_tool: String,
}

pub struct McpClient<T> {
    transport: T,
}

impl<T: McpTransport> McpClient<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Initializes MCP and obtains the advertised tool registry.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, JSON-RPC, capability, or schema failure.
    pub async fn initialize_and_discover(
        &self,
    ) -> Result<(String, String, Vec<McpTool>), McpError> {
        let initialized = self
            .rpc(
                1,
                "initialize",
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "dirextalk-deployer", "version": env!("CARGO_PKG_VERSION")}
                }),
            )
            .await?;
        let protocol_version = initialized
            .get("protocolVersion")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| McpError::Protocol("initialize omitted protocolVersion".to_owned()))?
            .to_owned();
        if protocol_version != MCP_PROTOCOL_VERSION {
            return Err(McpError::Protocol(
                "initialize negotiated an unsupported protocol version".to_owned(),
            ));
        }
        let server_name = initialized
            .pointer("/serverInfo/name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| McpError::Protocol("initialize omitted serverInfo.name".to_owned()))?
            .to_owned();
        if server_name != MCP_SERVER_NAME {
            return Err(McpError::Protocol(
                "initialize returned an unexpected server".to_owned(),
            ));
        }
        if initialized
            .pointer("/serverInfo/version")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(McpError::Protocol(
                "initialize omitted serverInfo.version".to_owned(),
            ));
        }
        if !initialized
            .pointer("/capabilities/tools")
            .is_some_and(Value::is_object)
        {
            return Err(McpError::Protocol(
                "initialize omitted tools capability".to_owned(),
            ));
        }

        let listed = self.rpc(2, "tools/list", json!({})).await?;
        let tools: Vec<McpTool> = serde_json::from_value(
            listed
                .get("tools")
                .cloned()
                .ok_or_else(|| McpError::Protocol("tools/list omitted tools".to_owned()))?,
        )
        .map_err(|error| McpError::Protocol(error.to_string()))?;
        if tools.is_empty() {
            return Err(McpError::Protocol(
                "tools/list returned no tools".to_owned(),
            ));
        }
        let mut names = HashSet::with_capacity(tools.len());
        for tool in &tools {
            if tool.name.is_empty() || !names.insert(tool.name.as_str()) {
                return Err(McpError::Protocol(
                    "tools/list contains an empty or duplicate tool name".to_owned(),
                ));
            }
            if !CANONICAL_READ_ONLY_TOOLS.contains(&tool.name.as_str())
                && !CANONICAL_WRITE_TOOLS.contains(&tool.name.as_str())
            {
                return Err(McpError::Protocol(
                    "tools/list contains an unknown tool".to_owned(),
                ));
            }
            if !tool.input_schema.is_object() {
                return Err(McpError::Protocol(
                    "tools/list contains a non-object input schema".to_owned(),
                ));
            }
        }
        Ok((protocol_version, server_name, tools))
    }

    /// Calls exactly one annotation-proven read-only tool.
    ///
    /// # Errors
    ///
    /// Returns before `tools/call` when the selected tool is absent or unsafe,
    /// and propagates MCP transport/protocol failures.
    pub async fn verify_read_only(&self, smoke: &ReadOnlySmoke) -> Result<McpCheck, McpError> {
        let (protocol_version, server_name, tools) = self.initialize_and_discover().await?;
        let tool = tools
            .iter()
            .find(|tool| tool.name == smoke.tool_name)
            .ok_or(McpError::NotReadOnly)?;
        if !tool.is_read_only() || !CANONICAL_READ_ONLY_TOOLS.contains(&tool.name.as_str()) {
            return Err(McpError::NotReadOnly);
        }
        let result = self
            .rpc(
                3,
                "tools/call",
                json!({"name": smoke.tool_name, "arguments": smoke.arguments}),
            )
            .await?;
        if result.get("isError").and_then(Value::as_bool) != Some(false) {
            return Err(McpError::Protocol(format!(
                "read-only smoke tool {} did not report success",
                smoke.tool_name
            )));
        }
        Ok(McpCheck {
            protocol_version,
            server_name,
            tools: tools.into_iter().map(|tool| tool.name).collect(),
            smoke_tool: smoke.tool_name.clone(),
        })
    }

    async fn rpc(&self, id: u64, method: &str, params: Value) -> Result<Value, McpError> {
        let response = self
            .transport
            .post(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(McpError::Protocol(
                "response is not JSON-RPC 2.0".to_owned(),
            ));
        }
        if response.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(McpError::Protocol(
                "response id does not match the request".to_owned(),
            ));
        }
        if let Some(error) = response.get("error") {
            return Err(McpError::Rpc {
                code: error.get("code").and_then(Value::as_i64).unwrap_or(-1),
            });
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| McpError::Protocol("response omitted result".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FakeTransport {
        requests: Mutex<Vec<Value>>,
    }

    #[async_trait]
    impl McpTransport for FakeTransport {
        async fn post(&self, request: Value) -> Result<Value, McpError> {
            let method = request["method"].as_str().unwrap().to_owned();
            self.requests.lock().unwrap().push(request);
            Ok(match method.as_str() {
                "initialize" => json!({
                    "jsonrpc":"2.0", "id":1,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "serverInfo":{"name":"dirextalk-message-server","version":"test"},
                        "capabilities":{"tools":{}}
                    }
                }),
                "tools/list" => json!({
                    "jsonrpc":"2.0", "id":2,
                    "result":{"tools":[
                        {"name":"dirextalk_messages_list","inputSchema":{"type":"object"},
                         "annotations":{"readOnlyHint":true,"destructiveHint":false}},
                        {"name":"dirextalk_messages_send","inputSchema":{"type":"object"},
                         "annotations":{"readOnlyHint":true,"destructiveHint":false}}
                    ]}
                }),
                "tools/call" => json!({"jsonrpc":"2.0", "id":3, "result":{"isError":false}}),
                _ => unreachable!(),
            })
        }
    }

    #[tokio::test]
    async fn smoke_never_pollutes_normal_chat_or_calls_write_tools() {
        let transport = FakeTransport {
            requests: Mutex::new(Vec::new()),
        };
        let client = McpClient::new(transport);
        let check = client
            .verify_read_only(&ReadOnlySmoke {
                tool_name: "dirextalk_messages_list".into(),
                arguments: serde_json::Map::new(),
            })
            .await
            .unwrap();
        assert_eq!(check.smoke_tool, "dirextalk_messages_list");
        let requests = client.transport.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["initialize", "tools/list", "tools/call"]
        );
        assert_eq!(
            requests[2].pointer("/params/name").and_then(Value::as_str),
            Some("dirextalk_messages_list")
        );
        let serialized = serde_json::to_string(&*requests).unwrap();
        assert!(!serialized.contains("messages/send"));
        assert!(!serialized.contains("normal chat"));
    }

    #[tokio::test]
    async fn refuses_advertised_write_tool_before_call() {
        let client = McpClient::new(FakeTransport {
            requests: Mutex::new(Vec::new()),
        });
        let error = client
            .verify_read_only(&ReadOnlySmoke {
                tool_name: "dirextalk_messages_send".into(),
                arguments: serde_json::Map::new(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::NotReadOnly));
        assert_eq!(client.transport.requests.lock().unwrap().len(), 2);
    }

    struct QueueTransport {
        responses: Mutex<std::collections::VecDeque<Value>>,
    }

    #[async_trait]
    impl McpTransport for QueueTransport {
        async fn post(&self, _request: Value) -> Result<Value, McpError> {
            Ok(self.responses.lock().unwrap().pop_front().unwrap())
        }
    }

    #[tokio::test]
    async fn rejects_wrong_protocol_before_tool_discovery() {
        let client = McpClient::new(QueueTransport {
            responses: Mutex::new(std::collections::VecDeque::from([json!({
                "jsonrpc":"2.0", "id":1,
                "result": {
                    "protocolVersion":"2024-11-05",
                    "serverInfo":{"name":MCP_SERVER_NAME,"version":"test"},
                    "capabilities":{"tools":{}}
                }
            })])),
        });
        let error = client.initialize_and_discover().await.unwrap_err();
        assert!(matches!(error, McpError::Protocol(_)));
    }

    #[tokio::test]
    async fn rejects_duplicate_tool_names_before_smoke_call() {
        let client = McpClient::new(QueueTransport {
            responses: Mutex::new(std::collections::VecDeque::from([
                json!({
                    "jsonrpc":"2.0", "id":1,
                    "result": {
                        "protocolVersion":MCP_PROTOCOL_VERSION,
                        "serverInfo":{"name":MCP_SERVER_NAME,"version":"test"},
                        "capabilities":{"tools":{}}
                    }
                }),
                json!({
                    "jsonrpc":"2.0", "id":2,
                    "result":{"tools":[
                        {"name":"dirextalk_messages_list","inputSchema":{"type":"object"},
                         "annotations":{"readOnlyHint":true,"destructiveHint":false}},
                        {"name":"dirextalk_messages_list","inputSchema":{"type":"object"},
                         "annotations":{"readOnlyHint":false,"destructiveHint":true}}
                    ]}
                }),
            ])),
        });
        let error = client.initialize_and_discover().await.unwrap_err();
        assert!(matches!(error, McpError::Protocol(_)));
    }

    #[tokio::test]
    async fn rpc_error_omits_untrusted_remote_message() {
        let client = McpClient::new(QueueTransport {
            responses: Mutex::new(std::collections::VecDeque::from([
                json!({
                    "jsonrpc":"2.0", "id":1,
                    "result": {
                        "protocolVersion":MCP_PROTOCOL_VERSION,
                        "serverInfo":{"name":MCP_SERVER_NAME,"version":"test"},
                        "capabilities":{"tools":{}}
                    }
                }),
                json!({
                    "jsonrpc":"2.0", "id":2,
                    "result":{"tools":[
                        {"name":"dirextalk_messages_list","inputSchema":{"type":"object"},
                         "annotations":{"readOnlyHint":true,"destructiveHint":false}}
                    ]}
                }),
                json!({
                    "jsonrpc":"2.0", "id":3,
                    "error":{"code":-32602,"message":"echoed agent-secret"}
                }),
            ])),
        });
        let error = client
            .verify_read_only(&ReadOnlySmoke {
                tool_name: "dirextalk_messages_list".into(),
                arguments: serde_json::Map::new(),
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("-32602"));
        assert!(!error.contains("agent-secret"));
    }
}
