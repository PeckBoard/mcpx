//! A tiny MCP server (`mcpx echo-server`, hidden) used by the test suite and
//! handy for trying mcpx out: tools `echo` and `fail`, resource
//! `mem://hello`, prompt `greet`.

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, Implementation, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::json;

#[derive(Clone, Default)]
pub struct EchoServer;

fn from<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, ErrorData> {
    serde_json::from_value(v).map_err(|e| ErrorData::internal_error(e.to_string(), None))
}

impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("mcpx-echo", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        from(json!({"tools": [
            {"name": "echo", "description": "Echo back `message`.",
             "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}},
            {"name": "fail", "description": "Always returns an error result.",
             "inputSchema": {"type": "object", "properties": {}}}
        ]}))
    }

    async fn call_tool(
        &self,
        r: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = r.arguments.unwrap_or_default();
        match r.name.as_ref() {
            "echo" => {
                let msg = args
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
                Ok(CallToolResult::success(vec![ContentBlock::text(msg)]).into())
            }
            "fail" => Ok(CallToolResult::error(vec![ContentBlock::text("boom")]).into()),
            other => Err(ErrorData::invalid_params(
                format!("unknown tool {other}"),
                None,
            )),
        }
    }

    async fn list_resources(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        from(
            json!({"resources": [{"uri": "mem://hello", "name": "hello", "mimeType": "text/plain"}]}),
        )
    }

    async fn read_resource(
        &self,
        r: ReadResourceRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if r.uri != "mem://hello" {
            return Err(ErrorData::invalid_params("no such resource", None));
        }
        let res: ReadResourceResult = from(json!({"contents": [
            {"uri": "mem://hello", "mimeType": "text/plain", "text": "hello world"}
        ]}))?;
        Ok(res.into())
    }

    async fn list_prompts(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        from(
            json!({"prompts": [{"name": "greet", "description": "Greet someone.",
            "arguments": [{"name": "who", "required": true}]}]}),
        )
    }

    async fn get_prompt(
        &self,
        r: GetPromptRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let who = r
            .arguments
            .as_ref()
            .and_then(|a| a.get("who"))
            .and_then(|v| v.as_str())
            .unwrap_or("world")
            .to_string();
        let res: GetPromptResult = from(json!({"messages": [
            {"role": "user", "content": {"type": "text", "text": format!("Hello, {who}!")}}
        ]}))?;
        Ok(res.into())
    }
}

/// Serve [`EchoServer`] on stdin/stdout until the client disconnects.
pub async fn run_stdio() -> anyhow::Result<()> {
    let svc = EchoServer
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    svc.waiting().await?;
    Ok(())
}
