//! Connecting to one MCP server (stdio / streamable HTTP / legacy SSE) and
//! the JSON-in/JSON-out operations the CLI and gateway share.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderName, HeaderValue};
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientConfig, GetPromptRequestParams,
    Implementation, ReadResourceRequestParams,
};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use rmcp::{ServiceExt, service::ClientInitializeError};
use serde_json::{Map, Value, json};

use crate::config::{Server, Transport};
use crate::oauth::{NeedsLogin, OAuth, probe};
use crate::sse::SseTransport;

pub type Service = RunningService<RoleClient, ClientConfig>;

pub enum ConnectError {
    /// HTTP 401, with the `WWW-Authenticate` challenge when present.
    Unauthorized(Option<String>),
    Other(anyhow::Error),
}

fn handler() -> ClientConfig {
    ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("mcpx", env!("CARGO_PKG_VERSION")),
    )
}

pub struct Connector {
    pub oauth: Arc<OAuth>,
    /// Pass stdio servers' stderr through (else discarded).
    pub inherit_stderr: bool,
    pub connect_timeout: Duration,
    http: reqwest::Client,
}

impl Connector {
    pub fn new(oauth: Arc<OAuth>, inherit_stderr: bool) -> Self {
        Self {
            oauth,
            inherit_stderr,
            connect_timeout: Duration::from_secs(30),
            http: reqwest::Client::new(),
        }
    }

    pub async fn connect(&self, server: &Server) -> Result<Service> {
        tokio::time::timeout(self.connect_timeout, self.connect_inner(server))
            .await
            .map_err(|_| anyhow!("timed out connecting to '{}'", server.name))?
            .with_context(|| format!("connect '{}'", server.name))
    }

    async fn connect_inner(&self, server: &Server) -> Result<Service> {
        match &server.transport {
            Transport::Stdio {
                command,
                args,
                env,
                cwd,
            } => {
                let mut cmd = tokio::process::Command::new(resolve_command(command));
                cmd.args(args).envs(env);
                if let Some(d) = cwd {
                    cmd.current_dir(d);
                }
                let stderr = if self.inherit_stderr {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                };
                let (t, _) = TokioChildProcess::builder(cmd)
                    .stderr(stderr)
                    .spawn()
                    .with_context(|| format!("spawn '{command}'"))?;
                handler().serve(t).await.map_err(|e| anyhow!("{e}"))
            }
            Transport::Http { url, headers, sse } => {
                let mut token = self.oauth.access_token(server).await?;
                let mut retried = false;
                loop {
                    let r = if *sse {
                        self.connect_sse(url, headers, token.as_deref()).await
                    } else {
                        self.connect_streamable(url, headers, token.as_deref())
                            .await
                    };
                    match r {
                        Ok(s) => return Ok(s),
                        Err(ConnectError::Other(e)) => return Err(e),
                        Err(ConnectError::Unauthorized(ch)) => {
                            if server.has_static_auth() {
                                bail!(
                                    "HTTP 401 Unauthorized (check the Authorization header in mcp.json)"
                                );
                            }
                            if retried {
                                return Err(NeedsLogin(server.name.clone()).into());
                            }
                            retried = true;
                            token = Some(self.oauth.on_unauthorized(server, ch.as_deref()).await?);
                        }
                    }
                }
            }
        }
    }

    async fn connect_streamable(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
        token: Option<&str>,
    ) -> Result<Service, ConnectError> {
        let mut custom = HashMap::new();
        for (k, v) in headers {
            let name = HeaderName::try_from(k.as_str())
                .map_err(|e| ConnectError::Other(anyhow!("header '{k}': {e}")))?;
            let val = HeaderValue::try_from(v.as_str())
                .map_err(|e| ConnectError::Other(anyhow!("header '{k}': {e}")))?;
            custom.insert(name, val);
        }
        let mut cfg = StreamableHttpClientTransportConfig::with_uri(url).custom_headers(custom);
        if let Some(t) = token {
            cfg = cfg.auth_header(t);
        }
        let t = StreamableHttpClientTransport::with_client(self.http.clone(), cfg);
        match handler().serve(t).await {
            Ok(s) => Ok(s),
            Err(e) => Err(self.classify(e, url, token).await),
        }
    }

    async fn classify(
        &self,
        e: ClientInitializeError,
        url: &str,
        token: Option<&str>,
    ) -> ConnectError {
        if let Some(ch) = e.auth_challenge() {
            return ConnectError::Unauthorized(Some(ch.to_string()));
        }
        if e.is_authorization_required() {
            return ConnectError::Unauthorized(None);
        }
        // A 401 without a challenge header is not classified by rmcp.
        if let Ok((401, ch)) = probe(&self.http, url, token).await {
            return ConnectError::Unauthorized(ch);
        }
        ConnectError::Other(anyhow!("{e}"))
    }

    async fn connect_sse(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
        token: Option<&str>,
    ) -> Result<Service, ConnectError> {
        let mut h = reqwest::header::HeaderMap::new();
        for (k, v) in headers {
            let name = HeaderName::try_from(k.as_str())
                .map_err(|e| ConnectError::Other(anyhow!("header '{k}': {e}")))?;
            let val = HeaderValue::try_from(v.as_str())
                .map_err(|e| ConnectError::Other(anyhow!("header '{k}': {e}")))?;
            h.insert(name, val);
        }
        if let Some(t) = token {
            let v = HeaderValue::try_from(format!("Bearer {t}"))
                .map_err(|e| ConnectError::Other(e.into()))?;
            h.insert(http::header::AUTHORIZATION, v);
        }
        let t = SseTransport::connect(self.http.clone(), url, h).await?;
        handler()
            .serve(t)
            .await
            .map_err(|e| ConnectError::Other(anyhow!("{e}")))
    }
}

/// True once the service loop or its transport has gone away (e.g. the
/// stdio child crashed).
pub fn is_dead(s: &Service) -> bool {
    s.is_closed() || s.peer().is_transport_closed()
}

pub fn info(s: &Service) -> Value {
    match s.peer().peer_info() {
        Some(i) => serde_json::to_value(&*i).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

fn has_capability(s: &Service, cap: &str) -> bool {
    s.peer()
        .peer_info()
        .and_then(|i| serde_json::to_value(&i.capabilities).ok())
        .is_some_and(|c| c.get(cap).is_some_and(|v| !v.is_null()))
}

pub async fn list_tools(s: &Service) -> Result<Vec<Value>> {
    if !has_capability(s, "tools") {
        return Ok(vec![]);
    }
    let tools = s
        .peer()
        .list_all_tools()
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(tools
        .iter()
        .map(|t| serde_json::to_value(t).unwrap_or(Value::Null))
        .collect())
}

pub async fn call_tool(s: &Service, tool: &str, args: Map<String, Value>) -> Result<Value> {
    let params: CallToolRequestParams =
        serde_json::from_value(json!({"name": tool, "arguments": args}))?;
    let r = s.call_tool(params).await.map_err(|e| anyhow!("{e}"))?;
    Ok(serde_json::to_value(r)?)
}

pub async fn list_resources(s: &Service) -> Result<Vec<Value>> {
    if !has_capability(s, "resources") {
        return Ok(vec![]);
    }
    let r = s
        .peer()
        .list_all_resources()
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(r.iter()
        .map(|x| serde_json::to_value(x).unwrap_or(Value::Null))
        .collect())
}

pub async fn read_resource(s: &Service, uri: &str) -> Result<Value> {
    let params: ReadResourceRequestParams = serde_json::from_value(json!({"uri": uri}))?;
    let r = s.read_resource(params).await.map_err(|e| anyhow!("{e}"))?;
    Ok(serde_json::to_value(r)?)
}

pub async fn list_prompts(s: &Service) -> Result<Vec<Value>> {
    if !has_capability(s, "prompts") {
        return Ok(vec![]);
    }
    let r = s
        .peer()
        .list_all_prompts()
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(r.iter()
        .map(|x| serde_json::to_value(x).unwrap_or(Value::Null))
        .collect())
}

pub async fn get_prompt(s: &Service, name: &str, args: Map<String, Value>) -> Result<Value> {
    // Prompt arguments are strings on the wire.
    let args: Map<String, Value> = args
        .into_iter()
        .map(|(k, v)| {
            let s = match v {
                Value::String(s) => s,
                other => other.to_string(),
            };
            (k, Value::String(s))
        })
        .collect();
    let params: GetPromptRequestParams =
        serde_json::from_value(json!({"name": name, "arguments": args}))?;
    let r = s.get_prompt(params).await.map_err(|e| anyhow!("{e}"))?;
    Ok(serde_json::to_value(r)?)
}

/// The program to spawn for a stdio server's `command`. Windows only
/// auto-resolves `.exe`, so a bare `npx` / `uvx` (really `npx.cmd`) would
/// fail to spawn; look it up on `PATH` × `PATHEXT` there. Elsewhere the
/// command is used as-is.
fn resolve_command(command: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let exts: Vec<&str> = exts.split(';').filter(|e| !e.is_empty()).collect();
        if let Some(p) = find_in_path(command, std::env::split_paths(&path), &exts, |p| {
            p.is_file()
        }) {
            return p;
        }
    }
    std::path::PathBuf::from(command)
}

/// First `dir/command{ext}` that `exists`, for a bare command name without
/// an extension; `None` for paths or names that already carry one.
#[cfg_attr(not(windows), allow(dead_code))]
fn find_in_path(
    command: &str,
    dirs: impl IntoIterator<Item = std::path::PathBuf>,
    exts: &[&str],
    exists: impl Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(command);
    if p.components().count() != 1 || p.extension().is_some() {
        return None;
    }
    dirs.into_iter()
        .flat_map(|d| exts.iter().map(move |e| d.join(format!("{command}{e}"))))
        .find(|c| exists(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn finds_cmd_shims_on_path() {
        let dirs = || vec![PathBuf::from("a"), PathBuf::from("b")];
        let exts = [".EXE", ".CMD"];
        let exists = |p: &std::path::Path| p == std::path::Path::new("b").join("npx.CMD");
        assert_eq!(
            find_in_path("npx", dirs(), &exts, exists),
            Some(PathBuf::from("b").join("npx.CMD"))
        );
        assert_eq!(find_in_path("npx.cmd", dirs(), &exts, exists), None);
        assert_eq!(find_in_path("x/npx", dirs(), &exts, exists), None);
        assert_eq!(find_in_path("uvx", dirs(), &exts, exists), None);
    }
}
