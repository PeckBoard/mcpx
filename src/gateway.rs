//! `mcpx serve`: one loopback HTTP endpoint in front of every configured
//! server. `/mcp` is a streamable-HTTP MCP server exposing all tools as
//! `server__tool`; the REST routes mirror the CLI commands.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, Implementation, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::paths::{Paths, write_private};
use crate::pool::{Denied, Pool, SEP};

pub const DEFAULT_PORT: u16 = 7790;

/// Contents of `gateway.json`, which tells CLI invocations where the
/// running gateway is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayState {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub pid: u32,
}

impl GatewayState {
    pub fn read(paths: &Paths) -> Option<Self> {
        serde_json::from_str(&std::fs::read_to_string(paths.gateway()).ok()?).ok()
    }
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

pub struct Running {
    pub addr: SocketAddr,
    pub token: Option<String>,
    pub ct: CancellationToken,
    pub handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct AppState {
    pool: Arc<Pool>,
    token: Option<Arc<str>>,
}

/// Bind 127.0.0.1:`port` (0 = random) and serve until `ct` is cancelled.
pub async fn start(pool: Arc<Pool>, port: u16, auth: bool) -> Result<Running> {
    let token = auth.then(|| {
        use base64::Engine;
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    });
    let ct = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("bind 127.0.0.1:{port}"))?;
    let addr = listener.local_addr()?;
    let app = router(pool.clone(), token.clone(), ct.child_token());
    let reaper = pool.spawn_reaper();
    let shutdown = ct.clone();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await;
        reaper.abort();
        pool.shutdown().await;
    });
    Ok(Running {
        addr,
        token,
        ct,
        handle,
    })
}

fn router(pool: Arc<Pool>, token: Option<String>, ct: CancellationToken) -> Router {
    let mcp_pool = pool.clone();
    let mcp = StreamableHttpService::new(
        move || {
            Ok(Aggregate {
                pool: mcp_pool.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_cancellation_token(ct),
    );
    let state = AppState {
        pool,
        token: token.map(Into::into),
    };
    Router::new()
        .route("/health", get(health))
        .route("/servers", get(servers))
        .route("/tools", get(tools))
        .route("/call", post(call))
        .route("/resources", get(resources))
        .route("/read", post(read))
        .route("/prompts", get(prompts))
        .route("/prompt", post(prompt))
        .nest_service("/mcp", mcp)
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Loopback `Host` only (DNS-rebinding defence) and, unless `--no-auth`,
/// `Authorization: Bearer <token>` on everything but `/health`. Without a
/// token, browser requests (those carrying `Origin`) are refused.
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let hostname = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    if !matches!(hostname, "127.0.0.1" | "localhost" | "::1") {
        return err(StatusCode::FORBIDDEN, "host not allowed");
    }
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }
    match &st.token {
        Some(tok) => {
            let ok = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer "))
                .is_some_and(|t| constant_eq(t.as_bytes(), tok.as_bytes()));
            if !ok {
                return err(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
            }
        }
        None => {
            if req.headers().contains_key(header::ORIGIN) {
                return err(StatusCode::FORBIDDEN, "browser requests need --auth");
            }
        }
    }
    next.run(req).await
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({"error": {"message": msg.into()}}))).into_response()
}

struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let msg = format!("{:#}", self.0);
        let code = if self.0.downcast_ref::<Denied>().is_some() {
            StatusCode::FORBIDDEN
        } else if msg.starts_with("unknown server") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        };
        err(code, msg)
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

async fn health() -> Json<Value> {
    Json(json!({"ok": true, "name": "mcpx", "version": env!("CARGO_PKG_VERSION")}))
}

#[derive(Deserialize)]
struct ServerQ {
    server: Option<String>,
}

async fn servers(State(st): State<AppState>) -> Json<Value> {
    Json(Value::Array(st.pool.servers().await))
}

async fn tools(State(st): State<AppState>, Query(q): Query<ServerQ>) -> ApiResult {
    Ok(Json(st.pool.tools(q.server.as_deref()).await?))
}

async fn resources(State(st): State<AppState>, Query(q): Query<ServerQ>) -> ApiResult {
    Ok(Json(st.pool.resources(q.server.as_deref()).await?))
}

async fn prompts(State(st): State<AppState>, Query(q): Query<ServerQ>) -> ApiResult {
    Ok(Json(st.pool.prompts(q.server.as_deref()).await?))
}

#[derive(Deserialize)]
struct CallReq {
    server: String,
    tool: String,
    #[serde(default)]
    arguments: Map<String, Value>,
    /// Seconds.
    #[serde(default)]
    timeout: Option<u64>,
}

async fn call(State(st): State<AppState>, Json(r): Json<CallReq>) -> ApiResult {
    let t = r.timeout.map(Duration::from_secs);
    Ok(Json(
        st.pool.call(&r.server, &r.tool, r.arguments, t).await?,
    ))
}

#[derive(Deserialize)]
struct ReadReq {
    server: String,
    uri: String,
}

async fn read(State(st): State<AppState>, Json(r): Json<ReadReq>) -> ApiResult {
    Ok(Json(st.pool.read(&r.server, &r.uri).await?))
}

#[derive(Deserialize)]
struct PromptReq {
    server: String,
    name: String,
    #[serde(default)]
    arguments: Map<String, Value>,
}

async fn prompt(State(st): State<AppState>, Json(r): Json<PromptReq>) -> ApiResult {
    Ok(Json(st.pool.prompt(&r.server, &r.name, r.arguments).await?))
}

/// The `/mcp` endpoint's server: every upstream tool/prompt, renamed
/// `server__name`, routed back by prefix.
#[derive(Clone)]
struct Aggregate {
    pool: Arc<Pool>,
}

fn rename(items: &Value, key: &str) -> Vec<Value> {
    items[key]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut t| {
            if let Some(q) = t.get("qualifiedName").cloned() {
                t["name"] = q;
            }
            if let Some(o) = t.as_object_mut() {
                o.remove("qualifiedName");
                o.remove("server");
            }
            t
        })
        .collect()
}

fn internal(e: impl std::fmt::Display) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

impl Aggregate {
    fn route<'a>(&self, q: &'a str) -> Result<(String, &'a str), ErrorData> {
        self.pool.split_qualified(q).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("unknown tool '{q}' (expected server{SEP}name)"),
                None,
            )
        })
    }
}

impl ServerHandler for Aggregate {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new(
            "mcpx-gateway",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(format!(
            "Aggregates several MCP servers. Tools and prompts are named <server>{SEP}<name>."
        ))
    }

    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let v = self.pool.tools(None).await.map_err(internal)?;
        serde_json::from_value(json!({"tools": rename(&v, "tools")})).map_err(internal)
    }

    async fn call_tool(
        &self,
        r: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (server, tool) = self.route(&r.name)?;
        match self
            .pool
            .call(&server, tool, r.arguments.unwrap_or_default(), None)
            .await
        {
            Ok(v) => {
                let res: CallToolResult = serde_json::from_value(v).map_err(internal)?;
                Ok(res.into())
            }
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!("{e:#}"))]).into()),
        }
    }

    async fn list_resources(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let v = self.pool.resources(None).await.map_err(internal)?;
        let items: Vec<Value> = v["resources"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|mut r| {
                if let Some(o) = r.as_object_mut() {
                    o.remove("qualifiedName");
                    o.remove("server");
                }
                r
            })
            .collect();
        serde_json::from_value(json!({"resources": items})).map_err(internal)
    }

    async fn read_resource(
        &self,
        r: ReadResourceRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        // URIs are not namespaced: ask the servers that list it, else all.
        let listed = self.pool.resources(None).await.map_err(internal)?;
        let mut order: Vec<String> = listed["resources"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|x| x["uri"].as_str() == Some(r.uri.as_str()))
            .filter_map(|x| x["server"].as_str().map(str::to_string))
            .collect();
        for n in self.pool.names() {
            if !order.contains(&n) {
                order.push(n);
            }
        }
        let mut last = None;
        for n in order {
            match self.pool.read(&n, &r.uri).await {
                Ok(v) => {
                    let res: ReadResourceResult = serde_json::from_value(v).map_err(internal)?;
                    return Ok(res.into());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(ErrorData::invalid_params(
            format!(
                "resource '{}' not found{}",
                r.uri,
                last.map(|e| format!(": {e:#}")).unwrap_or_default()
            ),
            None,
        ))
    }

    async fn list_prompts(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let v = self.pool.prompts(None).await.map_err(internal)?;
        serde_json::from_value(json!({"prompts": rename(&v, "prompts")})).map_err(internal)
    }

    async fn get_prompt(
        &self,
        r: GetPromptRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let (server, name) = self.route(&r.name)?;
        let args: Map<String, Value> = r
            .arguments
            .and_then(|a| serde_json::to_value(a).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let v = self
            .pool
            .prompt(&server, name, args)
            .await
            .map_err(internal)?;
        let res: GetPromptResult = serde_json::from_value(v).map_err(internal)?;
        Ok(res.into())
    }
}

/// `mcpx serve` entry point: start, publish `gateway.json`, run until
/// Ctrl-C / SIGTERM, then clean up.
pub async fn serve_forever(pool: Arc<Pool>, paths: &Paths, port: u16, auth: bool) -> Result<()> {
    let running = start(pool, port, auth).await?;
    let state = GatewayState {
        port: running.addr.port(),
        token: running.token.clone(),
        pid: std::process::id(),
    };
    write_private(
        &paths.gateway(),
        serde_json::to_string_pretty(&state)?.as_bytes(),
    )?;
    eprintln!(
        "mcpx gateway listening on http://{} (MCP endpoint: /mcp; token in {})",
        running.addr,
        paths.gateway().display()
    );
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    if GatewayState::read(paths).is_some_and(|s| s.pid == std::process::id()) {
        let _ = std::fs::remove_file(paths.gateway());
    }
    running.ct.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), running.handle).await;
    Ok(())
}
