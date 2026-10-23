//! OAuth against a fake authorization server + protected MCP server:
//! RFC 9728/8414 discovery, dynamic client registration, authorization
//! code with PKCE (loopback callback driven by the test), refresh after
//! revocation, and client_credentials.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use mcpx::client::Connector;
use mcpx::config::Config;
use mcpx::oauth::{Browser, OAuth};
use mcpx::pool::Pool;
use mcpx::testserver::EchoServer;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct AsState {
    base: String,
    clients: HashMap<String, Vec<String>>,
    codes: HashMap<String, (String, String, String)>, // code -> (client, redirect, challenge)
    access: HashSet<String>,
    refresh: HashSet<String>,
    n: u64,
    refresh_grants: u32,
    cc_grants: u32,
    resources_seen: Vec<String>,
}

type S = Arc<Mutex<AsState>>;

fn mint(st: &mut AsState, prefix: &str) -> String {
    st.n += 1;
    format!("{prefix}-{}", st.n)
}

async fn prm(State(s): State<S>) -> Json<Value> {
    let b = s.lock().unwrap().base.clone();
    Json(
        json!({"resource": format!("{b}/mcp"), "authorization_servers": [b], "scopes_supported": ["mcp"]}),
    )
}

async fn asm(State(s): State<S>) -> Json<Value> {
    let b = s.lock().unwrap().base.clone();
    Json(json!({
        "issuer": b,
        "authorization_endpoint": format!("{b}/authorize"),
        "token_endpoint": format!("{b}/token"),
        "registration_endpoint": format!("{b}/register"),
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn register(State(s): State<S>, Json(body): Json<Value>) -> Response {
    let mut st = s.lock().unwrap();
    let id = mint(&mut st, "client");
    let redirects: Vec<String> = body["redirect_uris"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(redirects.iter().all(|r| r.starts_with("http://127.0.0.1:")));
    st.clients.insert(id.clone(), redirects);
    (StatusCode::CREATED, Json(json!({"client_id": id}))).into_response()
}

async fn authorize(State(s): State<S>, Query(q): Query<HashMap<String, String>>) -> Response {
    let mut st = s.lock().unwrap();
    let client = &q["client_id"];
    let redirect = &q["redirect_uri"];
    assert!(
        st.clients[client].contains(redirect),
        "redirect not registered"
    );
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["response_type"], "code");
    assert_eq!(q.get("scope").map(String::as_str), Some("mcp"));
    let res = q["resource"].clone();
    st.resources_seen.push(res);
    let code = mint(&mut st, "code");
    st.codes.insert(
        code.clone(),
        (
            client.clone(),
            redirect.clone(),
            q["code_challenge"].clone(),
        ),
    );
    Redirect::to(&format!("{redirect}?code={code}&state={}", q["state"])).into_response()
}

fn issue(st: &mut AsState, with_refresh: bool) -> Value {
    let a = mint(st, "at");
    st.access.insert(a.clone());
    let mut v = json!({"access_token": a, "token_type": "Bearer", "expires_in": 3600});
    if with_refresh {
        let r = mint(st, "rt");
        st.refresh.insert(r.clone());
        v["refresh_token"] = json!(r);
    }
    v
}

fn bad(e: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
}

async fn token(
    State(s): State<S>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let mut st = s.lock().unwrap();
    let expected_resource = format!("{}/mcp", st.base);
    if f.get("resource") != Some(&expected_resource) {
        return bad("invalid_target");
    }
    match f["grant_type"].as_str() {
        "authorization_code" => {
            let Some((client, redirect, challenge)) = st.codes.remove(&f["code"]) else {
                return bad("invalid_grant");
            };
            let verifier = &f["code_verifier"];
            let calc = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if calc != challenge || f["redirect_uri"] != redirect || f["client_id"] != client {
                return bad("invalid_grant");
            }
            Json(issue(&mut st, true)).into_response()
        }
        "refresh_token" => {
            if !st.refresh.remove(&f["refresh_token"]) {
                return bad("invalid_grant");
            }
            st.refresh_grants += 1;
            Json(issue(&mut st, true)).into_response()
        }
        "client_credentials" => {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Basic "))
                .and_then(|b| STANDARD.decode(b).ok())
                .map(|b| String::from_utf8(b).unwrap());
            if auth.as_deref() != Some("svc:s3cret") {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "invalid_client"})),
                )
                    .into_response();
            }
            st.cc_grants += 1;
            Json(issue(&mut st, false)).into_response()
        }
        _ => bad("unsupported_grant_type"),
    }
}

async fn require_bearer(State(s): State<S>, req: Request, next: Next) -> Response {
    let tok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(String::from);
    let (ok, base) = {
        let st = s.lock().unwrap();
        (tok.is_some_and(|t| st.access.contains(&t)), st.base.clone())
    };
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                format!(r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp", scope="mcp""#),
            )],
        )
            .into_response();
    }
    next.run(req).await
}

async fn spawn_fake() -> (String, S) {
    let st: S = Default::default();
    let mcp = StreamableHttpService::new(
        || Ok(EchoServer),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let protected =
        Router::new()
            .nest_service("/mcp", mcp)
            .layer(axum::middleware::from_fn_with_state(
                st.clone(),
                require_bearer,
            ));
    let app = Router::new()
        .route("/.well-known/oauth-protected-resource/mcp", get(prm))
        .route("/.well-known/oauth-authorization-server", get(asm))
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(st.clone())
        .merge(protected);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    st.lock().unwrap().base = base.clone();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (base, st)
}

fn config(server: Value) -> Config {
    Config {
        servers: Config::parse(&json!({"mcpServers": {"remote": server}}).to_string()).unwrap(),
        sources: vec![],
    }
}

/// A "browser" that follows the authorization redirect to the loopback
/// callback.
fn headless_browser() -> Browser {
    Browser::Callback(Arc::new(|url: String| {
        tokio::spawn(async move {
            let r = reqwest::get(&url).await.expect("follow authorize redirect");
            assert!(r.status().is_success(), "callback returned {}", r.status());
        });
    }))
}

#[tokio::test]
async fn authorization_code_pkce_dcr_and_refresh() {
    mcpx::init_tls();
    let (base, st) = spawn_fake().await;
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let cfg = config(json!({"url": format!("{base}/mcp")}));
    let oauth = Arc::new(OAuth::new(tokens.clone()));

    // Not logged in: a clear instruction, not a hang.
    let pool = Pool::new(cfg.clone(), Connector::new(oauth.clone(), false));
    let err = match pool.get("remote").await {
        Ok(_) => panic!("must need login"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("mcpx login remote"), "{err:#}");

    let server = cfg.server("remote").unwrap();
    let v = oauth.login(&server, headless_browser()).await.unwrap();
    assert_eq!(v["status"], "authorized");
    assert_eq!(
        st.lock().unwrap().resources_seen,
        vec![format!("{base}/mcp")]
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&tokens).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let pool = Pool::new(cfg.clone(), Connector::new(oauth.clone(), false));
    let r = pool
        .call(
            "remote",
            "echo",
            [("message".to_string(), json!("secured"))]
                .into_iter()
                .collect(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r["content"][0]["text"], "secured");
    pool.shutdown().await;

    // Server revokes every access token: the next connect gets a 401 and
    // must recover via the refresh token without user interaction.
    st.lock().unwrap().access.clear();
    let pool = Pool::new(cfg.clone(), Connector::new(oauth.clone(), false));
    let tools = pool.tools(Some("remote")).await.unwrap();
    assert_eq!(tools["tools"][0]["name"], "echo");
    assert_eq!(st.lock().unwrap().refresh_grants, 1);
    pool.shutdown().await;

    let status = oauth.status(std::slice::from_ref(&server));
    assert_eq!(status[0]["state"], "valid");
    let raw = std::fs::read_to_string(&tokens).unwrap();
    assert!(
        !serde_json::to_string(&status).unwrap().contains("at-"),
        "status leaks token"
    );
    assert!(raw.contains("refresh_token"));

    // Second login reuses the dynamically registered client.
    oauth.login(&server, headless_browser()).await.unwrap();
    assert_eq!(st.lock().unwrap().clients.len(), 1);

    assert!(oauth.logout(&server).await.unwrap());
    assert_eq!(oauth.status(&[server])[0]["state"], "none");
}

#[tokio::test]
async fn client_credentials_grant() {
    mcpx::init_tls();
    let (base, st) = spawn_fake().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(json!({
        "url": format!("{base}/mcp"),
        "oauth": {"grant": "client_credentials", "client_id": "svc", "client_secret": "s3cret", "scopes": ["mcp"]}
    }));
    let oauth = Arc::new(OAuth::new(dir.path().join("tokens.json")));
    let pool = Pool::new(cfg.clone(), Connector::new(oauth.clone(), false));
    let r = pool
        .call(
            "remote",
            "echo",
            [("message".to_string(), json!("machine"))]
                .into_iter()
                .collect(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r["content"][0]["text"], "machine");
    assert_eq!(st.lock().unwrap().cc_grants, 1);
    pool.shutdown().await;

    // Revoked: a fresh client_credentials token is fetched transparently.
    st.lock().unwrap().access.clear();
    let pool = Pool::new(cfg, Connector::new(oauth, false));
    pool.tools(Some("remote")).await.unwrap();
    assert_eq!(st.lock().unwrap().cc_grants, 2);
    pool.shutdown().await;
}
