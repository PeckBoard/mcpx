//! OAuth 2.1 for remote MCP servers, per the MCP Authorization spec:
//! `WWW-Authenticate` → RFC 9728 protected-resource metadata → RFC 8414 /
//! OIDC authorization-server metadata → RFC 7591 dynamic client
//! registration → authorization code + PKCE (S256) on a loopback redirect,
//! or `client_credentials`. Every token request carries the RFC 8707
//! `resource` parameter. Tokens live in `tokens.json` (0600), keyed by the
//! server URL, and are never printed.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;

use crate::config::Server;
use crate::paths::write_private;

/// Refresh this many seconds before the server-declared expiry.
const EXPIRY_SKEW: u64 = 30;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientReg {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Registered via RFC 7591 (vs taken from config).
    #[serde(default)]
    pub dynamic: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Token {
    fn expired(&self) -> bool {
        self.expires_at
            .is_some_and(|t| now_secs() + EXPIRY_SKEW >= t)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AsMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_server: Option<AsMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientReg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Token>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    servers: BTreeMap<String, Entry>,
}

/// What discovery learned about a protected server.
#[derive(Debug, Clone)]
pub struct Discovery {
    pub resource: String,
    pub auth_server: AsMeta,
    pub scope: Option<String>,
}

/// The server needs an interactive `mcpx login`.
#[derive(Debug)]
pub struct NeedsLogin(pub String);

impl std::fmt::Display for NeedsLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "server '{0}' requires authorization: run `mcpx login {0}`",
            self.0
        )
    }
}
impl std::error::Error for NeedsLogin {}

/// How `login` shows the authorization URL to the user.
#[derive(Clone)]
pub enum Browser {
    /// Try `open`/`xdg-open`; fall back to printing when headless.
    Open,
    /// Only print the URL (`--no-browser`).
    Print,
    /// Hand the URL to a callback (tests drive the flow with it).
    Callback(Arc<dyn Fn(String) + Send + Sync>),
}

pub struct OAuth {
    http: reqwest::Client,
    path: PathBuf,
    lock: Mutex<()>,
}

impl OAuth {
    pub fn new(path: PathBuf) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("http client"),
            path,
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> Store {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save(&self, s: &Store) -> Result<()> {
        write_private(&self.path, serde_json::to_string_pretty(s)?.as_bytes())
    }

    fn entry(&self, url: &str) -> Entry {
        self.load().servers.get(url).cloned().unwrap_or_default()
    }

    fn put(&self, url: &str, e: Entry) -> Result<()> {
        let mut s = self.load();
        s.servers.insert(url.to_string(), e);
        self.save(&s)
    }

    /// The bearer token to send, if any: a still-valid stored token, a
    /// refreshed one, or a fresh `client_credentials` token.
    pub async fn access_token(&self, server: &Server) -> Result<Option<String>> {
        let Some(url) = server.url() else {
            return Ok(None);
        };
        if server.has_static_auth() {
            return Ok(None);
        }
        let _g = self.lock.lock().await;
        let e = self.entry(url);
        if let Some(t) = &e.token {
            if !t.expired() {
                return Ok(Some(t.access_token.clone()));
            }
            if t.refresh_token.is_some() {
                match self.refresh(url, e.clone()).await {
                    Ok(tok) => return Ok(Some(tok)),
                    Err(err) => tracing::debug!("refresh for {url} failed: {err:#}"),
                }
            }
        }
        if server.oauth.is_client_credentials() {
            return self.client_credentials(server, None).await.map(Some);
        }
        Ok(None)
    }

    /// React to a 401: refresh, or re-run `client_credentials`; otherwise
    /// the user must log in interactively.
    pub async fn on_unauthorized(
        &self,
        server: &Server,
        challenge: Option<&str>,
    ) -> Result<String> {
        let url = server.url().ok_or_else(|| anyhow!("not an http server"))?;
        let _g = self.lock.lock().await;
        let e = self.entry(url);
        if e.token.as_ref().is_some_and(|t| t.refresh_token.is_some()) {
            match self.refresh(url, e).await {
                Ok(t) => return Ok(t),
                Err(err) => tracing::debug!("refresh for {url} failed: {err:#}"),
            }
        }
        if server.oauth.is_client_credentials() {
            return self.client_credentials(server, challenge).await;
        }
        Err(NeedsLogin(server.name.clone()).into())
    }

    async fn refresh(&self, url: &str, mut e: Entry) -> Result<String> {
        let (Some(asm), Some(client), Some(tok)) = (&e.auth_server, &e.client, &e.token) else {
            bail!("no stored client/token to refresh");
        };
        let rt = tok
            .refresh_token
            .clone()
            .ok_or_else(|| anyhow!("no refresh token"))?;
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", rt.clone()),
        ];
        if let Some(r) = &e.resource {
            form.push(("resource", r.clone()));
        }
        let mut new = self.token_request(asm, client, form).await?;
        if new.refresh_token.is_none() {
            new.refresh_token = Some(rt);
        }
        let access = new.access_token.clone();
        e.token = Some(new);
        self.put(url, e)?;
        Ok(access)
    }

    async fn client_credentials(&self, server: &Server, challenge: Option<&str>) -> Result<String> {
        let url = server.url().unwrap_or_default();
        let mut e = self.entry(url);
        let disc = self.discover(url, challenge).await?;
        let client = match (&server.oauth.client_id, &e.client) {
            (Some(id), _) => ClientReg {
                client_id: id.clone(),
                client_secret: server.oauth.client_secret.clone(),
                redirect_uri: None,
                dynamic: false,
            },
            (None, Some(c))
                if c.client_secret.is_some()
                    && e.auth_server.as_ref() == Some(&disc.auth_server) =>
            {
                c.clone()
            }
            (None, _) => {
                self.register(&disc.auth_server, None, &["client_credentials"])
                    .await?
            }
        };
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("resource", disc.resource.clone()),
        ];
        if let Some(s) = self.scope(server, &disc) {
            form.push(("scope", s));
        }
        let tok = self.token_request(&disc.auth_server, &client, form).await?;
        let access = tok.access_token.clone();
        e.auth_server = Some(disc.auth_server);
        e.resource = Some(disc.resource);
        e.client = Some(client);
        e.token = Some(tok);
        e.grant = Some("client_credentials".into());
        self.put(url, e)?;
        Ok(access)
    }

    fn scope(&self, server: &Server, disc: &Discovery) -> Option<String> {
        disc.scope
            .clone()
            .or_else(|| server.oauth.scopes.as_ref().map(|s| s.join(" ")))
            .filter(|s| !s.is_empty())
    }

    /// Interactive authorization-code login (or `client_credentials` when
    /// configured). Stores the resulting token.
    pub async fn login(&self, server: &Server, browser: Browser) -> Result<Value> {
        let url = server
            .url()
            .ok_or_else(|| anyhow!("server '{}' is stdio; nothing to log in to", server.name))?
            .to_string();
        if server.oauth.is_client_credentials() {
            let _g = self.lock.lock().await;
            self.client_credentials(server, None).await?;
            return Ok(
                json!({"server": server.name, "status": "authorized", "grant": "client_credentials"}),
            );
        }
        let (_, challenge) = probe(&self.http, &url, None).await.unwrap_or((0, None));
        let disc = self.discover(&url, challenge.as_deref()).await?;
        let auth_ep = disc
            .auth_server
            .authorization_endpoint
            .clone()
            .ok_or_else(|| anyhow!("authorization server has no authorization_endpoint"))?;
        let mut e = self.entry(&url);

        // Reuse the previously registered loopback port when possible so a
        // dynamically registered client's redirect_uri stays valid.
        let prev = e
            .client
            .as_ref()
            .filter(|_| e.auth_server.as_ref() == Some(&disc.auth_server))
            .cloned();
        let prev_port = prev
            .as_ref()
            .and_then(|c| c.redirect_uri.as_deref())
            .and_then(|u| Url::parse(u).ok())
            .and_then(|u| u.port());
        let listener = match prev_port {
            Some(p) => match tokio::net::TcpListener::bind(("127.0.0.1", p)).await {
                Ok(l) => l,
                Err(_) => tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?,
            },
            None => tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?,
        };
        let redirect = format!(
            "http://127.0.0.1:{}/callback",
            listener.local_addr()?.port()
        );

        let client = match (&server.oauth.client_id, prev) {
            (Some(id), _) => ClientReg {
                client_id: id.clone(),
                client_secret: server.oauth.client_secret.clone(),
                redirect_uri: Some(redirect.clone()),
                dynamic: false,
            },
            (None, Some(c)) if c.redirect_uri.as_deref() == Some(redirect.as_str()) => c,
            (None, _) => {
                self.register(
                    &disc.auth_server,
                    Some(&redirect),
                    &["authorization_code", "refresh_token"],
                )
                .await?
            }
        };

        let verifier = random_token(32);
        let challenge_s256 = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = random_token(16);
        let mut auth_url = Url::parse(&auth_ep).context("authorization_endpoint")?;
        {
            let mut q = auth_url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &client.client_id)
                .append_pair("redirect_uri", &redirect)
                .append_pair("code_challenge", &challenge_s256)
                .append_pair("code_challenge_method", "S256")
                .append_pair("state", &state)
                .append_pair("resource", &disc.resource);
            if let Some(s) = self.scope(server, &disc) {
                q.append_pair("scope", &s);
            }
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<HashMap<String, String>>();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let app = axum::Router::new().route(
            "/callback",
            axum::routing::get(
                move |q: axum::extract::Query<HashMap<String, String>>| {
                    let tx = tx.clone();
                    async move {
                        if let Some(tx) = tx.lock().unwrap().take() {
                            let _ = tx.send(q.0);
                        }
                        axum::response::Html(
                            "<html><body><h3>mcpx: authorization complete.</h3>You can close this window.</body></html>",
                        )
                    }
                },
            ),
        );
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let shown = auth_url.to_string();
        match &browser {
            Browser::Callback(f) => f(shown),
            Browser::Print => eprintln!("Open this URL to authorize mcpx:\n\n  {shown}\n"),
            Browser::Open => {
                eprintln!(
                    "Opening browser to authorize mcpx. If it does not open, visit:\n\n  {shown}\n"
                );
                open_browser(&shown);
            }
        }

        let params = tokio::time::timeout(LOGIN_TIMEOUT, rx).await;
        srv.abort();
        let params = params
            .map_err(|_| anyhow!("timed out waiting for the authorization redirect"))?
            .map_err(|_| anyhow!("callback server closed"))?;
        if let Some(err) = params.get("error") {
            bail!(
                "authorization denied: {err} {}",
                params.get("error_description").cloned().unwrap_or_default()
            );
        }
        if params.get("state") != Some(&state) {
            bail!("authorization response state mismatch");
        }
        let code = params
            .get("code")
            .ok_or_else(|| anyhow!("authorization response has no code"))?;
        let form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.clone()),
            ("redirect_uri", redirect.clone()),
            ("code_verifier", verifier),
            ("resource", disc.resource.clone()),
        ];
        let tok = self.token_request(&disc.auth_server, &client, form).await?;
        let _g = self.lock.lock().await;
        e.auth_server = Some(disc.auth_server);
        e.resource = Some(disc.resource);
        e.client = Some(client);
        e.token = Some(tok);
        e.grant = Some("authorization_code".into());
        self.put(&url, e)?;
        Ok(json!({"server": server.name, "status": "authorized", "grant": "authorization_code"}))
    }

    pub async fn logout(&self, server: &Server) -> Result<bool> {
        let url = server
            .url()
            .ok_or_else(|| anyhow!("server '{}' is stdio", server.name))?;
        let _g = self.lock.lock().await;
        let mut s = self.load();
        let had = s.servers.remove(url).is_some();
        self.save(&s)?;
        Ok(had)
    }

    /// Token state per server, without secrets.
    pub fn status(&self, servers: &[Server]) -> Vec<Value> {
        let s = self.load();
        servers
            .iter()
            .filter_map(|srv| {
                let url = srv.url()?;
                let e = s.servers.get(url);
                let tok = e.and_then(|e| e.token.as_ref());
                let state = if srv.has_static_auth() {
                    "static-header"
                } else {
                    match tok {
                        None => "none",
                        Some(t) if t.expired() && t.refresh_token.is_some() => {
                            "expired-refreshable"
                        }
                        Some(t) if t.expired() => "expired",
                        Some(_) => "valid",
                    }
                };
                Some(json!({
                    "server": srv.name,
                    "url": url,
                    "state": state,
                    "grant": e.and_then(|e| e.grant.clone()),
                    "expiresAt": tok.and_then(|t| t.expires_at),
                    "hasRefreshToken": tok.is_some_and(|t| t.refresh_token.is_some()),
                    "scope": tok.and_then(|t| t.scope.clone()),
                    "clientId": e.and_then(|e| e.client.as_ref().map(|c| c.client_id.clone())),
                    "issuer": e.and_then(|e| e.auth_server.as_ref().and_then(|a| a.issuer.clone())),
                }))
            })
            .collect()
    }

    /// RFC 9728 → RFC 8414/OIDC discovery for `server_url`.
    pub async fn discover(&self, server_url: &str, challenge: Option<&str>) -> Result<Discovery> {
        let su = Url::parse(server_url).context("server url")?;
        let params = challenge.map(parse_www_authenticate).unwrap_or_default();
        let mut prm_urls = Vec::new();
        if let Some(u) = params.get("resource_metadata") {
            prm_urls.push(u.clone());
        }
        let origin = su.origin().ascii_serialization();
        let path = su.path().trim_end_matches('/');
        if !path.is_empty() {
            prm_urls.push(format!(
                "{origin}/.well-known/oauth-protected-resource{path}"
            ));
        }
        prm_urls.push(format!("{origin}/.well-known/oauth-protected-resource"));

        let mut prm: Option<Value> = None;
        for u in &prm_urls {
            if let Some(v) = self.get_json(u).await {
                prm = Some(v);
                break;
            }
        }
        let resource = prm
            .as_ref()
            .and_then(|p| p.get("resource"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| canonical_resource(&su));
        let issuer = prm
            .as_ref()
            .and_then(|p| p.get("authorization_servers"))
            .and_then(|a| a.get(0))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| origin.clone());

        let iu = Url::parse(&issuer).context("authorization server url")?;
        let io = iu.origin().ascii_serialization();
        let ip = iu.path().trim_end_matches('/');
        let as_urls = if ip.is_empty() {
            vec![
                format!("{io}/.well-known/oauth-authorization-server"),
                format!("{io}/.well-known/openid-configuration"),
            ]
        } else {
            vec![
                format!("{io}/.well-known/oauth-authorization-server{ip}"),
                format!("{io}/.well-known/openid-configuration{ip}"),
                format!("{io}{ip}/.well-known/openid-configuration"),
            ]
        };
        let mut meta: Option<AsMeta> = None;
        for u in &as_urls {
            if let Some(v) = self.get_json(u).await
                && let Ok(m) = serde_json::from_value::<AsMeta>(v)
            {
                meta = Some(m);
                break;
            }
        }
        // 2025-03-26 fallback: default endpoints on the server's origin.
        let auth_server = meta.unwrap_or_else(|| AsMeta {
            issuer: Some(issuer.clone()),
            authorization_endpoint: Some(format!("{io}/authorize")),
            token_endpoint: format!("{io}/token"),
            registration_endpoint: Some(format!("{io}/register")),
            token_endpoint_auth_methods_supported: None,
        });
        let scope = params.get("scope").cloned().or_else(|| {
            prm.as_ref()
                .and_then(|p| p.get("scopes_supported"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
        });
        Ok(Discovery {
            resource,
            auth_server,
            scope,
        })
    }

    async fn get_json(&self, url: &str) -> Option<Value> {
        let r = self
            .http
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !r.status().is_success() {
            return None;
        }
        r.json().await.ok()
    }

    /// RFC 7591 dynamic client registration.
    async fn register(
        &self,
        asm: &AsMeta,
        redirect: Option<&str>,
        grants: &[&str],
    ) -> Result<ClientReg> {
        let ep = asm.registration_endpoint.as_deref().ok_or_else(|| {
            anyhow!("authorization server does not support dynamic client registration; set oauth.client_id in mcp.json")
        })?;
        let confidential = grants.contains(&"client_credentials");
        let mut body = json!({
            "client_name": "mcpx",
            "grant_types": grants,
            "token_endpoint_auth_method": if confidential { "client_secret_basic" } else { "none" },
        });
        if let Some(r) = redirect {
            body["redirect_uris"] = json!([r]);
            body["response_types"] = json!(["code"]);
        }
        let r = self
            .http
            .post(ep)
            .json(&body)
            .send()
            .await
            .context("client registration")?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("client registration failed ({status}): {}", oauth_error(&v));
        }
        Ok(ClientReg {
            client_id: v
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("registration response has no client_id"))?
                .to_string(),
            client_secret: v
                .get("client_secret")
                .and_then(Value::as_str)
                .map(str::to_string),
            redirect_uri: redirect.map(str::to_string),
            dynamic: true,
        })
    }

    async fn token_request(
        &self,
        asm: &AsMeta,
        client: &ClientReg,
        mut form: Vec<(&str, String)>,
    ) -> Result<Token> {
        let mut req = self
            .http
            .post(&asm.token_endpoint)
            .header("Accept", "application/json");
        match &client.client_secret {
            Some(secret) => {
                let methods = asm.token_endpoint_auth_methods_supported.as_deref();
                let post_only = methods.is_some_and(|m| {
                    m.iter().any(|x| x == "client_secret_post")
                        && !m.iter().any(|x| x == "client_secret_basic")
                });
                if post_only {
                    form.push(("client_id", client.client_id.clone()));
                    form.push(("client_secret", secret.clone()));
                } else {
                    req = req.basic_auth(form_encode(&client.client_id), Some(form_encode(secret)));
                }
            }
            None => form.push(("client_id", client.client_id.clone())),
        }
        let r = req.form(&form).send().await.context("token request")?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("token request failed ({status}): {}", oauth_error(&v));
        }
        let access_token = v
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("token response has no access_token"))?
            .to_string();
        Ok(Token {
            access_token,
            refresh_token: v
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_string),
            expires_at: v
                .get("expires_in")
                .and_then(Value::as_u64)
                .map(|s| now_secs() + s),
            scope: v.get("scope").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// POST a bare `initialize` to `url` and report the status and any
/// `WWW-Authenticate` challenge. Used to explain connect failures.
pub async fn probe(
    http: &reqwest::Client,
    url: &str,
    token: Option<&str>,
) -> Result<(u16, Option<String>)> {
    let body = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "mcpx", "version": env!("CARGO_PKG_VERSION")}}
    });
    let mut req = http
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .timeout(Duration::from_secs(15))
        .json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let r = req.send().await?;
    let challenge = r
        .headers()
        .get("www-authenticate")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    Ok((r.status().as_u16(), challenge))
}

/// Parameters of a `Bearer` challenge (`realm`, `scope`, `resource_metadata`, …).
pub fn parse_www_authenticate(h: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let s = h.trim();
    let s = s
        .strip_prefix("Bearer")
        .or_else(|| s.strip_prefix("bearer"))
        .unwrap_or(s);
    let mut rest = s.trim_start();
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq]
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        rest = rest[eq + 1..].trim_start();
        let val;
        if let Some(r) = rest.strip_prefix('"') {
            let mut v = String::new();
            let mut chars = r.char_indices();
            let mut end = r.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, n)) = chars.next() {
                            v.push(n);
                        }
                    }
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    _ => v.push(c),
                }
            }
            val = v;
            rest = &r[end.min(r.len())..];
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            val = rest[..end].trim().to_string();
            rest = &rest[end..];
        }
        rest = rest.trim_start().trim_start_matches(',').trim_start();
        if !key.is_empty() {
            out.insert(key, val);
        }
    }
    out
}

/// RFC 8707 canonical resource URI: no fragment, no trailing slash.
fn canonical_resource(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    u.set_query(None);
    u.to_string().trim_end_matches('/').to_string()
}

fn oauth_error(v: &Value) -> String {
    match (v.get("error"), v.get("error_description")) {
        (Some(e), Some(d)) => format!(
            "{} ({})",
            e.as_str().unwrap_or(""),
            d.as_str().unwrap_or("")
        ),
        (Some(e), None) => e.as_str().unwrap_or("").to_string(),
        _ => "unexpected response".to_string(),
    }
}

/// RFC 6749 §2.3.1: client credentials in Basic auth are form-urlencoded.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn random_token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn open_browser(url: &str) {
    let headless = cfg!(target_os = "linux")
        && std::env::var_os("DISPLAY").is_none()
        && std::env::var_os("WAYLAND_DISPLAY").is_none();
    if headless {
        return;
    }
    let mut cmd = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(windows) {
        // Not `cmd /C start`: cmd mangles the `&` in query strings.
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else {
        std::process::Command::new("xdg-open")
    };
    let _ = cmd
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let p = parse_www_authenticate(
            r#"Bearer realm="mcp", resource_metadata="https://a.example/.well-known/oauth-protected-resource/mcp", scope="read write", error=invalid_token"#,
        );
        assert_eq!(
            p["resource_metadata"],
            "https://a.example/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(p["scope"], "read write");
        assert_eq!(p["error"], "invalid_token");
        assert_eq!(p["realm"], "mcp");
    }

    #[test]
    fn canonical_resource_strips_slash_and_fragment() {
        let u = Url::parse("https://a.example/mcp/#x").unwrap();
        assert_eq!(canonical_resource(&u), "https://a.example/mcp");
    }
}
