//! Command-line front end. JSON to stdout, errors as JSON on stderr with a
//! non-zero exit; `--pretty` for human-readable tables.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Map, Value, json};

use crate::client::Connector;
use crate::config::Config;
use crate::gateway::{self, DEFAULT_PORT, GatewayState};
use crate::oauth::{Browser, OAuth};
use crate::paths::Paths;
use crate::pool::{Filter, Pool};

#[derive(Parser)]
#[command(name = "mcpx", version, about = "MCP client CLI and local gateway")]
struct Cli {
    /// mcp.json to use (default: ./.mcp.json, then ~/.config/mcpx/mcp.json).
    #[arg(long, global = true, env = "MCPX_CONFIG")]
    config: Option<PathBuf>,
    /// Also load servers from ~/.claude.json, ~/.cursor/mcp.json and .vscode/mcp.json.
    #[arg(long, global = true)]
    import: bool,
    /// Human-readable tables instead of JSON.
    #[arg(long, global = true)]
    pretty: bool,
    /// Connect to servers directly even when a gateway is running.
    #[arg(long, global = true)]
    direct: bool,
    /// Per-request timeout in seconds.
    #[arg(long, global = true, default_value_t = 120)]
    timeout: u64,
    /// Log to stderr (and show stdio servers' stderr).
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List configured servers with connection status and capabilities.
    Servers,
    /// List tools (with inputSchema), for one server or all.
    Tools { server: Option<String> },
    /// Call a tool: `mcpx call <server>.<tool> [json|-] [--arg k=v]...`.
    Call {
        target: String,
        /// Arguments as a JSON object, or `-` to read it from stdin.
        json: Option<String>,
        /// One argument; the value is parsed as JSON when valid, else a string.
        #[arg(long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,
    },
    /// List resources.
    Resources { server: Option<String> },
    /// Read a resource.
    Read { server: String, uri: String },
    /// List prompts.
    Prompts { server: Option<String> },
    /// Get a prompt: `mcpx prompt <server>.<name> [json|-] [--arg k=v]...`.
    Prompt {
        target: String,
        json: Option<String>,
        #[arg(long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,
    },
    /// Authorize mcpx against an OAuth-protected server.
    Login {
        server: String,
        /// Print the authorization URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Forget stored tokens and client registration for a server.
    Logout { server: String },
    /// Token state.
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// Run the local gateway (REST + aggregated MCP endpoint at /mcp).
    Serve {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Only expose tools matching this glob over `server__tool` (repeatable).
        #[arg(long)]
        allow: Vec<String>,
        /// Hide and refuse tools matching this glob (repeatable; wins over --allow).
        #[arg(long)]
        deny: Vec<String>,
        /// Do not require the bearer token (loopback only either way).
        #[arg(long)]
        no_auth: bool,
    },
    /// Built-in demo MCP server on stdio (used by tests).
    #[command(hide = true)]
    EchoServer,
}

#[derive(Subcommand)]
enum AuthCmd {
    /// Show which servers have tokens and when they expire.
    Status,
}

/// Where data commands go: an in-process pool or a running gateway.
enum Backend {
    Local(Arc<Pool>),
    Remote {
        http: reqwest::Client,
        base: String,
        token: Option<String>,
    },
}

impl Backend {
    async fn get(&self, path: &str) -> Result<Value> {
        let Backend::Remote { http, base, token } = self else {
            unreachable!()
        };
        let mut r = http.get(format!("{base}{path}"));
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        remote_result(r.send().await?).await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let Backend::Remote { http, base, token } = self else {
            unreachable!()
        };
        let mut r = http.post(format!("{base}{path}")).json(&body);
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        remote_result(r.send().await?).await
    }
}

async fn remote_result(r: reqwest::Response) -> Result<Value> {
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = v["error"]["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("gateway returned HTTP {status}"));
        bail!("{msg}");
    }
    Ok(v)
}

fn query(server: &Option<String>) -> String {
    match server {
        Some(s) => format!(
            "?server={}",
            url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
        ),
        None => String::new(),
    }
}

/// A healthy gateway from `gateway.json`, if any.
async fn find_gateway(paths: &Paths) -> Option<GatewayState> {
    let st = GatewayState::read(paths)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .ok()?;
    let r = http
        .get(format!("{}/health", st.base()))
        .send()
        .await
        .ok()?;
    let v: Value = r.json().await.ok()?;
    (v["name"] == "mcpx").then_some(st)
}

/// Split `server.name`, preferring the longest configured server name.
fn split_target(target: &str, names: &[String]) -> Result<(String, String)> {
    if let Some(n) = names
        .iter()
        .filter(|n| {
            target.len() > n.len() + 1
                && target.starts_with(n.as_str())
                && target.as_bytes()[n.len()] == b'.'
        })
        .max_by_key(|n| n.len())
    {
        return Ok((n.clone(), target[n.len() + 1..].to_string()));
    }
    target
        .split_once('.')
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .ok_or_else(|| anyhow!("expected <server>.<name>, got '{target}'"))
}

/// Merge positional JSON (or `-` for stdin) with `--arg k=v` pairs.
pub fn build_args(json_arg: Option<&str>, pairs: &[String]) -> Result<Map<String, Value>> {
    let mut map = match json_arg {
        None => Map::new(),
        Some(s) => {
            let text = if s == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                s.to_string()
            };
            if text.trim().is_empty() {
                Map::new()
            } else {
                match serde_json::from_str::<Value>(&text)
                    .context("arguments must be a JSON object")?
                {
                    Value::Object(m) => m,
                    _ => bail!("arguments must be a JSON object"),
                }
            }
        }
    };
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| anyhow!("--arg expects KEY=VALUE, got '{p}'"))?;
        let v = serde_json::from_str(v).unwrap_or_else(|_| Value::String(v.to_string()));
        map.insert(k.to_string(), v);
    }
    Ok(map)
}

pub async fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter = if cli.verbose {
        "mcpx=debug,rmcp=info"
    } else {
        "mcpx=warn,rmcp=error"
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}", json!({"error": {"message": format!("{e:#}")}}));
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    if let Cmd::EchoServer = cli.cmd {
        crate::testserver::run_stdio().await?;
        return Ok(ExitCode::SUCCESS);
    }
    let paths = Paths::from_env();
    let mut config = Config::load(cli.config.as_deref(), &paths)?;
    if cli.import {
        config.import_others();
    }
    let oauth = Arc::new(OAuth::new(paths.tokens()));
    let timeout = Duration::from_secs(cli.timeout);
    let pretty = cli.pretty;

    // Commands that never go through a gateway.
    match &cli.cmd {
        Cmd::Login { server, no_browser } => {
            let s = config.server(server)?;
            let b = if *no_browser {
                Browser::Print
            } else {
                Browser::Open
            };
            let v = oauth.login(&s, b).await?;
            return emit(&v, pretty, Kind::Generic);
        }
        Cmd::Logout { server } => {
            let s = config.server(server)?;
            let had = oauth.logout(&s).await?;
            return emit(
                &json!({"server": server, "removed": had}),
                pretty,
                Kind::Generic,
            );
        }
        Cmd::Auth {
            cmd: AuthCmd::Status,
        } => {
            let servers: Vec<_> = config
                .names()
                .iter()
                .filter_map(|n| config.server(n).ok())
                .collect();
            return emit(&Value::Array(oauth.status(&servers)), pretty, Kind::Auth);
        }
        Cmd::Serve {
            port,
            allow,
            deny,
            no_auth,
        } => {
            let mut pool = Pool::new(config, Connector::new(oauth, cli.verbose));
            pool.filter = Filter::new(allow, deny)?;
            pool.call_timeout = timeout;
            gateway::serve_forever(Arc::new(pool), &paths, *port, !no_auth).await?;
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }

    let use_gateway = !cli.direct && cli.config.is_none() && !cli.import;
    let names = config.names();
    let backend = match use_gateway {
        true => match find_gateway(&paths).await {
            Some(st) => Backend::Remote {
                http: reqwest::Client::builder()
                    .timeout(timeout + Duration::from_secs(5))
                    .build()?,
                base: st.base(),
                token: st.token,
            },
            None => local(config, oauth, &cli, timeout),
        },
        false => local(config, oauth, &cli, timeout),
    };
    let result = dispatch(&backend, cli.cmd, &names, timeout, pretty).await;
    if let Backend::Local(pool) = &backend {
        pool.shutdown().await;
    }
    result
}

fn local(config: Config, oauth: Arc<OAuth>, cli: &Cli, timeout: Duration) -> Backend {
    let mut pool = Pool::new(config, Connector::new(oauth, cli.verbose));
    pool.call_timeout = timeout;
    Backend::Local(Arc::new(pool))
}

async fn dispatch(
    b: &Backend,
    cmd: Cmd,
    names: &[String],
    timeout: Duration,
    pretty: bool,
) -> Result<ExitCode> {
    match cmd {
        Cmd::Servers => {
            let v = match b {
                Backend::Local(p) => Value::Array(p.servers().await),
                r => r.get("/servers").await?,
            };
            emit(&v, pretty, Kind::Servers)
        }
        Cmd::Tools { server } => {
            let v = match b {
                Backend::Local(p) => p.tools(server.as_deref()).await?,
                r => r.get(&format!("/tools{}", query(&server))).await?,
            };
            list_out(v, "tools", pretty, Kind::Tools)
        }
        Cmd::Resources { server } => {
            let v = match b {
                Backend::Local(p) => p.resources(server.as_deref()).await?,
                r => r.get(&format!("/resources{}", query(&server))).await?,
            };
            list_out(v, "resources", pretty, Kind::Resources)
        }
        Cmd::Prompts { server } => {
            let v = match b {
                Backend::Local(p) => p.prompts(server.as_deref()).await?,
                r => r.get(&format!("/prompts{}", query(&server))).await?,
            };
            list_out(v, "prompts", pretty, Kind::Prompts)
        }
        Cmd::Call { target, json, args } => {
            let (server, tool) = split_target(&target, names)?;
            let args = build_args(json.as_deref(), &args)?;
            let v = match b {
                Backend::Local(p) => p.call(&server, &tool, args, Some(timeout)).await?,
                r => {
                    r.post(
                        "/call",
                        json!({"server": server, "tool": tool, "arguments": args, "timeout": timeout.as_secs()}),
                    )
                    .await?
                }
            };
            emit(&v, pretty, Kind::Call)?;
            Ok(if v["isError"] == json!(true) {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Read { server, uri } => {
            let v = match b {
                Backend::Local(p) => p.read(&server, &uri).await?,
                r => {
                    r.post("/read", json!({"server": server, "uri": uri}))
                        .await?
                }
            };
            emit(&v, pretty, Kind::Read)
        }
        Cmd::Prompt { target, json, args } => {
            let (server, name) = split_target(&target, names)?;
            let args = build_args(json.as_deref(), &args)?;
            let v = match b {
                Backend::Local(p) => p.prompt(&server, &name, args).await?,
                r => {
                    r.post(
                        "/prompt",
                        json!({"server": server, "name": name, "arguments": args}),
                    )
                    .await?
                }
            };
            emit(&v, pretty, Kind::Prompt)
        }
        _ => unreachable!("handled earlier"),
    }
}

/// Print the list under `key`; per-server errors go to stderr. Fails only
/// when every queried server failed.
fn list_out(v: Value, key: &str, pretty: bool, kind: Kind) -> Result<ExitCode> {
    let errors = v["errors"].as_array().cloned().unwrap_or_default();
    for e in &errors {
        eprintln!("{}", json!({"warning": e}));
    }
    let items = v[key].clone();
    emit(&items, pretty, kind)?;
    let empty = items.as_array().is_none_or(|a| a.is_empty());
    Ok(if empty && !errors.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[derive(Clone, Copy)]
enum Kind {
    Generic,
    Servers,
    Tools,
    Resources,
    Prompts,
    Call,
    Read,
    Prompt,
    Auth,
}

fn emit(v: &Value, pretty: bool, kind: Kind) -> Result<ExitCode> {
    if !pretty {
        let s = if std::io::stdout().is_terminal() {
            serde_json::to_string_pretty(v)?
        } else {
            serde_json::to_string(v)?
        };
        println!("{s}");
        return Ok(ExitCode::SUCCESS);
    }
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let first_line = |x: &Value| {
        let t = s(x);
        let l = t.lines().next().unwrap_or("").to_string();
        if l.chars().count() > 80 {
            format!("{}…", l.chars().take(79).collect::<String>())
        } else {
            l
        }
    };
    let arr = || v.as_array().cloned().unwrap_or_default();
    match kind {
        Kind::Servers => table(
            &["NAME", "TRANSPORT", "STATUS", "SERVER / ERROR"],
            arr().iter().map(|x| {
                let detail = if x["status"] == "connected" {
                    format!(
                        "{} {}",
                        s(&x["serverInfo"]["name"]),
                        s(&x["serverInfo"]["version"])
                    )
                } else {
                    s(&x["error"])
                };
                vec![s(&x["name"]), s(&x["transport"]), s(&x["status"]), detail]
            }),
        ),
        Kind::Tools => table(
            &["SERVER", "TOOL", "DESCRIPTION"],
            arr().iter().map(|x| {
                vec![
                    s(&x["server"]),
                    s(&x["name"]),
                    first_line(&x["description"]),
                ]
            }),
        ),
        Kind::Resources => table(
            &["SERVER", "URI", "NAME", "MIME"],
            arr().iter().map(|x| {
                vec![
                    s(&x["server"]),
                    s(&x["uri"]),
                    s(&x["name"]),
                    s(&x["mimeType"]),
                ]
            }),
        ),
        Kind::Prompts => table(
            &["SERVER", "PROMPT", "DESCRIPTION"],
            arr().iter().map(|x| {
                vec![
                    s(&x["server"]),
                    s(&x["name"]),
                    first_line(&x["description"]),
                ]
            }),
        ),
        Kind::Auth => table(
            &["SERVER", "STATE", "GRANT", "EXPIRES"],
            arr().iter().map(|x| {
                let exp = x["expiresAt"]
                    .as_u64()
                    .map(|t| {
                        let now = crate::oauth::now_secs();
                        if t > now {
                            format!("in {}m", (t - now) / 60)
                        } else {
                            "past".into()
                        }
                    })
                    .unwrap_or_default();
                vec![s(&x["server"]), s(&x["state"]), s(&x["grant"]), exp]
            }),
        ),
        Kind::Call => {
            for c in v["content"].as_array().into_iter().flatten() {
                match c["type"].as_str() {
                    Some("text") => println!("{}", s(&c["text"])),
                    _ => println!("{}", serde_json::to_string_pretty(c)?),
                }
            }
            if let Some(sc) = v.get("structuredContent")
                && v["content"].as_array().is_none_or(|a| a.is_empty())
            {
                println!("{}", serde_json::to_string_pretty(sc)?);
            }
            if v["isError"] == json!(true) {
                eprintln!("(tool reported an error)");
            }
        }
        Kind::Read => {
            for c in v["contents"].as_array().into_iter().flatten() {
                match c.get("text") {
                    Some(t) => println!("{}", s(t)),
                    None => println!("{}", serde_json::to_string_pretty(c)?),
                }
            }
        }
        Kind::Prompt => {
            for m in v["messages"].as_array().into_iter().flatten() {
                let content = &m["content"];
                let text = if content["type"] == "text" {
                    s(&content["text"])
                } else {
                    content.to_string()
                };
                println!("{}: {}", s(&m["role"]), text);
            }
        }
        Kind::Generic => println!("{}", serde_json::to_string_pretty(v)?),
    }
    Ok(ExitCode::SUCCESS)
}

fn table(headers: &[&str], rows: impl Iterator<Item = Vec<String>>) {
    let rows: Vec<Vec<String>> = rows.collect();
    let mut w: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let n = cells.len();
        let out: Vec<String> = cells
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                if i + 1 == n {
                    c
                } else {
                    format!("{c:<width$}", width = w[i])
                }
            })
            .collect();
        println!("{}", out.join("  ").trim_end());
    };
    line(headers.iter().map(|h| h.to_string()).collect());
    for r in rows {
        line(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_merge_json_and_pairs() {
        let m = build_args(
            Some(r#"{"a":1,"b":"x"}"#),
            &["b=2".into(), "c=hello".into(), "d={\"k\":true}".into()],
        )
        .unwrap();
        assert_eq!(m["a"], json!(1));
        assert_eq!(m["b"], json!(2));
        assert_eq!(m["c"], json!("hello"));
        assert_eq!(m["d"], json!({"k": true}));
        assert!(build_args(Some("[1]"), &[]).is_err());
        assert!(build_args(None, &["novalue".into()]).is_err());
    }

    #[test]
    fn target_prefers_known_server_names() {
        let names = vec!["a".to_string(), "a.b".to_string()];
        assert_eq!(
            split_target("a.b.tool", &names).unwrap(),
            ("a.b".into(), "tool".into())
        );
        assert_eq!(
            split_target("a.x.y", &names).unwrap(),
            ("a".into(), "x.y".into())
        );
        assert_eq!(
            split_target("z.t", &names).unwrap(),
            ("z".into(), "t".into())
        );
        assert!(split_target("nodot", &names).is_err());
    }
}
