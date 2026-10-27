//! mcp.json parsing: the `mcpServers` map shared by Claude, Cursor and
//! VS Code (`servers`), plus `${VAR}` expansion and `--import`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::paths::{Paths, user_home};

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct OAuthConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// `authorization_code` (default) or `client_credentials`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

impl OAuthConfig {
    pub fn is_client_credentials(&self) -> bool {
        self.grant.as_deref() == Some("client_credentials")
    }
}

/// One entry of `mcpServers` as written on disk (unexpanded).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct RawServer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// mcpx spelling: `http` | `sse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Claude / Cursor / VS Code spelling: `stdio` | `http` | `sse`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Stdio {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        cwd: Option<PathBuf>,
    },
    Http {
        url: String,
        headers: BTreeMap<String, String>,
        sse: bool,
    },
}

/// A server entry with `${VAR}` references expanded.
#[derive(Debug, Clone, PartialEq)]
pub struct Server {
    pub name: String,
    pub transport: Transport,
    pub oauth: OAuthConfig,
}

impl Server {
    pub fn is_stdio(&self) -> bool {
        matches!(self.transport, Transport::Stdio { .. })
    }
    pub fn url(&self) -> Option<&str> {
        match &self.transport {
            Transport::Http { url, .. } => Some(url),
            _ => None,
        }
    }
    pub fn kind(&self) -> &'static str {
        match &self.transport {
            Transport::Stdio { .. } => "stdio",
            Transport::Http { sse: true, .. } => "sse",
            Transport::Http { .. } => "http",
        }
    }
    /// Command line or URL, for display.
    pub fn target(&self) -> String {
        match &self.transport {
            Transport::Stdio { command, args, .. } => std::iter::once(command.as_str())
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
            Transport::Http { url, .. } => url.clone(),
        }
    }
    /// A static `Authorization` header in the config disables OAuth.
    pub fn has_static_auth(&self) -> bool {
        match &self.transport {
            Transport::Http { headers, .. } => headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("authorization")),
            _ => false,
        }
    }
}

impl RawServer {
    pub fn resolve(&self, name: &str) -> Result<Server> {
        let kind = self
            .kind
            .as_deref()
            .or(self.transport.as_deref())
            .map(str::to_ascii_lowercase);
        let x = |s: &str| expand(s).with_context(|| format!("server '{name}'"));
        let transport = match (&self.command, &self.url) {
            (Some(cmd), _) if kind.as_deref().is_none_or(|k| k == "stdio") => Transport::Stdio {
                command: x(cmd)?,
                args: self.args.iter().map(|a| x(a)).collect::<Result<_>>()?,
                env: self
                    .env
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), x(v)?)))
                    .collect::<Result<_>>()?,
                cwd: self.cwd.as_deref().map(x).transpose()?.map(PathBuf::from),
            },
            (_, Some(url)) => {
                let sse = match kind.as_deref() {
                    None
                    | Some("http")
                    | Some("streamable-http")
                    | Some("streamablehttp")
                    | Some("streamable_http") => false,
                    Some("sse") => true,
                    Some(other) => bail!("server '{name}': unknown transport type '{other}'"),
                };
                Transport::Http {
                    url: x(url)?,
                    headers: self
                        .headers
                        .iter()
                        .map(|(k, v)| Ok((k.clone(), x(v)?)))
                        .collect::<Result<_>>()?,
                    sse,
                }
            }
            _ => bail!("server '{name}': needs either `command` (stdio) or `url` (http/sse)"),
        };
        let oauth = match &self.oauth {
            None => OAuthConfig::default(),
            Some(o) => OAuthConfig {
                client_id: o.client_id.as_deref().map(x).transpose()?,
                client_secret: o.client_secret.as_deref().map(x).transpose()?,
                scopes: o
                    .scopes
                    .as_ref()
                    .map(|s| s.iter().map(|v| x(v)).collect::<Result<_>>())
                    .transpose()?,
                grant: o.grant.clone(),
            },
        };
        Ok(Server {
            name: name.to_string(),
            transport,
            oauth,
        })
    }
}

/// Expand `${VAR}` and `${VAR:-default}`. A missing variable without a
/// default is an error (silently sending an empty token is worse). On
/// Windows `${HOME}` falls back to `%USERPROFILE%` so shared configs work.
pub fn expand(s: &str) -> Result<String> {
    expand_with(s, |k| {
        std::env::var(k).ok().or_else(|| {
            (cfg!(windows) && k == "HOME")
                .then(|| std::env::var("USERPROFILE").ok())
                .flatten()
        })
    })
}

pub fn expand_with(s: &str, get: impl Fn(&str) -> Option<String>) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unterminated ${{ in '{s}'"))?;
        let expr = &after[..end];
        let (var, default) = match expr.split_once(":-") {
            Some((v, d)) => (v, Some(d)),
            None => (expr, None),
        };
        match (get(var), default) {
            (Some(v), _) if !v.is_empty() || default.is_none() => out.push_str(&v),
            (_, Some(d)) => out.push_str(d),
            (None, None) => bail!("environment variable '{var}' is not set"),
            (Some(_), None) => unreachable!(),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub servers: BTreeMap<String, RawServer>,
    /// Files the servers came from, for diagnostics.
    pub sources: Vec<PathBuf>,
}

impl Config {
    /// Parse one mcp.json document (`mcpServers` or VS Code's `servers`).
    pub fn parse(text: &str) -> Result<BTreeMap<String, RawServer>> {
        let v: serde_json::Value = serde_json::from_str(text).context("invalid JSON")?;
        let map = v
            .get("mcpServers")
            .or_else(|| v.get("servers"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        serde_json::from_value(map).context("invalid mcpServers entry")
    }

    pub fn load_file(path: &Path) -> Result<BTreeMap<String, RawServer>> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parse {}", path.display()))
    }

    /// `--config`, else `./.mcp.json`, else `<home>/mcp.json`. A missing
    /// default file yields an empty config, not an error.
    pub fn load(explicit: Option<&Path>, paths: &Paths) -> Result<Self> {
        let candidates: Vec<PathBuf> = match explicit {
            Some(p) => vec![p.to_path_buf()],
            None => vec![PathBuf::from(".mcp.json"), paths.config()],
        };
        for p in &candidates {
            if explicit.is_some() || p.exists() {
                let servers = Self::load_file(p)?;
                return Ok(Self {
                    servers,
                    sources: vec![p.clone()],
                });
            }
        }
        Ok(Self::default())
    }

    /// Merge servers from other clients' config files. Entries already
    /// present win; disabled entries are skipped.
    pub fn import_others(&mut self) {
        let home = user_home();
        let mut found: Vec<(PathBuf, BTreeMap<String, RawServer>)> = Vec::new();
        let claude = home.join(".claude.json");
        if let Ok(text) = std::fs::read_to_string(&claude)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        {
            let mut m = BTreeMap::new();
            if let Some(s) = v.get("mcpServers")
                && let Ok(s) = serde_json::from_value::<BTreeMap<String, RawServer>>(s.clone())
            {
                m.extend(s);
            }
            if let Ok(cwd) = std::env::current_dir()
                && let Some(s) = v
                    .get("projects")
                    .and_then(|p| p.get(cwd.to_string_lossy().as_ref()))
                    .and_then(|p| p.get("mcpServers"))
                && let Ok(s) = serde_json::from_value::<BTreeMap<String, RawServer>>(s.clone())
            {
                m.extend(s);
            }
            found.push((claude, m));
        }
        for p in [
            home.join(".cursor").join("mcp.json"),
            PathBuf::from(".cursor").join("mcp.json"),
            PathBuf::from(".vscode").join("mcp.json"),
        ] {
            if let Ok(m) = Self::load_file(&p) {
                found.push((p, m));
            }
        }
        for (path, servers) in found {
            let mut used = false;
            for (name, s) in servers {
                if s.disabled == Some(true) || self.servers.contains_key(&name) {
                    continue;
                }
                self.servers.insert(name, s);
                used = true;
            }
            if used {
                self.sources.push(path);
            }
        }
    }

    pub fn server(&self, name: &str) -> Result<Server> {
        let raw = self.servers.get(name).ok_or_else(|| {
            anyhow!(
                "unknown server '{name}' (known: {})",
                self.servers.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;
        raw.resolve(name)
    }

    pub fn names(&self) -> Vec<String> {
        self.servers
            .iter()
            .filter(|(_, s)| s.disabled != Some(true))
            .map(|(n, _)| n.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stdio_http_and_vscode_shapes() {
        let m = Config::parse(
            r#"{"mcpServers":{
                "fs":{"command":"npx","args":["-y","fs-server"],"env":{"A":"1"}},
                "remote":{"url":"https://x.example/mcp","headers":{"X-K":"v"}},
                "legacy":{"type":"sse","url":"https://x.example/sse"},
                "cc":{"url":"https://x.example/mcp","oauth":{"grant":"client_credentials","client_id":"c"}}
            }}"#,
        )
        .unwrap();
        let fs = m["fs"].resolve("fs").unwrap();
        assert_eq!(fs.kind(), "stdio");
        assert_eq!(fs.target(), "npx -y fs-server");
        assert_eq!(m["remote"].resolve("remote").unwrap().kind(), "http");
        assert_eq!(m["legacy"].resolve("legacy").unwrap().kind(), "sse");
        assert!(m["cc"].resolve("cc").unwrap().oauth.is_client_credentials());

        let vs = Config::parse(r#"{"servers":{"a":{"type":"stdio","command":"x"}}}"#).unwrap();
        assert_eq!(vs["a"].resolve("a").unwrap().kind(), "stdio");

        let bad = Config::parse(r#"{"mcpServers":{"z":{"args":["a"]}}}"#).unwrap();
        assert!(bad["z"].resolve("z").is_err());
    }

    #[test]
    fn expands_variables() {
        let get = |k: &str| match k {
            "TOKEN" => Some("abc".to_string()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            expand_with("Bearer ${TOKEN}", get).unwrap(),
            "Bearer abc".to_string()
        );
        assert_eq!(expand_with("${NOPE:-dflt}/x", get).unwrap(), "dflt/x");
        assert_eq!(expand_with("${EMPTY:-d}", get).unwrap(), "d");
        assert_eq!(expand_with("${EMPTY}", get).unwrap(), "");
        assert!(expand_with("${NOPE}", get).is_err());
        assert!(expand_with("${TOKEN", get).is_err());
        assert_eq!(expand_with("plain $HOME", get).unwrap(), "plain $HOME");
    }

    #[test]
    fn expands_variables_in_oauth() {
        // SAFETY: test-only; the variable name is unique to this test.
        unsafe { std::env::set_var("MCPX_TEST_OAUTH_SECRET_7F3", "s3cret") };
        let m = Config::parse(
            r#"{"mcpServers":{"pb":{"url":"http://127.0.0.1:1/mcp","oauth":{
                "grant":"client_credentials","client_id":"${MCPX_TEST_NOPE_7F3:-cid}",
                "client_secret":"${MCPX_TEST_OAUTH_SECRET_7F3}","scopes":["${MCPX_TEST_NOPE_7F3:-mcp}"]}}}}"#,
        )
        .unwrap();
        let o = m["pb"].resolve("pb").unwrap().oauth;
        assert_eq!(o.client_id.as_deref(), Some("cid"));
        assert_eq!(o.client_secret.as_deref(), Some("s3cret"));
        assert_eq!(o.scopes, Some(vec!["mcp".to_string()]));
    }

    #[test]
    fn explicit_config_must_exist_default_may_not() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        assert!(Config::load(Some(&dir.path().join("nope.json")), &paths).is_err());
        let p = dir.path().join("mcp.json");
        std::fs::write(&p, r#"{"mcpServers":{"a":{"command":"x"}}}"#).unwrap();
        let c = Config::load(Some(&p), &paths).unwrap();
        assert_eq!(c.names(), vec!["a".to_string()]);
        assert!(c.server("b").is_err());
    }
}
