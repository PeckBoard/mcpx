//! Lazily connected, kept-warm MCP connections keyed by server name, plus
//! the aggregate operations (servers/tools/call/…) shared by the CLI and
//! the gateway. Output shapes here ARE the gateway REST response shapes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use crate::client::{self, Connector, Service};
use crate::config::{Config, Server};

pub const SEP: &str = "__";

/// Allow/deny globs over `server__tool`. Deny wins; an empty allow list
/// allows everything.
#[derive(Clone, Default)]
pub struct Filter {
    allow: Option<GlobSet>,
    deny: Option<GlobSet>,
}

impl Filter {
    pub fn new(allow: &[String], deny: &[String]) -> Result<Self> {
        fn build(globs: &[String]) -> Result<Option<GlobSet>> {
            if globs.is_empty() {
                return Ok(None);
            }
            let mut b = GlobSetBuilder::new();
            for g in globs {
                b.add(Glob::new(g).map_err(|e| anyhow!("bad glob '{g}': {e}"))?);
            }
            Ok(Some(b.build()?))
        }
        Ok(Self {
            allow: build(allow)?,
            deny: build(deny)?,
        })
    }

    pub fn allows(&self, qualified: &str) -> bool {
        if self.deny.as_ref().is_some_and(|d| d.is_match(qualified)) {
            return false;
        }
        self.allow.as_ref().is_none_or(|a| a.is_match(qualified))
    }
}

struct Slot {
    server: Server,
    conn: Mutex<Option<Arc<Service>>>,
    last_used: std::sync::Mutex<Instant>,
}

pub struct Pool {
    config: Config,
    connector: Connector,
    slots: std::sync::Mutex<HashMap<String, Arc<Slot>>>,
    pub filter: Filter,
    pub call_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Pool {
    pub fn new(config: Config, connector: Connector) -> Self {
        Self {
            config,
            connector,
            slots: Default::default(),
            filter: Filter::default(),
            call_timeout: Duration::from_secs(120),
            idle_timeout: Duration::from_secs(600),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn names(&self) -> Vec<String> {
        self.config.names()
    }

    fn slot(&self, name: &str) -> Result<Arc<Slot>> {
        let mut slots = self.slots.lock().unwrap();
        if let Some(s) = slots.get(name) {
            return Ok(s.clone());
        }
        let server = self.config.server(name)?;
        let s = Arc::new(Slot {
            server,
            conn: Mutex::new(None),
            last_used: std::sync::Mutex::new(Instant::now()),
        });
        slots.insert(name.to_string(), s.clone());
        Ok(s)
    }

    /// A live connection to `name`, connecting (or reconnecting after a
    /// crash) as needed.
    pub async fn get(&self, name: &str) -> Result<Arc<Service>> {
        let slot = self.slot(name)?;
        let mut g = slot.conn.lock().await;
        *slot.last_used.lock().unwrap() = Instant::now();
        if let Some(c) = g.as_ref() {
            if !client::is_dead(c) {
                return Ok(c.clone());
            }
            tracing::info!("server '{name}' connection lost; reconnecting");
        }
        let c = Arc::new(self.connector.connect(&slot.server).await?);
        *g = Some(c.clone());
        Ok(c)
    }

    /// Drop stdio connections idle longer than `idle_timeout` (their child
    /// processes exit with them). HTTP connections are cheap to keep.
    pub async fn reap_idle(&self) {
        let slots: Vec<Arc<Slot>> = self.slots.lock().unwrap().values().cloned().collect();
        for s in slots {
            if !s.server.is_stdio() {
                continue;
            }
            let idle = s.last_used.lock().unwrap().elapsed() >= self.idle_timeout;
            if !idle {
                continue;
            }
            if let Ok(mut g) = s.conn.try_lock()
                && let Some(c) = g.take()
            {
                tracing::info!("stopping idle stdio server '{}'", s.server.name);
                c.cancellation_token().cancel();
            }
        }
    }

    pub fn spawn_reaper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                let Some(p) = me.upgrade() else { break };
                p.reap_idle().await;
            }
        })
    }

    /// Close every connection, waiting briefly for stdio children to exit.
    pub async fn shutdown(&self) {
        let slots: Vec<Arc<Slot>> = self.slots.lock().unwrap().drain().map(|(_, s)| s).collect();
        for s in slots {
            if let Some(c) = s.conn.lock().await.take() {
                match Arc::try_unwrap(c) {
                    Ok(mut svc) => {
                        let _ = svc.close_with_timeout(Duration::from_secs(3)).await;
                    }
                    Err(c) => c.cancellation_token().cancel(),
                }
            }
        }
    }

    fn targets(&self, server: Option<&str>) -> Result<Vec<String>> {
        match server {
            Some(s) => {
                self.config.server(s)?;
                Ok(vec![s.to_string()])
            }
            None => Ok(self.names()),
        }
    }

    /// Split `server__tool`, preferring the longest matching server name.
    pub fn split_qualified<'a>(&self, q: &'a str) -> Option<(String, &'a str)> {
        self.names()
            .into_iter()
            .filter(|n| {
                q.len() > n.len() + SEP.len()
                    && q.starts_with(n.as_str())
                    && q[n.len()..].starts_with(SEP)
            })
            .max_by_key(|n| n.len())
            .map(|n| {
                let rest = &q[n.len() + SEP.len()..];
                (n, rest)
            })
    }

    pub async fn servers(&self) -> Vec<Value> {
        let futs = self.names().into_iter().map(|n| async move {
            let srv = self.config.server(&n);
            let (kind, target) = match &srv {
                Ok(s) => (s.kind(), s.target()),
                Err(_) => ("?", String::new()),
            };
            let mut v = json!({"name": n, "transport": kind, "target": target});
            match self.get(&n).await {
                Ok(c) => {
                    v["status"] = json!("connected");
                    let info = client::info(&c);
                    for k in [
                        "protocolVersion",
                        "serverInfo",
                        "capabilities",
                        "instructions",
                    ] {
                        if let Some(x) = info.get(k) {
                            v[k] = x.clone();
                        }
                    }
                }
                Err(e) => {
                    v["status"] = json!("error");
                    v["error"] = json!(format!("{e:#}"));
                }
            }
            v
        });
        futures::future::join_all(futs).await
    }

    /// `{"tools": [...], "errors": [...]}`; each tool gains `server` and
    /// `qualifiedName` (`server__tool`). The filter applies.
    pub async fn tools(&self, server: Option<&str>) -> Result<Value> {
        self.collect(server, "tools", |c| {
            Box::pin(async move { client::list_tools(&c).await })
        })
        .await
        .map(|mut v| {
            if let Some(arr) = v["tools"].as_array_mut() {
                arr.retain(|t| {
                    t["qualifiedName"]
                        .as_str()
                        .is_some_and(|q| self.filter.allows(q))
                });
            }
            v
        })
    }

    pub async fn resources(&self, server: Option<&str>) -> Result<Value> {
        self.collect(server, "resources", |c| {
            Box::pin(async move { client::list_resources(&c).await })
        })
        .await
    }

    pub async fn prompts(&self, server: Option<&str>) -> Result<Value> {
        self.collect(server, "prompts", |c| {
            Box::pin(async move { client::list_prompts(&c).await })
        })
        .await
    }

    async fn collect<F>(&self, server: Option<&str>, key: &str, list: F) -> Result<Value>
    where
        F: Fn(Arc<Service>) -> futures::future::BoxFuture<'static, Result<Vec<Value>>> + Sync,
    {
        let targets = self.targets(server)?;
        let list = &list;
        let futs = targets.into_iter().map(|n| async move {
            let r = async {
                let c = self.get(&n).await?;
                tokio::time::timeout(self.call_timeout, list(c))
                    .await
                    .map_err(|_| anyhow!("timed out"))?
            }
            .await;
            (n, r)
        });
        let mut items = Vec::new();
        let mut errors = Vec::new();
        for (n, r) in futures::future::join_all(futs).await {
            match r {
                Ok(list) => {
                    for mut it in list {
                        if let Some(o) = it.as_object_mut() {
                            o.insert("server".into(), json!(n));
                            if key != "resources"
                                && let Some(name) = o.get("name").and_then(Value::as_str)
                            {
                                let q = format!("{n}{SEP}{name}");
                                o.insert("qualifiedName".into(), json!(q));
                            }
                        }
                        items.push(it);
                    }
                }
                Err(e) => errors.push(json!({"server": n, "error": format!("{e:#}")})),
            }
        }
        if server.is_some()
            && let Some(e) = errors.first()
        {
            bail!("{}", e["error"].as_str().unwrap_or("error"));
        }
        Ok(json!({ key: items, "errors": errors }))
    }

    pub async fn call(
        &self,
        server: &str,
        tool: &str,
        args: Map<String, Value>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let q = format!("{server}{SEP}{tool}");
        if !self.filter.allows(&q) {
            bail!(Denied(q));
        }
        let c = self.get(server).await?;
        let t = timeout.unwrap_or(self.call_timeout);
        tokio::time::timeout(t, client::call_tool(&c, tool, args))
            .await
            .map_err(|_| anyhow!("tool call timed out after {}s", t.as_secs()))?
    }

    pub async fn read(&self, server: &str, uri: &str) -> Result<Value> {
        let c = self.get(server).await?;
        tokio::time::timeout(self.call_timeout, client::read_resource(&c, uri))
            .await
            .map_err(|_| anyhow!("timed out"))?
    }

    pub async fn prompt(
        &self,
        server: &str,
        name: &str,
        args: Map<String, Value>,
    ) -> Result<Value> {
        let c = self.get(server).await?;
        tokio::time::timeout(self.call_timeout, client::get_prompt(&c, name, args))
            .await
            .map_err(|_| anyhow!("timed out"))?
    }
}

/// A call blocked by the gateway's allow/deny filter.
#[derive(Debug)]
pub struct Denied(pub String);
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tool '{}' is not allowed by the gateway filter", self.0)
    }
}
impl std::error::Error for Denied {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_deny_wins_and_allow_restricts() {
        let f = Filter::new(
            &["gh__*".into(), "fs__read*".into()],
            &["gh__delete*".into()],
        )
        .unwrap();
        assert!(f.allows("gh__list_issues"));
        assert!(!f.allows("gh__delete_repo"));
        assert!(f.allows("fs__read_file"));
        assert!(!f.allows("fs__write_file"));
        assert!(Filter::default().allows("anything__x"));
    }
}
