//! Legacy HTTP+SSE client transport (MCP 2024-11-05): `GET <url>` opens an
//! event stream whose first `endpoint` event names the URL to POST
//! JSON-RPC messages to; responses arrive as `message` events. rmcp 3.x
//! only ships the streamable-HTTP client, so this fills the gap.

use std::time::Duration;

use futures::StreamExt;
use reqwest::header::HeaderMap;
use rmcp::RoleClient;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::Transport;
use sse_stream::SseStream;
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::client::ConnectError;

pub struct SseTransport {
    http: reqwest::Client,
    headers: HeaderMap,
    endpoint: String,
    rx: mpsc::Receiver<ServerJsonRpcMessage>,
    task: tokio::task::JoinHandle<()>,
}

impl SseTransport {
    pub async fn connect(
        http: reqwest::Client,
        url: &str,
        headers: HeaderMap,
    ) -> Result<Self, ConnectError> {
        let base = Url::parse(url).map_err(|e| ConnectError::Other(e.into()))?;
        let resp = http
            .get(url)
            .headers(headers.clone())
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| ConnectError::Other(e.into()))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let ch = resp
                .headers()
                .get("www-authenticate")
                .and_then(|h| h.to_str().ok())
                .map(str::to_string);
            return Err(ConnectError::Unauthorized(ch));
        }
        if !resp.status().is_success() {
            return Err(ConnectError::Other(anyhow::anyhow!(
                "SSE connect failed: HTTP {}",
                resp.status()
            )));
        }
        let (ep_tx, mut ep_rx) = watch::channel::<Option<String>>(None);
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let mut events = SseStream::from_bytes_stream(resp.bytes_stream());
            while let Some(ev) = events.next().await {
                let Ok(ev) = ev else { break };
                let data = ev.data.unwrap_or_default();
                match ev.event.as_deref() {
                    Some("endpoint") => {
                        if let Ok(u) = base.join(data.trim()) {
                            let _ = ep_tx.send(Some(u.to_string()));
                        }
                    }
                    None | Some("message") => {
                        match serde_json::from_str::<ServerJsonRpcMessage>(&data) {
                            Ok(m) => {
                                if tx.send(m).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => tracing::debug!("bad SSE message: {e}"),
                        }
                    }
                    _ => {}
                }
            }
        });
        let endpoint = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(e) = ep_rx.borrow().clone() {
                    return Some(e);
                }
                if ep_rx.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await
        .ok()
        .flatten()
        .ok_or_else(|| ConnectError::Other(anyhow::anyhow!("SSE server sent no endpoint event")))?;
        Ok(Self {
            http,
            headers,
            endpoint,
            rx,
            task,
        })
    }
}

impl Transport<RoleClient> for SseTransport {
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: ClientJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let http = self.http.clone();
        let headers = self.headers.clone();
        let endpoint = self.endpoint.clone();
        async move {
            let r = http
                .post(&endpoint)
                .headers(headers)
                .json(&item)
                .send()
                .await
                .map_err(std::io::Error::other)?;
            if !r.status().is_success() {
                return Err(std::io::Error::other(format!(
                    "SSE POST failed: HTTP {}",
                    r.status()
                )));
            }
            Ok(())
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<ServerJsonRpcMessage>> + Send {
        self.rx.recv()
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.task.abort();
        Ok(())
    }
}

impl Drop for SseTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}
