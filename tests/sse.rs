//! Legacy HTTP+SSE transport against a minimal 2024-11-05 style server
//! (GET /sse → `endpoint` event, POST /messages) bridged to the echo server.

use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::routing::{get, post};
use futures::Stream;
use mcpx::client::Connector;
use mcpx::config::Config;
use mcpx::oauth::OAuth;
use mcpx::pool::Pool;
use mcpx::testserver::EchoServer;
use rmcp::ServiceExt;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, WriteHalf};
use tokio::sync::{Mutex, mpsc};

#[derive(Clone)]
struct Bridge {
    to_server: Arc<Mutex<WriteHalf<tokio::io::DuplexStream>>>,
    from_server: Arc<Mutex<Option<mpsc::Receiver<String>>>>,
}

async fn sse(State(b): State<Bridge>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = b
        .from_server
        .lock()
        .await
        .take()
        .expect("single SSE client");
    let first = futures::stream::once(async {
        Ok(Event::default()
            .event("endpoint")
            .data("/messages?sessionId=1"))
    });
    let rest = futures::stream::unfold(rx, |mut rx| async move {
        let line = rx.recv().await?;
        Some((Ok(Event::default().event("message").data(line)), rx))
    });
    Sse::new(futures::StreamExt::chain(first, rest))
}

async fn messages(State(b): State<Bridge>, body: String) -> StatusCode {
    let mut w = b.to_server.lock().await;
    w.write_all(body.as_bytes()).await.unwrap();
    w.write_all(b"\n").await.unwrap();
    StatusCode::ACCEPTED
}

#[tokio::test]
async fn legacy_sse_transport() {
    mcpx::init_tls();
    let (server_io, bridge_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let s = EchoServer.serve(server_io).await.unwrap();
        let _ = s.waiting().await;
    });
    let (r, w) = tokio::io::split(bridge_io);
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if tx.send(l).await.is_err() {
                break;
            }
        }
    });
    let bridge = Bridge {
        to_server: Arc::new(Mutex::new(w)),
        from_server: Arc::new(Mutex::new(Some(rx))),
    };
    let app = Router::new()
        .route("/sse", get(sse))
        .route("/messages", post(messages))
        .with_state(bridge);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let text =
        json!({"mcpServers": {"old": {"type": "sse", "url": format!("{base}/sse")}}}).to_string();
    let config = Config {
        servers: Config::parse(&text).unwrap(),
        sources: vec![],
    };
    let oauth = Arc::new(OAuth::new(dir.path().join("tokens.json")));
    let pool = Pool::new(config, Connector::new(oauth, false));
    let r = pool
        .call(
            "old",
            "echo",
            [("message".to_string(), json!("over sse"))]
                .into_iter()
                .collect(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r["content"][0]["text"], "over sse");
    pool.shutdown().await;
}
