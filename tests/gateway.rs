//! `mcpx serve` on a random port: REST + the aggregated `/mcp` endpoint via
//! an rmcp client, the allow/deny filter, bearer auth, and CLI routing
//! through `gateway.json`.

use std::sync::Arc;

use mcpx::client::Connector;
use mcpx::config::Config;
use mcpx::gateway::{self, GatewayState};
use mcpx::oauth::OAuth;
use mcpx::pool::{Filter, Pool};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};

#[tokio::test]
async fn gateway_rest_and_mcp() {
    mcpx::init_tls();
    let exe = env!("CARGO_BIN_EXE_mcpx");
    let dir = tempfile::tempdir().unwrap();
    let text =
        json!({"mcpServers": {"echo": {"command": exe, "args": ["echo-server"]}}}).to_string();
    let config = Config {
        servers: Config::parse(&text).unwrap(),
        sources: vec![],
    };
    let oauth = Arc::new(OAuth::new(dir.path().join("tokens.json")));
    let mut pool = Pool::new(config, Connector::new(oauth, false));
    pool.filter = Filter::new(&[], &["*__fail".to_string()]).unwrap();
    let gw = gateway::start(Arc::new(pool), 0, true).await.unwrap();
    let base = format!("http://{}", gw.addr);
    let token = gw.token.clone().unwrap();
    let http = reqwest::Client::new();

    let h: Value = http
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(h["ok"], true);

    let r = http.get(format!("{base}/tools")).send().await.unwrap();
    assert_eq!(r.status(), 401);

    let tools: Value = http
        .get(format!("{base}/tools"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["qualifiedName"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["echo__echo"]);

    let r: Value = http
        .post(format!("{base}/call"))
        .bearer_auth(&token)
        .json(&json!({"server": "echo", "tool": "echo", "arguments": {"message": "via rest"}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["content"][0]["text"], "via rest");

    let r = http
        .post(format!("{base}/call"))
        .bearer_auth(&token)
        .json(&json!({"server": "echo", "tool": "fail"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let r: Value = http
        .post(format!("{base}/read"))
        .bearer_auth(&token)
        .json(&json!({"server": "echo", "uri": "mem://hello"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["contents"][0]["text"], "hello world");

    // An MCP client (what a bot would use) against /mcp.
    let cfg = StreamableHttpClientTransportConfig::with_uri(format!("{base}/mcp"))
        .auth_header(token.clone());
    let t = StreamableHttpClientTransport::with_client(reqwest::Client::new(), cfg);
    let client = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("test", "0"),
    )
    .serve(t)
    .await
    .unwrap();
    let tools = client.peer().list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names, vec!["echo__echo".to_string()]);
    let params: CallToolRequestParams =
        serde_json::from_value(json!({"name": "echo__echo", "arguments": {"message": "via mcp"}}))
            .unwrap();
    let r = client.call_tool(params).await.unwrap();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["content"][0]["text"], "via mcp");
    let params: CallToolRequestParams =
        serde_json::from_value(json!({"name": "echo__fail", "arguments": {}})).unwrap();
    let r = serde_json::to_value(client.call_tool(params).await.unwrap()).unwrap();
    assert_eq!(r["isError"], true);
    drop(client);

    // Unauthenticated MCP is refused.
    let t = StreamableHttpClientTransport::with_client(
        reqwest::Client::new(),
        StreamableHttpClientTransportConfig::with_uri(format!("{base}/mcp")),
    );
    assert!(
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("test", "0")
        )
        .serve(t)
        .await
        .is_err()
    );

    // The CLI finds the gateway through gateway.json and routes through it
    // (cwd has no .mcp.json and MCPX_HOME has no mcp.json).
    let home = tempfile::tempdir().unwrap();
    let state = GatewayState {
        port: gw.addr.port(),
        token: Some(token.clone()),
        pid: std::process::id(),
    };
    std::fs::write(
        home.path().join("gateway.json"),
        serde_json::to_string(&state).unwrap(),
    )
    .unwrap();
    let out = tokio::process::Command::new(exe)
        .env("MCPX_HOME", home.path())
        .current_dir(home.path())
        .args(["call", "echo.echo", r#"{"message":"via cli"}"#])
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["content"][0]["text"], "via cli");

    gw.ct.cancel();
    let _ = gw.handle.await;
}
