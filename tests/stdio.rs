//! Direct (no gateway) use against the built-in stdio echo server, both
//! through the library and the real binary.

use std::sync::Arc;

use mcpx::client::Connector;
use mcpx::config::Config;
use mcpx::oauth::OAuth;
use mcpx::pool::Pool;
use serde_json::{Value, json};

fn echo_config() -> Config {
    let exe = env!("CARGO_BIN_EXE_mcpx");
    let text =
        json!({"mcpServers": {"echo": {"command": exe, "args": ["echo-server"]}}}).to_string();
    Config {
        servers: Config::parse(&text).unwrap(),
        sources: vec![],
    }
}

#[tokio::test]
async fn stdio_server_end_to_end() {
    mcpx::init_tls();
    let dir = tempfile::tempdir().unwrap();
    let oauth = Arc::new(OAuth::new(dir.path().join("tokens.json")));
    let pool = Pool::new(echo_config(), Connector::new(oauth, false));

    let servers = pool.servers().await;
    assert_eq!(servers[0]["status"], "connected", "{servers:?}");
    assert_eq!(servers[0]["serverInfo"]["name"], "mcpx-echo");

    let tools = pool.tools(None).await.unwrap();
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["qualifiedName"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["echo__echo", "echo__fail"]);
    assert_eq!(
        tools["tools"][0]["inputSchema"]["required"],
        json!(["message"])
    );

    let mut args = serde_json::Map::new();
    args.insert("message".into(), json!("hi there"));
    let r = pool.call("echo", "echo", args, None).await.unwrap();
    assert_eq!(r["content"][0]["text"], "hi there");
    assert_ne!(r["isError"], json!(true));

    let r = pool
        .call("echo", "fail", Default::default(), None)
        .await
        .unwrap();
    assert_eq!(r["isError"], json!(true));

    let res = pool.resources(Some("echo")).await.unwrap();
    assert_eq!(res["resources"][0]["uri"], "mem://hello");
    let r = pool.read("echo", "mem://hello").await.unwrap();
    assert_eq!(r["contents"][0]["text"], "hello world");

    let p = pool.prompts(None).await.unwrap();
    assert_eq!(p["prompts"][0]["qualifiedName"], "echo__greet");
    let mut args = serde_json::Map::new();
    args.insert("who".into(), json!("Ada"));
    let r = pool.prompt("echo", "greet", args).await.unwrap();
    assert_eq!(r["messages"][0]["content"]["text"], "Hello, Ada!");

    assert!(
        pool.call("nope", "x", Default::default(), None)
            .await
            .is_err()
    );
    pool.shutdown().await;
}

#[tokio::test]
async fn reconnects_after_stdio_server_dies() {
    mcpx::init_tls();
    let dir = tempfile::tempdir().unwrap();
    let oauth = Arc::new(OAuth::new(dir.path().join("tokens.json")));
    let pool = Pool::new(echo_config(), Connector::new(oauth, false));
    let first = pool.get("echo").await.unwrap();
    first.cancellation_token().cancel();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let second = pool.get("echo").await.unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    let r = pool
        .call(
            "echo",
            "echo",
            [("message".to_string(), json!("again"))]
                .into_iter()
                .collect(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r["content"][0]["text"], "again");
    pool.shutdown().await;
}

#[test]
fn cli_call_exit_codes_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcp.json");
    let exe = env!("CARGO_BIN_EXE_mcpx");
    std::fs::write(
        &cfg,
        json!({"mcpServers": {"echo": {"command": exe, "args": ["echo-server"]}}}).to_string(),
    )
    .unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(exe)
            .env("MCPX_HOME", dir.path())
            .arg("--config")
            .arg(&cfg)
            .args(args)
            .output()
            .unwrap()
    };

    let out = run(&["call", "echo.echo", "--arg", "message=hello"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["content"][0]["text"], "hello");

    let out = run(&["call", "echo.fail", "{}"]);
    assert_eq!(out.status.code(), Some(1));

    let out = run(&["call", "missing.tool"]);
    assert!(!out.status.success());
    let err: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown server")
    );

    let out = run(&["--pretty", "tools"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("SERVER"), "{text}");
    assert!(text.contains("echo"), "{text}");
}
