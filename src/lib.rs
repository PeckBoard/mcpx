//! mcpx: an MCP client CLI and local gateway.

pub mod cli;
pub mod client;
pub mod config;
pub mod gateway;
pub mod oauth;
pub mod paths;
pub mod pool;
pub mod sse;
pub mod testserver;

/// Install the ring rustls provider (reqwest is built without one so the
/// binary cross-compiles to musl without cmake). Idempotent.
pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
