use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    mcpx::init_tls();
    mcpx::cli::main().await
}
