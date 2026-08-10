//! Universal-verification auditor CLI (§3.10, M8).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    referendum_poc::actors::run_stub("referendum-auditor").await
}
