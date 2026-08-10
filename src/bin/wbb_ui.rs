//! Public WBB page + read proxy (M6). Slim main — logic lives in `referendum_poc`.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    referendum_poc::actors::run_stub("wbb-ui").await
}
