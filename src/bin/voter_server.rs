//! Voter backend . Slim main - logic lives in `referendum_poc`.

use std::path::PathBuf;

use referendum_poc::actors::load_settings;
use referendum_poc::actors::voter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("cannot determine working directory: {e}"))?,
    };
    let settings = load_settings(&base_dir)?;
    voter::run(settings).await
}
