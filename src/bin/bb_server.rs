//! Ballot Box server . Slim main - logic lives in `referendum_poc`.

use std::path::PathBuf;

use referendum_poc::actors::bb;
use referendum_poc::actors::common::load_signing_key;
use referendum_poc::actors::load_settings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("cannot determine working directory: {e}"))?,
    };
    let settings = load_settings(&base_dir)?;

    let signing_key_path = base_dir.join(format!("{}-signing-key.bin", settings.service.name));
    let signing_key = load_signing_key(&signing_key_path).await?;

    bb::run(settings, signing_key).await
}
