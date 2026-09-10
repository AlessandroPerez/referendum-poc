//! Notification Server service . Slim main - logic lives in `referendum_poc`.

use std::path::PathBuf;

use referendum_poc::actors::common::load_signing_key;
use referendum_poc::actors::load_settings;
use referendum_poc::actors::ns;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().expect("current dir"));
    let settings = load_settings(&base_dir)?;

    let signing_key_path = base_dir.join(format!("{}-signing-key.bin", settings.service.name));
    let signing_key = load_signing_key(&signing_key_path).await?;

    ns::run(settings, signing_key).await
}
