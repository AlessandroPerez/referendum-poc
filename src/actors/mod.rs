//! Actor services (HTTP servers), implemented per roadmap milestones:
//! `er`/`dip`/`ns` (M3), `rt`/`tt` (M4), `voter` (M5), `bb`/`wbb_ui` (M6),
//! tally driver and auditor CLIs (M8).

use anyhow::Context;

pub mod common;
pub mod dip;
pub mod er;
pub mod ns;

/// Placeholder entrypoint used by binary targets whose milestone has not landed
/// yet. Initializes telemetry and exits successfully.
pub async fn run_stub(service_name: &'static str) -> anyhow::Result<()> {
    crate::telemetry::init_subscriber(crate::telemetry::get_subscriber(
        service_name.into(),
        "info".into(),
        std::io::stdout,
    ));
    tracing::info!(
        service = service_name,
        "service stub: implemented in a later milestone"
    );
    tokio::task::yield_now().await;
    Ok(())
}

/// Read settings for `base_dir`, logging the target environment — shared by
/// all future service entrypoints.
pub fn load_settings(base_dir: &std::path::Path) -> anyhow::Result<crate::configuration::Settings> {
    crate::configuration::get_configuration(base_dir).context("failed to load configuration")
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn stub_runs() {
        super::run_stub("test-service")
            .await
            .expect("stub must run");
    }

    #[test]
    fn settings_load_from_manifest_dir() {
        // Shares the crate-wide env lock: `get_configuration` reads
        // `APP_ENVIRONMENT`, which sibling tests may mutate (see
        // `configuration::ENV_LOCK`).
        let _guard = crate::configuration::ENV_LOCK.lock().expect("env lock");
        let settings = super::load_settings(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("settings must load");
        assert_eq!(settings.service.name, "referendum-poc");
    }
}
