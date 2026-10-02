//! Universal-verification auditor CLI (Sec. 3.10).
//!
//! Fetches every artifact from the WBB and re-runs the public pipeline; only
//! the entity verifying keys and the cluster CA come from the local
//! ceremony/config directory. Prints per-step OK/FAIL and exits nonzero on
//! any FAIL (Sec. 3.10).

use std::path::PathBuf;

use clap::Parser;
use referendum_poc::actors::auditor::{run_audit, AuditConfig};
use referendum_poc::actors::load_settings;
use reqwest::Url;

#[derive(Parser)]
#[command(name = "referendum-auditor")]
#[command(about = "Universal verification of a referendum WBB log")]
struct Cli {
    /// Directory containing `configuration/base.yaml` and ceremony artifacts.
    #[arg(short, long, default_value = ".")]
    config: PathBuf,

    /// WBB log base URL (overrides configuration).
    #[arg(long)]
    wbb: Option<Url>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    referendum_poc::telemetry::init_subscriber(referendum_poc::telemetry::get_subscriber(
        "referendum-auditor".into(),
        "info".into(),
        std::io::stdout,
    ));

    let cli = Cli::parse();
    let settings = load_settings(&cli.config)?;
    let ceremony_dir = std::path::PathBuf::from(&settings._ceremony.election_context)
        .parent()
        .unwrap_or(&cli.config)
        .to_path_buf();

    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let wbb_url = match cli.wbb {
        Some(url) => url,
        None => Url::parse(&settings.wbb.base_url)
            .map_err(|e| anyhow::anyhow!("invalid wbb.base_url: {e}"))?,
    };

    // Entity verifying keys from the ceremony's PUBLIC key files - an
    // external verifier needs no secret material to run the audit.
    let mut names = vec![("pm".to_string(), "PM-1".to_string())];
    names.push(("er".to_string(), "ER-1".to_string()));
    for i in 1..=settings.election.n_rt {
        names.push((format!("rt-{i}"), format!("RT-{i}")));
    }
    for i in 1..=settings.election.n_tt {
        names.push((format!("tt-{i}"), format!("TT-{i}")));
    }
    for i in 1..=settings.election.n_bb {
        names.push((format!("bb-{i}"), format!("BB-{i}")));
    }
    let mut entity_keys = Vec::with_capacity(names.len());
    for (file_name, entity_id) in names {
        let path = ceremony_dir.join(format!("{file_name}-verifying-key.bin"));
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("verifying key {entity_id} must be 32 bytes"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid verifying key for {entity_id}: {e}"))?;
        entity_keys.push((entity_id, key));
    }

    let log_key_path =
        ceremony_dir.join(referendum_poc::protocol::setup::artifacts::WBB_LOG_PUBLIC_KEY_FILE);
    let log_key = tokio::fs::read_to_string(&log_key_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", log_key_path.display()))
        .and_then(|text| {
            referendum_poc::protocol::tlog::log_key_from_base64(&text)
                .map_err(|e| anyhow::anyhow!("{}: {e}", log_key_path.display()))
        })?;

    // Validator keys are pinned from the operator's own board configuration
    // in the ceremony directory - a local file, not something the board says.
    let validator_keys = match std::fs::read_to_string(ceremony_dir.join("sunlight.yaml")) {
        Ok(yaml) => referendum_poc::protocol::validators::pinned_keys_from_board_config(&yaml)
            .map_err(|e| anyhow::anyhow!("sunlight.yaml: {e}"))?,
        Err(_) => Vec::new(),
    };
    let log_origin = referendum_poc::protocol::tlog::log_origin_of(&wbb_url);

    let report = run_audit(AuditConfig {
        wbb_url,
        ca_pem,
        log_key,
        log_origin,
        validator_keys,
        entity_keys,
        n_tt: settings.election.n_tt,
        t_tt: settings.election.t_tt,
    })
    .await?;
    print!("{}", report.render());
    if !report.ok() {
        std::process::exit(1);
    }
    Ok(())
}
