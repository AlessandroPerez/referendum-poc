//! Election-admin driver logic (M4/M8).
//!
//! This module implements the coordinator-side steps that run inside the
//! `election-admin` CLI.  It keeps crypto in `protocol/` and HTTP orchestration
//! here.

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::SigningKey;
use evoting::api::prelude::RTPublicKey;
use evoting::api::server::bb::ElectionContext;
use evoting::api::server::rt::ThresholdRegistrationTeller;
use reqwest::Url;
use secrecy::SecretString;

use crate::actors::common::load_signing_key;
use crate::clients::rt::{RtClient, RtError};
use crate::clients::wbb::{sign_entry, SignedEntry, WbbClient};
use crate::protocol::acc::{
    acc_rng_from_signing_key_seeds, build_acc_pub_key_data_string, generate_credentials,
    load_rt_share, reconstruct_rt_teller,
};
use crate::protocol::clock::LogicalClock;
use crate::protocol::tls::reqwest_client_trusting_ca;

/// Configuration for the `gen-credentials` admin driver.
#[derive(Clone, Debug)]
pub struct GenCredentialsConfig {
    /// Directory containing ceremony artifacts (`election_context.json`,
    /// `rt_public_key.json`, `rt-*-share.json`, `rt-*-signing-key.bin`,
    /// `ca.pem`).
    pub ceremony_dir: std::path::PathBuf,
    /// Directory where `enrollment_packages.json` is written.
    pub output_dir: std::path::PathBuf,
    /// Number of credentials to generate.
    pub n_acc: usize,
    /// Outer RT threshold (`t_rt`).
    pub t_rt: usize,
    /// Inner RT threshold (`t'_rt`).
    pub t_prime: usize,
    /// WBB log URL, e.g. `https://127.0.0.1:8090/wbb/`.
    pub wbb_url: Url,
    /// Optional RT `/sign` endpoint URLs.  When `None`, the admin signs the
    /// `acc_pub_key` entry locally using the RT signing key files.
    pub rt_urls: Option<Vec<Url>>,
    /// Service bearer tokens for the RT `/sign` endpoints, one per URL.
    pub rt_tokens: Option<Vec<SecretString>>,
    /// PEM-encoded cluster CA certificate.
    pub ca_pem: String,
    /// Deterministic logical clock for WBB timestamps.
    pub clock: LogicalClock,
}

/// Errors raised by the admin driver.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("ACC error: {0}")]
    Acc(#[from] crate::protocol::acc::AccError),
    #[error("WBB error: {0}")]
    Wbb(#[from] crate::clients::wbb::WbbError),
    #[error("RT client error: {0}")]
    Rt(#[from] RtError),
    #[error("TLS error: {0}")]
    Tls(#[from] crate::protocol::tls::TlsError),
    #[error("expected {expected} RT URLs, got {got}")]
    RtUrlCount { expected: usize, got: usize },
    #[error("admin driver error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for AdminError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
    }
}

/// Run the M4 credential-generation driver.
///
/// 1. Reconstruct all RT tellers from share files.
/// 2. Generate `n_acc` credentials and the public ACC list.
/// 3. Co-sign the `setup,RT,acc_pub_key,2,…` WBB entry (via RT `/sign`
///    endpoints when configured, otherwise locally).
/// 4. Submit the partial signatures to the WBB and wait for inclusion.
/// 5. Write `enrollment_packages.json` to `output_dir`.
pub async fn gen_credentials(cfg: GenCredentialsConfig) -> Result<(), AdminError> {
    std::fs::create_dir_all(&cfg.output_dir)?;

    let election_context = load_election_context(&cfg.ceremony_dir).await?;
    let rt_pk = load_rt_public_key(&cfg.ceremony_dir).await?;

    let mut tellers: Vec<ThresholdRegistrationTeller<RistrettoGroup>> = Vec::with_capacity(3);
    let mut signing_key_seeds = Vec::with_capacity(3);
    for i in 1..=3 {
        let share_path = cfg.ceremony_dir.join(format!("rt-{i}-share.json"));
        let share = tokio::task::spawn_blocking({
            let path = share_path.clone();
            move || load_rt_share(&path)
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))??;
        tellers.push(reconstruct_rt_teller(share, &election_context, &rt_pk));

        let key_path = cfg.ceremony_dir.join(format!("rt-{i}-signing-key.bin"));
        let key = load_signing_key(&key_path).await?;
        signing_key_seeds.push(key.to_bytes());
    }

    // Deterministic RNG seeded from the RT signing keys.
    let mut rng = acc_rng_from_signing_key_seeds(&signing_key_seeds);

    let (packages, short_accs) = tokio::task::spawn_blocking(move || {
        generate_credentials(
            cfg.n_acc,
            cfg.t_rt,
            cfg.t_prime,
            &mut tellers,
            &election_context,
            &rt_pk,
            &mut rng,
        )
    })
    .await
    .map_err(|e| AdminError::Other(e.to_string()))??;

    // Write enrollment packages for M5.
    let packages_path = cfg.output_dir.join("enrollment_packages.json");
    tokio::fs::write(&packages_path, serde_json::to_string_pretty(&packages)?).await?;

    // Build the WBB data string and sign it.
    let data_string = build_acc_pub_key_data_string(&short_accs, cfg.t_prime)?;
    let mut clock = cfg.clock;
    let signed_entries =
        sign_acc_pub_key_entries(&cfg, &data_string, &signing_key_seeds, &mut clock).await?;

    // Submit all partial signatures to the WBB.
    let wbb_client = build_wbb_client(&cfg).await?;
    for entry in &signed_entries {
        wbb_client.submit(entry).await?;
    }

    // Wait until the entry is included (do not resubmit: it is already staged).
    let data_b64 = BASE64.encode(&signed_entries[0].data);
    let deadline = std::time::Duration::from_secs(15);
    let end = tokio::time::Instant::now() + deadline;
    loop {
        if let Ok(entries) = wbb_client.entries().await {
            if entries.entries.iter().any(|e| {
                e.entry
                    .get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| s == data_b64)
                    .unwrap_or(false)
            }) {
                break;
            }
        }
        if tokio::time::Instant::now() > end {
            return Err(AdminError::Other(
                "acc_pub_key entry was not included in time".to_string(),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    tracing::info!(
        n_acc = cfg.n_acc,
        packages_path = %packages_path.display(),
        "generated credentials and published acc_pub_key to WBB"
    );

    Ok(())
}

async fn load_election_context(
    ceremony_dir: &Path,
) -> anyhow::Result<ElectionContext<RistrettoGroup>> {
    let path = ceremony_dir.join("election_context.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse election context: {e}"))
}

async fn load_rt_public_key(ceremony_dir: &Path) -> anyhow::Result<RTPublicKey<RistrettoGroup>> {
    let path = ceremony_dir.join("rt_public_key.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse RT public key: {e}"))
}

async fn build_wbb_client(cfg: &GenCredentialsConfig) -> anyhow::Result<WbbClient> {
    let client = reqwest_client_trusting_ca(&cfg.ca_pem)?;
    Ok(WbbClient::new(client, cfg.wbb_url.clone()))
}

async fn sign_acc_pub_key_entries(
    cfg: &GenCredentialsConfig,
    data_string: &str,
    signing_key_seeds: &[[u8; 32]],
    clock: &mut LogicalClock,
) -> Result<Vec<SignedEntry>, AdminError> {
    let mut entries = Vec::with_capacity(3);

    // All co-signers share the same logical timestamp for this artifact; the
    // clock advances once the artifact is published.
    let timestamp = clock.now_ms() as i64;
    clock.advance();

    if let Some(urls) = &cfg.rt_urls {
        let tokens = cfg.rt_tokens.as_ref().ok_or_else(|| {
            AdminError::Other("rt_urls provided without corresponding rt_tokens".to_string())
        })?;
        if urls.len() != signing_key_seeds.len() {
            return Err(AdminError::RtUrlCount {
                expected: signing_key_seeds.len(),
                got: urls.len(),
            });
        }
        if tokens.len() != urls.len() {
            return Err(AdminError::RtUrlCount {
                expected: urls.len(),
                got: tokens.len(),
            });
        }
        let client = reqwest_client_trusting_ca(&cfg.ca_pem)?;
        for (url, token) in urls.iter().zip(tokens.iter()) {
            let rt_client = RtClient::new(client.clone(), url.clone(), token.clone());
            let response = rt_client.sign(data_string, timestamp).await?;
            let entry = RtClient::to_signed_entry(data_string, &response)?;
            entries.push(entry);
        }
    } else {
        for (i, seed) in signing_key_seeds.iter().enumerate() {
            let entity_id = format!("RT-{}", i + 1);
            let key = SigningKey::from_bytes(seed);
            let entry = sign_entry(data_string.as_bytes(), &entity_id, timestamp, &key);
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Convenience re-export of the enrollment package type for callers that need
/// to inspect the generated artifacts.
pub use crate::protocol::acc::EnrollmentPackage;
