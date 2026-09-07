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
    acc_rng_from_seeds, build_acc_pub_key_data_string, generate_credentials, load_rt_share,
    reconstruct_rt_teller,
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
    let mut operation_seeds: Vec<[u8; 32]> = Vec::with_capacity(3);
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

        let seed_path = cfg.ceremony_dir.join(format!("rt-{i}-seed.bin"));
        let bytes = tokio::fs::read(&seed_path).await.map_err(|e| {
            AdminError::Other(format!(
                "failed to read RT operation seed {}: {e}",
                seed_path.display()
            ))
        })?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AdminError::Other("operation seed must be 32 bytes".into()))?;
        operation_seeds.push(seed);
    }

    // Deterministic RNG seeded from the RT operation seeds (§9.2), decoupled
    // from the WBB entry-signing keys used below for co-signing.
    let mut rng = acc_rng_from_seeds(&operation_seeds);

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
    let data_string = build_acc_pub_key_data_string(&short_accs)?;
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

/// Configuration for a PM phase transition (§3.4.2, roadmap A4).
#[derive(Clone, Debug)]
pub struct PhaseTransitionConfig {
    /// Directory containing `pm-signing-key.bin`.
    pub ceremony_dir: std::path::PathBuf,
    /// WBB log base URL.
    pub wbb_url: Url,
    /// Cluster CA PEM for TLS.
    pub ca_pem: String,
    /// Logical clock for the entry timestamp (§9.4).
    pub clock: LogicalClock,
}

// ── M8: tally driver (§3.9 / roadmap §8.5, design lock 2026-09-07) ─────────

/// Configuration for the `election-admin tally` driver.
#[derive(Clone, Debug)]
pub struct TallyConfig {
    /// Directory containing ceremony artifacts (context, signing keys,
    /// share files, service tokens, operation seeds).
    pub ceremony_dir: std::path::PathBuf,
    /// WBB log base URL.
    pub wbb_url: Url,
    /// ER base URL (eligible-vid publication).
    pub er_url: Url,
    /// BB base URLs in `bb-1..n` order (ballot release).
    pub bb_urls: Vec<Url>,
    /// RT base URLs in `rt-1..n` order (credential controls).
    pub rt_urls: Vec<Url>,
    /// TT base URLs in `tt-1..n` order (ζ VSS, threshold decryptions, co-signing).
    pub tt_urls: Vec<Url>,
    /// Cluster CA PEM for TLS.
    pub ca_pem: String,
    /// Deterministic logical clock for WBB timestamps (§9.4).
    pub clock: LogicalClock,
    /// Number of generated credentials (`n_acc`) — bounds the dlog table.
    pub n_acc: usize,
    /// TT reconstruction threshold (`t_tt`) for ζ finalization.
    pub t_tt: usize,
}

/// Outcome of a tally run: the counts plus the per-stage cardinalities.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct TallyOutcome {
    pub counts: crate::protocol::tally::TallyCounts,
    /// Ballots released across all BBs (with duplicates).
    pub released: usize,
    /// Reconciled ballots after the ⊥ filter (§3.8.5).
    pub reconciled: usize,
    /// Ballots after ox re-vote dedup (§3.9 step 10).
    pub deduped: usize,
    /// Votes surviving the ACC check (§3.9 step 14).
    pub valid: usize,
    /// Votes surviving the illicit/keep-last filter (§3.9 step 24).
    pub legitimate: usize,
}

/// Run the full §3.9 tally pipeline over HTTP (M8.1).
pub async fn run_tally(cfg: TallyConfig) -> Result<TallyOutcome, AdminError> {
    use crate::clients::bb::BbClient;
    use crate::clients::er::ErClient;
    use crate::clients::tt::TtClient;
    use crate::protocol::tally::{
        extract_counts, reconcile_ballots, tally_rng_from_seeds, EncryptedBallotEntry,
        MixedBallotsEntry, ReEncryptionProofEntry, TallyProofEntry,
    };
    use crate::protocol::voting::{parse_wbb_data, wbb_data_string};
    use dlog_sigma_primitives::elgamal::ciphertext::DiscreteLogTable;
    use evoting::api::prelude::{
        DecryptedFingerprintsBundle, ShortPublicACC, ThresholdTabulationTeller,
    };
    use evoting::api::server::bb::{PublicElection, PublicPipeline};

    let election_context = load_election_context(&cfg.ceremony_dir).await?;
    let http = reqwest_client_trusting_ca(&cfg.ca_pem)?;
    let wbb = WbbClient::new(http.clone(), cfg.wbb_url.clone());
    let mut clock = cfg.clock;

    // §3.9 step 1: the tally runs strictly inside the tallying phase.
    let phase = wbb
        .phase()
        .await
        .map_err(|e| AdminError::Other(format!("WBB phase query failed: {e}")))?;
    if phase != "tallying" {
        return Err(AdminError::Other(format!(
            "tally requires the tallying phase, WBB is in {phase}"
        )));
    }

    // §3.9 step 1: ER publishes the eligible vid list (minus revoked).
    let er_admin_token = load_token_file(&cfg.ceremony_dir.join("er-admin-token.txt")).await?;
    let er = ErClient::new(http.clone(), cfg.er_url.clone());
    let eligible = er
        .publish_eligible_vids(&er_admin_token)
        .await
        .map_err(|e| AdminError::Other(format!("eligible-vid publication failed: {e}")))?;

    // §3.9 step 2: fetch every BB's ballots and publish the per-BB release,
    // each record signed with that BB's own key (design lock (a)/(c)).
    let mut per_bb = Vec::with_capacity(cfg.bb_urls.len());
    for (i, url) in cfg.bb_urls.iter().enumerate() {
        let name = format!("bb-{}", i + 1);
        let token =
            load_token_file(&cfg.ceremony_dir.join(format!("{name}-service-token.txt"))).await?;
        let bb = BbClient::new(http.clone(), url.clone());
        let records = bb
            .ballots(&token)
            .await
            .map_err(|e| AdminError::Other(format!("ballot release from {name} failed: {e}")))?;
        let signing_key =
            load_signing_key(&cfg.ceremony_dir.join(format!("{name}-signing-key.bin"))).await?;
        let entity_id = name.to_uppercase();
        for record in &records {
            let data = wbb_data_string(
                "tallying",
                "BB",
                "encrypted_ballot",
                1,
                &EncryptedBallotEntry {
                    record: record.clone(),
                },
            )
            .map_err(|e| AdminError::Other(e.to_string()))?;
            let timestamp = clock.now_ms() as i64;
            clock.advance();
            let entry = sign_entry(data.as_bytes(), &entity_id, timestamp, &signing_key);
            wbb.submit_and_wait(&entry, std::time::Duration::from_secs(10))
                .await?;
        }
        per_bb.push(records);
    }
    let released: usize = per_bb.iter().map(Vec::len).sum();

    // Design lock (a): reconcile by digest — the §3.8.5 ⊥ filter.
    let records = tokio::task::spawn_blocking(move || reconcile_ballots(&per_bb))
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Other(format!("ballot reconciliation failed: {e}")))?;
    let reconciled = records.len();

    // Deterministic driver RNG for mixes and fingerprint blinding (§9.2).
    let mut tt_seeds = Vec::with_capacity(cfg.tt_urls.len());
    for i in 1..=cfg.tt_urls.len() {
        let path = cfg.ceremony_dir.join(format!("tt-{i}-seed.bin"));
        let bytes = tokio::fs::read(&path).await.map_err(|e| {
            AdminError::Other(format!("failed to read TT seed {}: {e}", path.display()))
        })?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AdminError::Other("operation seed must be 32 bytes".into()))?;
        tt_seeds.push(seed);
    }
    let mut rng = tally_rng_from_seeds(&tt_seeds);

    // TT clients (ζ VSS, decryptions, co-signing).
    let mut tts = Vec::with_capacity(cfg.tt_urls.len());
    for (i, url) in cfg.tt_urls.iter().enumerate() {
        let token = load_token_file(
            &cfg.ceremony_dir
                .join(format!("tt-{}-service-token.txt", i + 1)),
        )
        .await?;
        tts.push(TtClient::new(http.clone(), url.clone(), token));
    }

    let pipeline = PublicPipeline::new(PublicElection::new(election_context.clone()));

    // §3.9 steps 6–7: threshold ζ* generation over all TTs.
    let zeta_star = run_zeta_vss(&tts, "ox", cfg.t_tt).await?;

    // §3.9 steps 5–10: verify ballots, fingerprint the ox handles, threshold-
    // decrypt, and dedup re-votes (last cast wins).
    let (fps, records, mut rng) = {
        let pipeline = pipeline.clone();
        tokio::task::spawn_blocking(move || {
            let fps = pipeline.gen_ox_fingerprints(&records, zeta_star, &mut rng)?;
            Ok::<_, evoting::error::Error>((fps, records, rng))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("ox fingerprint generation failed: {e:?}")))?
    };
    let mut ox_partials = Vec::with_capacity(tts.len());
    for tt in &tts {
        ox_partials.push(
            tt.decrypt_ox(&fps)
                .await
                .map_err(|e| AdminError::Other(format!("TT ox decryption failed: {e}")))?,
        );
    }
    let (dec_ox, deduped_records) = {
        let ctx = election_context.clone();
        let pipeline = pipeline.clone();
        let fps = fps.clone();
        tokio::task::spawn_blocking(move || {
            let dec_ox =
                ThresholdTabulationTeller::combine_ox_fps_decryptions(&ctx, &fps, &ox_partials)?;
            let deduped = pipeline.filter_revotes_ox(&records, &fps, &dec_ox)?;
            Ok::<_, evoting::error::Error>((dec_ox, deduped))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("ox re-vote filtering failed: {e:?}")))?
    };
    let deduped = deduped_records.len();
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "re_encryption_proof",
            3,
            &ReEncryptionProofEntry::OxFingerprints {
                fps: fps.clone(),
                decryptions: dec_ox,
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    // §3.9 steps 4–5 + mix: verify the deduped ballots and mix the votes.
    let (vote_art, mut rng) = {
        let pipeline = pipeline.clone();
        tokio::task::spawn_blocking(move || {
            let originals = pipeline.verify_ballots(&deduped_records)?;
            let art = pipeline.mix_votes(&originals, &mut rng);
            pipeline.verify_vote_mix(&originals, &art)?;
            Ok::<_, evoting::error::Error>((art, rng))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("vote mix failed: {e:?}")))?
    };
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "mixed_ballots",
            3,
            &MixedBallotsEntry::Votes {
                artifact: Box::new(vote_art.clone()),
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    // §3.9 step 11: RT credential controls over the shuffled votes.
    let shuffled_votes: Vec<_> = vote_art.shuffled.iter().map(|r| r.vote.clone()).collect();
    let mut rts = Vec::with_capacity(cfg.rt_urls.len());
    for (i, url) in cfg.rt_urls.iter().enumerate() {
        let token = load_token_file(
            &cfg.ceremony_dir
                .join(format!("rt-{}-service-token.txt", i + 1)),
        )
        .await?;
        rts.push(RtClient::new(http.clone(), url.clone(), token));
    }
    let mut controls_r1 = Vec::with_capacity(rts.len());
    for rt in &rts {
        controls_r1.push(
            rt.controls_round1(&shuffled_votes)
                .await
                .map_err(|e| AdminError::Other(format!("RT controls round 1 failed: {e}")))?,
        );
    }
    let all_ids: Vec<usize> = controls_r1.iter().map(|b| b.from_id).collect();
    let mut controls_r2 = Vec::with_capacity(rts.len());
    for rt in &rts {
        controls_r2.push(
            rt.controls_round2(&controls_r1, &all_ids)
                .await
                .map_err(|e| AdminError::Other(format!("RT controls round 2 failed: {e}")))?,
        );
    }
    let controls = {
        let votes = shuffled_votes.clone();
        tokio::task::spawn_blocking(move || {
            evoting::api::server::rt::ThresholdRegistrationTeller::combine_controls(
                &votes,
                &controls_r1,
                &controls_r2,
            )
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
    };
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "re_encryption_proof",
            3,
            &ReEncryptionProofEntry::Controls {
                controls: controls.clone(),
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    // §3.9 steps 12–14: fresh ζ, threshold ACC checks, invalid-vote filter.
    let zeta = run_zeta_vss(&tts, "acc", cfg.t_tt).await?;
    let mut acc_partials = Vec::with_capacity(tts.len());
    for tt in &tts {
        acc_partials.push(
            tt.decrypt_acc_checks(&shuffled_votes, &controls, zeta)
                .await
                .map_err(|e| AdminError::Other(format!("TT acc-check decryption failed: {e}")))?,
        );
    }
    let (acc_checks, valid_votes) = {
        let ctx = election_context.clone();
        let pipeline = pipeline.clone();
        let votes = shuffled_votes.clone();
        let controls = controls.clone();
        let mixed = vote_art.shuffled.clone();
        tokio::task::spawn_blocking(move || {
            let acc_checks = ThresholdTabulationTeller::combine_acc_checks(
                &ctx,
                &votes,
                &controls,
                &acc_partials,
                zeta,
            )?;
            pipeline.verify_acc_checks(&acc_checks, &controls, &mixed, zeta)?;
            let valid = pipeline.filter_invalid(&mixed, &controls, &acc_checks, zeta)?;
            Ok::<_, evoting::error::Error>((acc_checks, valid))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("ACC check failed: {e:?}")))?
    };
    let valid = valid_votes.len();
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "re_encryption_proof",
            3,
            &ReEncryptionProofEntry::AccChecks {
                acc_checks: acc_checks.clone(),
                zeta,
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    // §3.9 steps 20–24: mix the eligible public credentials, fingerprint,
    // threshold-decrypt, and drop illicit votes (keep-last per credential).
    let short_accs: Vec<ShortPublicACC<RistrettoGroup>> = {
        let entries = wbb.entries().await.map_err(AdminError::Wbb)?;
        let mut found = None;
        for sequenced in &entries.entries {
            let Some(data_b64) = sequenced.entry.get("data").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(data) = BASE64.decode(data_b64) else {
                continue;
            };
            if let Some(parsed) = parse_wbb_data(&data) {
                if parsed.entry_type == "acc_pub_key" {
                    found = Some(parsed.decode_payload().map_err(|e| {
                        AdminError::Other(format!("acc_pub_key payload invalid: {e}"))
                    })?);
                }
            }
        }
        found.ok_or_else(|| AdminError::Other("no acc_pub_key entry on the WBB".into()))?
    };
    let mut eligible_shorts = Vec::with_capacity(eligible.vids.len());
    for vid in &eligible.vids {
        eligible_shorts.push(
            short_accs
                .get((vid.value() - 1) as usize)
                .cloned()
                .ok_or_else(|| {
                    AdminError::Other(format!("eligible vid {vid} has no public credential"))
                })?,
        );
    }

    let (cred_art, fps2) = {
        let pipeline = pipeline.clone();
        let shorts = eligible_shorts.clone();
        let valid_votes = valid_votes.clone();
        tokio::task::spawn_blocking(move || {
            let art = pipeline.mix_credentials(&shorts, &mut rng);
            pipeline.verify_cred_mix(&shorts, &art)?;
            let fps =
                pipeline.gen_credential_fingerprints(&shorts, &art, &valid_votes, &mut rng)?;
            Ok::<_, evoting::error::Error>((art, fps))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("credential mix failed: {e:?}")))?
    };
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "mixed_ballots",
            3,
            &MixedBallotsEntry::Credentials {
                artifact: Box::new(cred_art.clone()),
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    let mut fps_partials = Vec::with_capacity(tts.len());
    for tt in &tts {
        fps_partials.push(
            tt.decrypt_fps(&fps2)
                .await
                .map_err(|e| AdminError::Other(format!("TT fp decryption failed: {e}")))?,
        );
    }
    let (bundle, legitimate) = {
        let ctx = election_context.clone();
        let pipeline = pipeline.clone();
        let fps2 = fps2.clone();
        let cred_art = cred_art.clone();
        let valid_votes = valid_votes.clone();
        tokio::task::spawn_blocking(move || {
            let (dec_pub_fps, dec_votes_fps) =
                ThresholdTabulationTeller::combine_fps_decryptions(&ctx, &fps2, &fps_partials)?;
            let bundle = DecryptedFingerprintsBundle {
                dec_pub_fps,
                dec_votes_fps,
            };
            let legitimate = pipeline.filter_illicit_keep_last(
                &valid_votes,
                &cred_art,
                &fps2,
                &bundle.dec_pub_fps,
                &bundle.dec_votes_fps,
            )?;
            Ok::<_, evoting::error::Error>((bundle, legitimate))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("illicit filtering failed: {e:?}")))?
    };
    let legitimate_count = legitimate.len();
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "re_encryption_proof",
            3,
            &ReEncryptionProofEntry::CredentialFingerprints { fps: fps2, bundle },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    // §3.9 steps 25–29: homomorphic sum + threshold tally decryption.
    let enc_tally = {
        let pipeline = pipeline.clone();
        tokio::task::spawn_blocking(move || pipeline.homomorphic_sum(legitimate))
            .await
            .map_err(|e| AdminError::Other(e.to_string()))?
    };
    let mut tally_partials = Vec::with_capacity(tts.len());
    for tt in &tts {
        tally_partials.push(
            tt.decrypt_tally(&enc_tally)
                .await
                .map_err(|e| AdminError::Other(format!("TT tally decryption failed: {e}")))?,
        );
    }
    let (decrypted, counts) = {
        let ctx = election_context.clone();
        let pipeline = pipeline.clone();
        let enc_tally = enc_tally.clone();
        let n_acc = cfg.n_acc;
        tokio::task::spawn_blocking(move || {
            let table = DiscreteLogTable::new(0..=n_acc as u64);
            let decrypted = ThresholdTabulationTeller::combine_tally_decryptions(
                &ctx,
                &enc_tally,
                &table,
                &tally_partials,
            )?;
            pipeline.verify_decrypted_tally(&enc_tally, &decrypted)?;
            let counts = extract_counts(&decrypted)
                .map_err(|e| evoting::error::Error::Mismatch(e.to_string()))?;
            Ok::<_, evoting::error::Error>((decrypted, counts))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("tally decryption failed: {e:?}")))?
    };

    // §3.9 step 30: publish the proofs and the final counts.
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string(
            "tallying",
            "TT",
            "tally_proof",
            3,
            &TallyProofEntry {
                enc_tally,
                decrypted,
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;
    publish_tt_cosigned(
        &wbb,
        &tts,
        &wbb_data_string("tallying", "TT", "tally_result", 3, &counts)
            .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    tracing::info!(
        released,
        reconciled,
        deduped,
        valid,
        legitimate = legitimate_count,
        blank = counts.blank,
        si = counts.si,
        no = counts.no,
        "tally pipeline complete"
    );

    Ok(TallyOutcome {
        counts,
        released,
        reconciled,
        deduped,
        valid,
        legitimate: legitimate_count,
    })
}

/// Run one threshold ζ VSS session over every TT and finalize from the first
/// `t_tt` sub-shares (§3.9 steps 6–7).
async fn run_zeta_vss(
    tts: &[crate::clients::tt::TtClient],
    session: &str,
    t_tt: usize,
) -> Result<<RistrettoGroup as dlog_group::group::GroupScalar>::Scalar, AdminError> {
    use evoting::api::prelude::ThresholdTabulationTeller;

    let mut broadcasts = Vec::with_capacity(tts.len());
    for tt in tts {
        broadcasts.push(
            tt.zeta_round1(session)
                .await
                .map_err(|e| AdminError::Other(format!("ζ VSS round 1 failed: {e}")))?,
        );
    }
    let mut sub_shares = Vec::with_capacity(tts.len());
    for tt in tts {
        sub_shares.push(
            tt.zeta_combine(session, &broadcasts)
                .await
                .map_err(|e| AdminError::Other(format!("ζ VSS combine failed: {e}")))?,
        );
    }
    Ok(ThresholdTabulationTeller::<RistrettoGroup>::finalize_zeta(
        &sub_shares[..t_tt],
    ))
}

/// Publish one TT-co-signed entry: all TTs sign the same data with a shared
/// logical timestamp; the entry publishes once the WBB staging threshold
/// (t≥3) is met.
async fn publish_tt_cosigned(
    wbb: &WbbClient,
    tts: &[crate::clients::tt::TtClient],
    data: &str,
    clock: &mut LogicalClock,
) -> Result<(), AdminError> {
    use crate::clients::tt::TtClient;

    let timestamp = clock.now_ms() as i64;
    clock.advance();

    let mut entries = Vec::with_capacity(tts.len());
    for tt in tts {
        let response = tt
            .sign(data, timestamp)
            .await
            .map_err(|e| AdminError::Other(format!("TT co-signing failed: {e}")))?;
        entries.push(
            TtClient::to_signed_entry(data, &response)
                .map_err(|e| AdminError::Other(e.to_string()))?,
        );
    }
    for entry in &entries {
        wbb.submit(entry).await?;
    }

    // Poll until the staged entry reaches the threshold and is sequenced.
    let data_b64 = BASE64.encode(data.as_bytes());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Ok(entries) = wbb.entries().await {
            if entries.entries.iter().any(|e| {
                e.entry
                    .get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| s == data_b64)
                    .unwrap_or(false)
            }) {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(AdminError::Other(
                "co-signed tally entry was not included in time".to_string(),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Read a secret token file from the ceremony directory.
async fn load_token_file(path: &Path) -> Result<SecretString, AdminError> {
    let token = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| AdminError::Other(format!("failed to read token {}: {e}", path.display())))?
        .trim()
        .to_string();
    Ok(SecretString::new(token))
}

/// Publish a PM-signed `phase_transition` entry moving the WBB from `from` to
/// `to` (forward-only `setup → voting → tallying`, enforced by the WBB).
pub async fn transition_phase(
    cfg: PhaseTransitionConfig,
    from: &str,
    to: &str,
) -> Result<(), AdminError> {
    let pm_key = load_signing_key(&cfg.ceremony_dir.join("pm-signing-key.bin")).await?;
    let data = crate::protocol::voting::phase_transition_data_string(from, to);
    let mut clock = cfg.clock;
    let timestamp = clock.now_ms() as i64;
    clock.advance();
    let entry = sign_entry(data.as_bytes(), "PM-1", timestamp, &pm_key);

    let client = reqwest_client_trusting_ca(&cfg.ca_pem)?;
    let wbb = WbbClient::new(client, cfg.wbb_url.clone());
    wbb.submit_and_wait(&entry, std::time::Duration::from_secs(10))
        .await
        .map_err(|e| AdminError::Other(format!("phase transition rejected: {e}")))?;
    Ok(())
}
