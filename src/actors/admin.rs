//! Election-admin driver logic .
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
use crate::protocol::clock::Clock;
use crate::protocol::tls::reqwest_client_trusting_ca;

/// Configuration for the `gen-credentials` admin driver.
#[derive(Clone, Debug)]
pub struct GenCredentialsConfig {
    /// Directory containing ceremony artifacts (`election_context.json`,
    /// `rt_public_key.json`, `rt-*-share.json`, `rt-*-signing-key.bin`,
    /// `ca.pem`).
    pub ceremony_dir: std::path::PathBuf,
    /// Directory where the ER credential file and the per-RT share files are written.
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
    /// Clock for WBB timestamps (logical in tests, wall clock in real runs).
    pub clock: Clock,
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
    #[error(
        "the tally needs at least 2 distinct confirmed ballots to mix, found {deduped} \
         after reconciliation and the re-vote filter: mixing fewer would link a ballot to its vote"
    )]
    TooFewBallots { deduped: usize },
    #[error(
        "the tally needs at least 2 eligible credentials to mix, found {eligible}: \
         mixing fewer would link a credential to its voter"
    )]
    TooFewEligible { eligible: usize },
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

/// Write credential material as pretty JSON, owner-readable only.
async fn write_secret_json<T: serde::Serialize>(
    path: &std::path::Path,
    value: &T,
) -> Result<(), AdminError> {
    // Created owner-readable from the first byte (never world-readable, not
    // even briefly), then moved into place so a reader never sees half a file.
    let json = serde_json::to_string_pretty(value)?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    {
        use tokio::io::AsyncWriteExt;
        let mut file = options.open(&tmp).await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;
    }
    #[cfg(unix)]
    {
        // An existing tmp file keeps its old mode: enforce it explicitly too.
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Run the credential-generation driver.
///
/// 1. Reconstruct all RT tellers from share files.
/// 2. Generate `n_acc` credentials and the public ACC list.
/// 3. Co-sign the `setup,RT,acc_pub_key,2,...` WBB entry (via RT `/sign`
///    endpoints when configured, otherwise locally).
/// 4. Submit the partial signatures to the WBB and wait for inclusion.
/// 5. Write the ER's credential file and one share file per RT to `output_dir`.
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

    // Deterministic RNG seeded from the RT operation seeds, decoupled
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

    // Build the WBB data string and sign it.
    let data_string = build_acc_pub_key_data_string(&short_accs)?;
    let mut clock = cfg.clock;
    let signed_entries =
        sign_acc_pub_key_entries(&cfg, &data_string, &signing_key_seeds, &mut clock).await?;

    // Submit all partial signatures to the WBB - unless an earlier run already
    // got this very entry published and then died before writing the share
    // files. Generation is deterministic, so the rerun rebuilds the identical
    // entry: adopt the published one and go on to write the files, instead of
    // being refused as a duplicate (or sequencing it a second time).
    let wbb_client = build_wbb_client(&cfg).await?;
    let data_b64 = BASE64.encode(&signed_entries[0].data);
    let already_published = wbb_client.entries().await?.entries.iter().any(|e| {
        e.entry
            .get("data")
            .and_then(|v| v.as_str())
            .map(|s| s == data_b64)
            .unwrap_or(false)
    });
    if !already_published {
        for entry in &signed_entries {
            match wbb_client.submit(entry).await {
                Ok(_) => {}
                // 409: this signer's part is already staged (or the entry is
                // already published) by an earlier run that died half-way.
                // The entry is identical, so carry on to the wait loop.
                Err(crate::clients::wbb::WbbError::Http(status, _))
                    if status == reqwest::StatusCode::CONFLICT => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    // Wait until the entry is included (do not resubmit: it is already staged).
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

    // Only now that the public ACCs are on the bulletin board is the secret
    // material written: a failed publication leaves no usable shares behind.
    // Split the credential material by recipient (Sec. 3.5.4): the ER gets
    // `A` and `E[A]` only, and each registration teller gets a file with ITS
    // OWN shares. No file ever holds two tellers' shares, so no single
    // service can rebuild a credential or a PIN.
    tokio::fs::create_dir_all(&cfg.output_dir).await?;
    // A file from an older layout held every teller's shares: remove it.
    match tokio::fs::remove_file(cfg.output_dir.join("enrollment_packages.json")).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let er_view: Vec<crate::protocol::acc::CredentialPackage> = packages
        .iter()
        .map(crate::protocol::acc::EnrollmentPackage::credential_package)
        .collect();
    write_secret_json(
        &cfg.output_dir
            .join(crate::protocol::acc::ER_CREDENTIALS_FILE),
        &er_view,
    )
    .await?;
    let mut rt_ids: Vec<usize> = packages.iter().flat_map(|p| p.rt_ids()).collect();
    rt_ids.sort_unstable();
    rt_ids.dedup();
    for rt_id in rt_ids {
        let shares: Vec<crate::protocol::acc::RtCredentialShare> = packages
            .iter()
            .map(|p| {
                p.rt_share(rt_id).ok_or_else(|| {
                    AdminError::Other(format!("RT-{rt_id} holds no share of a credential"))
                })
            })
            .collect::<Result<_, _>>()?;
        write_secret_json(
            &cfg.output_dir
                .join(crate::protocol::acc::rt_shares_file(rt_id)),
            &shares,
        )
        .await?;
    }
    drop(packages);

    tracing::info!(
        n_acc = cfg.n_acc,
        output_dir = %cfg.output_dir.display(),
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

/// The registration tellers' published control key shares (Sec. 3.9 step 15).
async fn load_rt_control_shares(
    ceremony_dir: &Path,
) -> Result<Vec<crate::protocol::tally::TellerPublicShare>, AdminError> {
    let path = ceremony_dir.join("rt-public-shares.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| AdminError::Other(format!("failed to read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AdminError::Other(format!("{} is unreadable: {e}", path.display())))
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
    clock: &mut Clock,
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

/// Configuration for a PM phase transition (Sec. 3.4.2).
#[derive(Clone, Debug)]
pub struct PhaseTransitionConfig {
    /// Directory containing `pm-signing-key.bin`.
    pub ceremony_dir: std::path::PathBuf,
    /// WBB log base URL.
    pub wbb_url: Url,
    /// Cluster CA PEM for TLS.
    pub ca_pem: String,
    /// Clock for the entry timestamp.
    pub clock: Clock,
}

// -- Tally driver (Sec. 3.9) ---------

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
    /// TT base URLs in `tt-1..n` order (zeta VSS, threshold decryptions, co-signing).
    pub tt_urls: Vec<Url>,
    /// Cluster CA PEM for TLS.
    pub ca_pem: String,
    /// Clock for WBB timestamps (logical in tests, wall clock in real runs).
    pub clock: Clock,
    /// Number of generated credentials (`n_acc`) - bounds the dlog table.
    pub n_acc: usize,
    /// TT reconstruction threshold (`t_tt`) for zeta finalization.
    pub t_tt: usize,
    /// RT reconstruction threshold (`t_rt`): how many valid credential-control
    /// shares the step needs (Sec. 3.9 steps 16-17).
    pub t_rt: usize,
    /// Ballot boxes (by id) the operator has decided to tally without when
    /// they give no release: a box named here no longer stops the tally
    /// (Sec. 3.9 step 4). Empty by default.
    pub proceed_without: Vec<u64>,
}

/// Outcome of a tally run: the counts plus the per-stage cardinalities.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct TallyOutcome {
    pub counts: crate::protocol::tally::TallyCounts,
    /// Ballots released across all BBs (with duplicates).
    pub released: usize,
    /// Reconciled ballots after the bot filter (Sec. 3.8.5).
    pub reconciled: usize,
    /// Ballots after ox re-vote dedup (Sec. 3.9 step 10).
    pub deduped: usize,
    /// Votes surviving the ACC check (Sec. 3.9 step 22).
    pub valid: usize,
    /// Votes whose credential is an authorised one (Sec. 3.9 step 27).
    pub legitimate: usize,
}

/// Fewest elements a verifiable mix can hide one among (ballots in the vote
/// mix, credentials in the credential mix).
pub const MIN_MIXABLE_BALLOTS: usize = 2;

/// The log key the ceremony pinned, and the name the board must sign under.
async fn load_pinned_log_key(
    ceremony_dir: &std::path::Path,
) -> Result<p256::ecdsa::VerifyingKey, AdminError> {
    let pinned = tokio::fs::read_to_string(
        ceremony_dir.join(crate::protocol::setup::artifacts::WBB_LOG_PUBLIC_KEY_FILE),
    )
    .await
    .map_err(|e| AdminError::Other(format!("pinned log key: {e}")))?;
    crate::protocol::tlog::log_key_from_base64(&pinned)
        .map_err(|e| AdminError::Other(format!("pinned log key: {e}")))
}

/// The board's entries, as far as a tree head signed by the PINNED key covers
/// them. Nothing this driver reads from the board is taken on trust.
///
/// A head can lag a little behind sequencing, so an entry this driver has
/// just seen may not be covered yet; it waits for a head that covers
/// everything served rather than working from a shorter prefix (which would
/// silently leave a ballot out of the cast order).
async fn verified_entries(
    wbb: &WbbClient,
    log_key: &p256::ecdsa::VerifyingKey,
) -> Result<Vec<(i64, serde_json::Value)>, AdminError> {
    let log_origin = crate::protocol::tlog::log_origin_of(wbb.base_url());
    let mut last_gap = 0usize;
    for attempt in 0..10 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let checkpoint = wbb.checkpoint().await?;
        let entries = wbb.entries_raw().await?.entries;
        let covered =
            crate::actors::auditor::verify_log(log_key, &log_origin, &checkpoint, &entries)
                .map_err(|e| {
                    AdminError::Other(format!("the bulletin board log does not verify: {e}"))
                })?
                .leaves
                .len();
        last_gap = entries.len().saturating_sub(covered);
        if last_gap > 0 {
            continue;
        }
        return entries
            .into_iter()
            .map(|sequenced| {
                serde_json::from_str(sequenced.entry.get())
                    .map(|value| (sequenced.leaf_index, value))
                    .map_err(|e| AdminError::Other(format!("leaf is not JSON: {e}")))
            })
            .collect();
    }
    Err(AdminError::Other(format!(
        "the bulletin board's signed tree head still does not cover {last_gap} of the entries \
         it serves"
    )))
}

/// The order the bulletin board recorded for the ballots, read from a log
/// this driver has VERIFIED itself.
///
/// The position of a ballot is the leaf of its first acceptance (a
/// `ballot_digest` entry signed by the box it names) - never the `seq_no` a
/// ballot box mints for itself, which that box could choose so that an
/// earlier ballot of a voter beats their re-vote (Sec. 3.9 step 10).
fn board_cast_order(
    entries: &[(i64, serde_json::Value)],
) -> std::collections::HashMap<crate::domain::BallotDigest, u64> {
    use crate::protocol::voting::{parse_wbb_data, signed_by_ballot_box, BallotDigestEntry};
    use base64::Engine as _;

    let mut accepted = Vec::new();
    for (leaf_index, entry) in entries {
        let Some(parsed) = entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .and_then(|data| parse_wbb_data(&data))
        else {
            continue;
        };
        if parsed.entry_type != "ballot_digest" {
            continue;
        }
        let Ok(payload) = parsed.decode_payload::<BallotDigestEntry>() else {
            continue;
        };
        if signed_by_ballot_box(entry, payload.receipt.bb_id) {
            accepted.push(((*leaf_index).max(0) as u64, payload.digest));
        }
    }
    crate::protocol::tally::board_cast_order(accepted)
}

/// Run the full Sec. 3.9 tally pipeline over HTTPS.
/// How many times a ballot box's release is asked for before the box is
/// named silent (pauses of 0.5, 1, 2, 4 s in between).
const RELEASE_ATTEMPTS: u32 = 5;

/// How long a box that answers "release in preparation" is waited for.
const RELEASE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(3600);

pub async fn run_tally(cfg: TallyConfig) -> Result<TallyOutcome, AdminError> {
    use crate::clients::bb::BbClient;
    use crate::clients::er::ErClient;
    use crate::clients::tt::TtClient;
    use crate::protocol::tally::{
        order_by_board, partials_are_the_tellers, reconcile_ballots, tally_rng_from_seeds,
        teller_shares_bind_to_master, valid_disclosures, EncryptedBallotEntry, MixedBallotsEntry,
        ReEncryptionProofEntry, TellerPublicShare,
    };
    use crate::protocol::voting::{parse_wbb_data, wbb_data_string};
    use evoting::api::prelude::{
        DecryptedFingerprintsBundle, ShortPublicACC, ThresholdTabulationTeller,
    };
    use evoting::api::server::bb::{PublicElection, PublicPipeline};

    let election_context = load_election_context(&cfg.ceremony_dir).await?;
    let http = reqwest_client_trusting_ca(&cfg.ca_pem)?;
    let wbb = WbbClient::new(http.clone(), cfg.wbb_url.clone());
    let mut clock = cfg.clock;

    // Sec. 3.9 step 1: the tally runs strictly inside the tallying phase.
    let phase = wbb
        .phase()
        .await
        .map_err(|e| AdminError::Other(format!("WBB phase query failed: {e}")))?;
    if phase != "tallying" {
        return Err(AdminError::Other(format!(
            "tally requires the tallying phase, WBB is in {phase}"
        )));
    }

    // Everything this driver needs from the board is checked BEFORE the first
    // publication, and every tally artifact is held back until the pipeline
    // has succeeded: the board is append-only, so a failure after it has
    // started publishing could not be undone, and a retry would leave a
    // second copy of a once-only artifact behind.
    let pinned_log = load_pinned_log_key(&cfg.ceremony_dir).await?;
    let already = verified_entries(&wbb, &pinned_log).await?;

    // The board is append-only and the tally's artifacts are once-only: a
    // second run would publish a duplicate and make an honest election
    // unauditable for good. A tally artifact already on the board therefore
    // means one of two things: the tally is complete (a result is there),
    // and this run stops before touching anything; or a previous run of
    // THIS driver was cut off while submitting its signed artifacts, and
    // this run finishes that submission from the outbox it saved, publishing
    // nothing that is not already signed. Anything else - artifacts on the
    // board that no saved outbox accounts for - is refused.
    let published_tally: Vec<(i64, String, String)> = already
        .iter()
        .filter_map(|(leaf, entry)| {
            let data_b64 = entry.get("data")?.as_str()?;
            let parsed = parse_wbb_data(&BASE64.decode(data_b64).ok()?)?;
            GUARDED_TALLY_ENTRY_TYPES
                .contains(&parsed.entry_type.as_str())
                .then(|| (*leaf, parsed.entry_type, data_b64.to_string()))
        })
        .collect();
    if let Some((leaf, _, _)) = published_tally
        .iter()
        .find(|(_, entry_type, _)| entry_type == "tally_result")
    {
        return Err(AdminError::Other(format!(
            "this election has already been tallied (entry {leaf} on the bulletin board); \
             a second run would publish duplicates of once-only artifacts"
        )));
    }
    // A submission of THIS driver's making that was cut off part-way is
    // finished; anything else on the board that a run of it would have
    // written is refused. A release entry alone is not enough to refuse on
    // (any single ballot box may write one, and one box must not be able to
    // block the tally), so the saved outbox decides.
    let saved = load_saved_tally(&cfg.ceremony_dir).await?;
    let on_board: std::collections::HashSet<&str> = already
        .iter()
        .filter_map(|(_, entry)| entry.get("data")?.as_str())
        .collect();
    let resumable = saved.as_ref().filter(|saved| {
        saved
            .outbox
            .iter()
            .any(|pending| on_board.contains(BASE64.encode(pending.data.as_bytes()).as_str()))
    });
    if let Some(saved) = resumable {
        // The saved tally must be THIS board's: same pinned log key, and every
        // artifact of it sequenced after the tree the pipeline ran on.
        if saved.log_key != log_key_fingerprint(&pinned_log)
            || published_tally
                .iter()
                .any(|(leaf, _, _)| *leaf < saved.tree_size)
        {
            return Err(AdminError::Other(
                "the saved tally was not made for this bulletin board: refusing to resume it"
                    .into(),
            ));
        }
        let known: std::collections::HashSet<String> = saved
            .outbox
            .iter()
            .map(|pending| BASE64.encode(pending.data.as_bytes()))
            .collect();
        if let Some((leaf, entry_type, _)) = published_tally
            .iter()
            .find(|(_, _, data)| !known.contains(data))
        {
            return Err(AdminError::Other(format!(
                "the bulletin board holds a tally artifact ({entry_type}, entry {leaf}) that \
                 the saved tally did not produce: refusing to add to it"
            )));
        }
        if saved.complete {
            tracing::warn!(
                published = published_tally.len(),
                total = saved.outbox.len(),
                "resuming the submission of a tally cut off part-way"
            );
            // The remaining artifacts are signed AGAIN, with fresh timestamps:
            // the board refuses a timestamp outside its window, and a cut-off
            // submission may be resumed long after the first run.
            let outbox = resign_pending(&cfg, &http, &saved.outbox, &already, &mut clock).await?;
            flush_publications(
                &wbb,
                &outbox,
                &already,
                &cfg.ceremony_dir,
                saved.release_cut,
            )
            .await?;
            return Ok(saved.outcome);
        }
        // Cut off BEFORE the tally decryption. Everything the tail needs is
        // already on the board, so it finishes on its own. The pipeline is
        // NOT run again: only the driver's RNG is deterministic, while the
        // TELLERS' proof nonces advance, so a second run produces different
        // proofs and the flush would put a second copy of each on a board
        // that cannot take one back.
        tracing::warn!(
            published = published_tally.len(),
            "a tally was cut off before its result: finishing it from the board"
        );
        let tt_keys = load_verifying_keys(&cfg.ceremony_dir, "tt", cfg.tt_urls.len()).await?;
        let mut tts = Vec::with_capacity(cfg.tt_urls.len());
        for (i, url) in cfg.tt_urls.iter().enumerate() {
            let token = load_token_file(
                &cfg.ceremony_dir
                    .join(format!("tt-{}-service-token.txt", i + 1)),
            )
            .await?;
            tts.push(TtClient::new(http.clone(), url.clone(), token));
        }
        let outbox = resign_pending(&cfg, &http, &saved.outbox, &already, &mut clock).await?;
        // The artifacts this run did not manage to send go FIRST: the tail
        // recomputes the sum from the board, so a flush cut off part-way must
        // be finished before it looks. Without this a single lost submission
        // strands the election for good - the board is append-only and the
        // pipeline cannot be re-run over it.
        flush_publications(
            &wbb,
            &outbox,
            &already,
            &cfg.ceremony_dir,
            saved.release_cut,
        )
        .await?;
        let outcome = saved.outcome;
        return finish_tally(
            FinishTally {
                cfg: &cfg,
                http: &http,
                wbb: &wbb,
                tts: &tts,
                tt_keys: &tt_keys,
                election_context: &election_context,
                pinned_log: &pinned_log,
                already: &already,
            },
            outbox,
            outcome,
            &mut clock,
        )
        .await;
    } else if let Some((leaf, entry_type, _)) = published_tally.first() {
        return Err(AdminError::Other(format!(
            "the bulletin board already holds a tally artifact ({entry_type}, entry {leaf}) \
             and this driver has no record of publishing it: refusing to add to it"
        )));
    }

    // Sec. 3.9 step 1: ER publishes the eligible vid list (minus revoked).
    let er_admin_token = load_token_file(&cfg.ceremony_dir.join("er-admin-token.txt")).await?;
    let er = ErClient::new(http.clone(), cfg.er_url.clone());
    let eligible = er
        .publish_eligible_vids(&er_admin_token)
        .await
        .map_err(|e| AdminError::Other(format!("eligible-vid publication failed: {e}")))?;
    // The credential mix has the same floor as the vote mix: refuse now,
    // before ballots are released and mixed, rather than deep in the tally.
    // (The eligible list itself is already on the board at this point.)
    if eligible.vids.len() < MIN_MIXABLE_BALLOTS {
        return Err(AdminError::TooFewEligible {
            eligible: eligible.vids.len(),
        });
    }

    // Sec. 3.9 step 2: fetch every BB's ballots. A box that does not answer,
    // or answers nonsense, releases NOTHING and is named. Whether the tally
    // may go on without it is decided below, once the board shows whether a
    // counted ballot is missing; only when no box answers at all is there
    // nothing to tally.
    // The operator names boxes by id: an id that is no box is a mistake,
    // not a choice.
    if let Some(bb) = cfg
        .proceed_without
        .iter()
        .find(|bb| **bb == 0 || **bb as usize > cfg.bb_urls.len())
    {
        return Err(AdminError::Other(format!(
            "--proceed-without names BB-{bb}, which is not a ballot box of this election"
        )));
    }
    let mut per_bb = Vec::with_capacity(cfg.bb_urls.len());
    let mut release_keys = Vec::with_capacity(cfg.bb_urls.len());
    let mut silent_boxes = Vec::new();
    let mut silent_ids: Vec<u64> = Vec::new();
    for (i, url) in cfg.bb_urls.iter().enumerate() {
        let name = format!("bb-{}", i + 1);
        let token =
            load_token_file(&cfg.ceremony_dir.join(format!("{name}-service-token.txt"))).await?;
        let bb = BbClient::new(http.clone(), url.clone());
        let bb_id = (i + 1) as u64;
        // A failed release is asked again, with growing pauses: an honest
        // box answers 503 when its board read was lost, and taking that for
        // an empty release would drop every ballot only it holds.
        let mut attempt = 0u32;
        let preparing_since = std::time::Instant::now();
        let mut records = loop {
            match bb.ballots(&token).await {
                Ok(records) => break records,
                // A box still preparing its release is waited for, without
                // spending an attempt, up to RELEASE_PATIENCE - even one the
                // operator named in `proceed_without`: it is alive, and its
                // release may hold ballots no other box has.
                Err(crate::clients::bb::BbError::ReleasePreparing)
                    if preparing_since.elapsed() < RELEASE_PATIENCE =>
                {
                    if cfg.proceed_without.contains(&bb_id) {
                        tracing::info!(
                            ballot_box = %name,
                            waited_s = preparing_since.elapsed().as_secs(),
                            "a box named to proceed without is still preparing its release; \
                             waiting for it, up to the release patience"
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(e) if attempt + 1 < RELEASE_ATTEMPTS => {
                    tracing::warn!(ballot_box = %name, attempt, "release failed, asking again: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(500 << attempt)).await;
                    attempt += 1;
                }
                Err(e) => {
                    tracing::warn!(ballot_box = %name, "no release from this box: {e}");
                    silent_boxes.push(format!("{}: {e}", name.to_uppercase()));
                    silent_ids.push(bb_id);
                    break Vec::new();
                }
            }
        };
        // A ballot box speaks for itself only: a record whose receipt names
        // another box is dropped here (the auditor reports such a release).
        records.retain(|record| record.receipt.bb_id == bb_id);
        release_keys.push((
            name.to_uppercase(),
            load_signing_key(&cfg.ceremony_dir.join(format!("{name}-signing-key.bin"))).await?,
        ));
        per_bb.push(records);
    }
    if silent_boxes.len() == cfg.bb_urls.len() {
        return Err(AdminError::Other(format!(
            "no ballot box released anything ({})",
            silent_boxes.join("; ")
        )));
    }

    // What the BOARD says counts (Sec. 3.9 steps 3 and 5, Sec. 3.10
    // 1(c)-(d)): a ballot whose digest at least one box published during
    // voting, for which at least one box published a disclosure that OPENS
    // on the released ballot. Any box's release will do (A9: one honest box
    // suffices). A ballot the board counts that no box released was held
    // back by every box that published its digest - or its confirmation was
    // made up by the box that published it; either way those boxes are named
    // and the tally goes on without it (Sec. 3.9 step 4 attributes exactly
    // this). A box whose published disclosure does not open is named too.
    let board_entries = verified_entries(&wbb, &pinned_log).await?;
    let board = crate::protocol::tally::board_ballots(&board_entries);
    // Sec. 3.9 step 2: each box "sends to the WBB the remaining ballots". A
    // release a box wrote to the board itself is part of the tally input as
    // surely as one it answered with - the auditor counts it either way, so
    // a box that withholds a ballot from the driver and then writes it to the
    // board must not make a correct tally fail its audit. Its first copy on
    // the board stands for that box (later ones are named by the auditor),
    // and the driver does not publish the ballot again. Everything released
    // past this reading is checked for before the tally starts (see
    // `flush_publications`).
    let release_cut = board_entries
        .iter()
        .map(|(leaf, _)| *leaf + 1)
        .max()
        .unwrap_or(0);
    let mut from_board: std::collections::HashSet<(crate::domain::BallotDigest, u64)> =
        std::collections::HashSet::new();
    for release in crate::protocol::tally::board_releases(&board_entries) {
        let Ok(digest) = crate::protocol::voting::ballot_digest(&release.record.ballot) else {
            continue;
        };
        let Some(records) = (release.bb_id as usize)
            .checked_sub(1)
            .and_then(|i| per_bb.get_mut(i))
        else {
            continue;
        };
        if !board.publishers.contains_key(&digest) || !from_board.insert((digest, release.bb_id)) {
            continue;
        }
        records.retain(|r| crate::protocol::voting::ballot_digest(&r.ballot).ok() != Some(digest));
        records.push(release.record);
    }
    let mut released_ballots: std::collections::HashMap<
        crate::domain::BallotDigest,
        evoting::api::prelude::Ballot<RistrettoGroup>,
    > = std::collections::HashMap::new();
    for record in per_bb.iter().flatten() {
        if let Ok(digest) = crate::protocol::voting::ballot_digest(&record.ballot) {
            // Only records whose digest a box published during voting are
            // judged here - the same set the auditor judges (Sec. 3.9 step 3
            // links a release to a published digest). A record released out
            // of nowhere changes nothing and is not narrated.
            if !board.publishers.contains_key(&digest) {
                continue;
            }
            released_ballots
                .entry(digest)
                .or_insert_with(|| record.ballot.clone());
        }
    }
    let disclosures = {
        let released = released_ballots.clone();
        let confirmations = board.confirmations.clone();
        let ctx = election_context.clone();
        tokio::task::spawn_blocking(move || valid_disclosures(&released, &confirmations, &ctx))
            .await
            .map_err(|e| AdminError::Other(e.to_string()))?
    };
    for note in disclosures
        .misconduct
        .iter()
        .chain(&disclosures.unaccounted)
    {
        tracing::warn!("{note}");
    }
    // A released record whose proofs do not verify is not a ballot: it is
    // neither counted nor "revealed" (Sec. 3.9 step 5 discards it), and the
    // audit names the box that released it.
    for digest in &disclosures.not_ballots {
        tracing::warn!(%digest, "a released record is not a ballot - its proofs do not verify");
    }
    for note in &disclosures.revealed {
        tracing::error!("{note}");
    }
    let counted: std::collections::HashSet<crate::domain::BallotDigest> = board
        .counted
        .iter()
        .filter(|digest| disclosures.valid.contains(digest))
        .copied()
        .collect();
    // A failed release is never taken for an empty one. A ballot the board
    // counts that no box released may be in the hands of a box that did not
    // answer - whether or not that box published its digest (a box holds
    // every ballot it was cast, published or not). Publishing the result now
    // would drop it silently, so the tally stops, naming the silent boxes,
    // and is run again once they answer (Sec. 3.9 steps 2-3; A9 gives one
    // honest box, not one that is always reachable). A box that stays silent
    // for good - possibly having published a digest it never means to
    // release - cannot hold the result hostage either: the operator runs the
    // tally again naming it in `proceed_without`, and the tally goes on
    // without it, saying so (Sec. 3.9 step 4: the misbehaving box is named
    // and the procedure continues).
    let missing: Vec<&crate::domain::BallotDigest> = board
        .counted
        .iter()
        .filter(|digest| !released_ballots.contains_key(digest))
        .collect();
    let blocking: Vec<u64> = silent_ids
        .iter()
        .copied()
        .filter(|bb| !cfg.proceed_without.contains(bb))
        .collect();
    if !missing.is_empty() && !blocking.is_empty() {
        let names: Vec<String> = blocking.iter().map(|bb| format!("BB-{bb}")).collect();
        // For each missing ballot, everything the operator needs to choose
        // whom to proceed without: who published it, who confirmed it, and
        // every silent box - any of which may hold it, published or not. A
        // box that answered without releasing it either withheld it or holds
        // a confirmation that was never the voter's (any box can sign one),
        // so it is not called the withholder outright (Sec. 3.9 step 4).
        let named = |boxes: &[u64]| -> String {
            if boxes.is_empty() {
                "none".to_string()
            } else {
                boxes
                    .iter()
                    .map(|bb| format!("BB-{bb}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };
        let digests: Vec<String> = missing
            .iter()
            .map(|digest| {
                let publishers = board.publishers.get(*digest).cloned().unwrap_or_default();
                let mut confirmers: Vec<u64> = board
                    .confirmations
                    .iter()
                    .filter(|c| c.digest == **digest)
                    .map(|c| c.bb_id)
                    .collect();
                confirmers.sort_unstable();
                confirmers.dedup();
                let answered: Vec<u64> = publishers
                    .iter()
                    .copied()
                    .filter(|bb| !silent_ids.contains(bb))
                    .collect();
                let not_released = if answered.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; not released by {} although it answered - withheld, or confirmed \
                         without the voter",
                        named(&answered)
                    )
                };
                format!(
                    "{digest} (published by {}; confirmed by {}; may be held by the silent \
                     {}{not_released})",
                    named(&publishers),
                    named(&confirmers),
                    named(&blocking)
                )
            })
            .collect();
        return Err(AdminError::Other(format!(
            "the release is incomplete: {} counted ballot(s) were released by no box ({}) \
             while {} did not answer; nothing was published - run the tally again once \
             the ballot boxes answer, or name the boxes to proceed without",
            missing.len(),
            digests.join("; "),
            names.join(", ")
        )));
    }
    for bb in silent_ids
        .iter()
        .filter(|bb| cfg.proceed_without.contains(bb))
    {
        tracing::warn!(
            ballot_box = %format!("BB-{bb}"),
            missing = %missing
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            "the tally proceeds without this box at the operator's request; \
             a counted ballot no box released is not counted"
        );
    }
    for digest in board
        .counted
        .iter()
        .filter(|d| !released_ballots.contains_key(d))
    {
        let publishers: Vec<String> = board
            .publishers
            .get(digest)
            .map(|boxes| boxes.iter().map(|bb| format!("BB-{bb}")).collect())
            .unwrap_or_default();
        tracing::warn!(
            %digest,
            "published and confirmed on the board but released by NO box: withheld by {} \
             (or its confirmation was never the voter's); not counted",
            publishers.join(", ")
        );
    }

    // Every tally artifact from here on is signed as the pipeline produces it
    // and submitted to the board only once the whole pipeline has succeeded
    // (see `PendingPublication`).
    let mut outbox: Vec<PendingPublication> = Vec::new();

    // The per-BB releases, each record signed with that BB's own key.
    for (i, (records, (entity_id, signing_key))) in per_bb.iter().zip(&release_keys).enumerate() {
        for record in records {
            // Already on the board, written by the box itself.
            if crate::protocol::voting::ballot_digest(&record.ballot)
                .is_ok_and(|digest| from_board.contains(&(digest, (i + 1) as u64)))
            {
                continue;
            }
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
            let entry = sign_entry(data.as_bytes(), entity_id, timestamp, signing_key);
            outbox.push(PendingPublication {
                entries: vec![entry],
                data,
                signer: Signer::BallotBox {
                    entity_id: entity_id.clone(),
                },
            });
        }
    }
    let released: usize = per_bb.iter().map(Vec::len).sum();

    // The cast order comes from the BOARD - the leaf each ballot's first
    // acceptance was published at - never from the sequence numbers the
    // ballot boxes mint for themselves (Sec. 3.9 step 10).
    let board_order = board_cast_order(&board_entries);
    let per_bb = per_bb
        .into_iter()
        .map(|records| order_by_board(records, &board_order))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AdminError::Other(e.to_string()))?;

    // Design lock (a): reconcile by digest - the Sec. 3.8.5 bot filter.
    let records = tokio::task::spawn_blocking(move || reconcile_ballots(&per_bb, &counted))
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Other(format!("ballot reconciliation failed: {e}")))?;
    let reconciled = records.len();
    // Fail early when there is obviously nothing to mix (the exact check,
    // after the re-vote filter, follows below).
    if reconciled < MIN_MIXABLE_BALLOTS {
        return Err(AdminError::TooFewBallots {
            deduped: reconciled,
        });
    }

    // Deterministic driver RNG for mixes and fingerprint blinding.
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
    // The permutation, the re-encryption randomness and the shuffle
    // argument's commitment randomness all come from this stream. Under the
    // reproducible logical clock it is a function of the tellers' seeds; on a
    // real run it is fresh from the operating system, so nobody who holds the
    // seed files can recompute a published permutation and a re-run over a
    // different released set never replays a stream (see README row 14).
    let rng = match cfg.clock.mode() {
        crate::protocol::clock::ClockMode::Wall => {
            use rand::SeedableRng as _;
            rand_chacha::ChaCha20Rng::from_entropy()
        }
        crate::protocol::clock::ClockMode::Logical => tally_rng_from_seeds(&tt_seeds),
    };

    // The tellers' verifying keys, pinned at the ceremony: every
    // co-signature is checked against them before it is queued.
    let tt_keys = load_verifying_keys(&cfg.ceremony_dir, "tt", cfg.tt_urls.len()).await?;
    let rt_keys = load_verifying_keys(&cfg.ceremony_dir, "rt", cfg.rt_urls.len()).await?;

    // The tellers' PUBLIC key shares travel in the election context
    // (`pk.params.tellers`) and are published once more on their own
    // (`tt_public_shares`, exactly one entry): both must agree and every
    // t_TT of them must interpolate to the election key. Every partial
    // decryption a teller returns is then held to ITS share by the library
    // (Protocol 12 proves a share against the shared key, not against a key
    // the prover names).
    let published_shares: Vec<TellerPublicShare> = {
        let mut found: Vec<Vec<TellerPublicShare>> = Vec::new();
        for (_, entry) in &board_entries {
            let Some(parsed) = entry
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(|b64| BASE64.decode(b64).ok())
                .and_then(|data| parse_wbb_data(&data))
            else {
                continue;
            };
            if parsed.entry_type == "tt_public_shares" {
                found.push(parsed.decode_payload().map_err(|e| {
                    AdminError::Other(format!("tt_public_shares payload invalid: {e}"))
                })?);
            }
        }
        match found.len() {
            1 => found.remove(0),
            0 => {
                return Err(AdminError::Other(
                    "no tt_public_shares entry on the bulletin board".into(),
                ))
            }
            n => {
                return Err(AdminError::Other(format!(
                    "{n} tt_public_shares entries on the bulletin board, expected one"
                )))
            }
        }
    };
    teller_shares_bind_to_master(
        &published_shares,
        &election_context.pk.params.tally.h,
        cfg.tt_urls.len(),
        cfg.t_tt,
    )
    .map_err(|e| AdminError::Other(format!("published teller shares refused: {e}")))?;
    let tellers = &election_context.pk.params.tellers;
    if tellers.t != cfg.t_tt
        || tellers.n() != cfg.tt_urls.len()
        || published_shares
            .iter()
            .any(|share| tellers.share_of(share.id) != Some(&share.h))
    {
        return Err(AdminError::Other(
            "the published teller shares do not match the election context's".into(),
        ));
    }

    // TT clients (zeta VSS, decryptions, co-signing).
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

    // Sec. 3.9 steps 5-10: verify ballots, blind the re-vote handles with the
    // tellers' zeta* shares (nobody holds zeta*), threshold-decrypt, and
    // dedup re-votes (last cast wins).
    let (ox_encs, records, mut rng) = {
        let pipeline = pipeline.clone();
        tokio::task::spawn_blocking(move || {
            let ox_encs = pipeline.ox_ciphertexts(&records)?;
            Ok::<_, evoting::error::Error>((ox_encs, records, rng))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("ballot verification failed: {e:?}")))?
    };
    let fps = run_threshold_blinding(
        &tts,
        "ox",
        "ox",
        &pipeline,
        std::slice::from_ref(&ox_encs),
        &election_context,
    )
    .await?;
    let mut ox_answers = Vec::with_capacity(tts.len());
    for tt in &tts {
        ox_answers.push(
            tt.decrypt_ox(&fps, std::slice::from_ref(&ox_encs))
                .await
                .map_err(|e| e.to_string()),
        );
    }
    let ox_partials = accept_teller_partials(
        "ox fingerprint decryption",
        ox_answers,
        |id, partials| {
            partials_are_the_tellers(id, partials, &fps.fp_lists[0], &election_context.pk.params)
        },
        |partials| vec![partials.len()],
        cfg.t_tt,
    )?;
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
    // A verifiable mix of fewer than two ballots is not a mix: a single
    // ballot would be trivially linked to its vote. Refuse with a clear
    // message rather than failing deep inside the shuffle proof.
    if deduped < MIN_MIXABLE_BALLOTS {
        return Err(AdminError::TooFewBallots { deduped });
    }
    queue_tt_cosigned(
        &mut outbox,
        &tts,
        &tt_keys,
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

    // Sec. 3.9 steps 5 and 11-13: verify the deduped ballots, trim and mix the votes.
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
    queue_tt_cosigned(
        &mut outbox,
        &tts,
        &tt_keys,
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

    // Sec. 3.9 steps 14-19: RT credential controls over the shuffled votes.
    // The mixed votes carry nothing of the ballot they came from (Sec. 3.9
    // step 11): from here on nothing is ordered, only kept or discarded.
    let shuffled_votes = vote_art.shuffled.clone();
    let mut rts = Vec::with_capacity(cfg.rt_urls.len());
    for (i, url) in cfg.rt_urls.iter().enumerate() {
        let token = load_token_file(
            &cfg.ceremony_dir
                .join(format!("rt-{}-service-token.txt", i + 1)),
        )
        .await?;
        rts.push(RtClient::new(http.clone(), url.clone(), token));
    }
    // Sec. 3.9 steps 15-16: each teller broadcasts its share WITH a NIZKP that
    // the exponent is the one its published key share commits to, and only
    // shares with valid NIZKPs are considered. A teller that fails is set
    // aside and NAMED, and any t_RT good ones finish the step - where the
    // combined proof alone could only fail, with nobody to blame and every
    // teller required.
    let rt_control_shares = load_rt_control_shares(&cfg.ceremony_dir).await?;
    let rt_pk = load_rt_public_key(&cfg.ceremony_dir).await?;
    let mut refused_controls: Vec<String> = Vec::new();
    // Sec. 3.9 steps 15-17: a teller that drops out of EITHER round is set
    // aside and NAMED, and the step is run again over those that remain, so
    // that any t_RT good tellers finish it. A round-2 answer is a response
    // over the nonces of the round 1 it was built on, so the tellers that did
    // answer start again from round 1 rather than answering a second
    // challenge over the same nonces.
    let mut pool: Vec<usize> = (0..rts.len()).collect();
    let (controls_r1, controls_r2) = loop {
        if pool.len() < cfg.t_rt {
            return Err(AdminError::Other(format!(
                "only {} registration tellers are left in the control rounds, {} are needed ({})",
                pool.len(),
                cfg.t_rt,
                refused_controls.join("; ")
            )));
        }
        let mut good_rts = Vec::with_capacity(pool.len());
        let mut controls_r1 = Vec::with_capacity(pool.len());
        for i in pool.iter().copied() {
            let id = i + 1;
            let rt = &rts[i];
            let broadcast = match rt.controls_round1(&shuffled_votes).await {
                Ok(broadcast) => broadcast,
                Err(e) => {
                    refused_controls.push(format!("RT-{id} did not answer: {e}"));
                    continue;
                }
            };
            if broadcast.from_id != id {
                refused_controls.push(format!(
                    "RT-{id} answered in the name of RT-{}",
                    broadcast.from_id
                ));
                continue;
            }
            // Sec. 3.9 step 15: the share a teller STATES must be the one
            // published for it at the ceremony. Without this a teller proves
            // honestly under a key it never held, and only step 16's
            // interpolation notices - without saying whose fault it was.
            match rt_control_shares.iter().find(|share| share.id == id) {
                Some(pinned) if pinned.h == broadcast.pk_rt_i => {}
                Some(_) => {
                    refused_controls.push(format!(
                        "RT-{id} states a control key share that is not the one published for it"
                    ));
                    continue;
                }
                None => {
                    refused_controls.push(format!("no published control key share for RT-{id}"));
                    continue;
                }
            }
            let votes = shuffled_votes.clone();
            let pk = election_context.pk.clone();
            let checked = tokio::task::spawn_blocking(move || {
                evoting::api::server::rt::ThresholdRegistrationTeller::verify_controls_round1(
                    &votes, &broadcast, &pk,
                )
                .map(|()| broadcast)
            })
            .await
            .map_err(|e| AdminError::Other(e.to_string()))?;
            match checked {
                Ok(broadcast) => {
                    controls_r1.push(broadcast);
                    good_rts.push(rt.clone());
                }
                Err(e) => refused_controls.push(format!("RT-{id} control share refused: {e}")),
            }
        }
        if controls_r1.len() < cfg.t_rt {
            return Err(AdminError::Other(format!(
                "only {} registration tellers produced a valid control share, {} are needed ({})",
                controls_r1.len(),
                cfg.t_rt,
                refused_controls.join("; ")
            )));
        }
        // The rest of Sec. 3.9 step 16: the parties' key shares must
        // interpolate to pk_RT. Any t_RT of the accepted ones will do, so the
        // SUBSETS are tried rather than the first t_RT taken - one teller that
        // slipped past the per-party check must not be able to stop a tally an
        // honest subset can finish - and the tellers left out are named.
        // `t_subsets` names the parties 1..=n, so its entries index from one.
        let chosen: Vec<usize> =
            match crate::protocol::tally::t_subsets(controls_r1.len(), cfg.t_rt)
                .into_iter()
                .find(|subset| {
                    let ids: Vec<usize> =
                        subset.iter().map(|i| controls_r1[i - 1].from_id).collect();
                    let stated: Vec<_> =
                        subset.iter().map(|i| controls_r1[i - 1].pk_rt_i).collect();
                    evoting::api::server::rt::ThresholdRegistrationTeller::<RistrettoGroup>
                    ::control_shares_reach_pk_rt(&ids, &stated, rt_pk.registration_pk())
                        .is_ok()
                }) {
                Some(subset) => subset.into_iter().map(|i| i - 1).collect(),
                None => {
                    return Err(AdminError::Crypto(format!(
                        "no {} of the registration tellers' key shares interpolate to pk_RT ({})",
                        cfg.t_rt,
                        refused_controls.join("; ")
                    )))
                }
            };
        let left_out: Vec<usize> = (0..controls_r1.len())
            .filter(|i| !chosen.contains(i))
            .map(|i| controls_r1[i].from_id)
            .collect();
        let round1: Vec<_> = chosen.iter().map(|i| controls_r1[*i].clone()).collect();
        let tellers: Vec<_> = chosen.iter().map(|i| good_rts[*i].clone()).collect();
        let ids: Vec<usize> = round1.iter().map(|b| b.from_id).collect();

        let mut round2 = Vec::with_capacity(tellers.len());
        let mut dropped = None;
        for (rt, id) in tellers.iter().zip(&ids) {
            // Sec. 3.9 step 16 judges what a party SENDS, not only whether it
            // answers: a response that does not open that party's own round-1
            // commitments is no share at all, and combining it would only make
            // the final proof fail with nobody to blame. So each answer is
            // checked on its own, and one that fails is that teller's - named,
            // set aside, and the step run again over the rest.
            let checked = match rt.controls_round2(&round1, &ids).await {
                Ok(response) if response.from_id != *id => Err(format!(
                    "answered the second control round in the name of RT-{}",
                    response.from_id
                )),
                Ok(response) => {
                    let votes = shuffled_votes.clone();
                    let all_round1 = round1.clone();
                    let all_ids = ids.clone();
                    let pk = election_context.pk.clone();
                    tokio::task::spawn_blocking(move || {
                        evoting::api::server::rt::ThresholdRegistrationTeller::verify_controls_round2(
                            &votes, &response, &all_round1, &all_ids, &pk,
                        )
                        .map(|()| response)
                    })
                    .await
                    .map_err(|e| AdminError::Other(e.to_string()))?
                    .map_err(|e| format!("second control round refused: {e}"))
                }
                Err(e) => Err(format!("did not answer the second control round: {e}")),
            };
            match checked {
                Ok(response) => round2.push(response),
                Err(why) => {
                    refused_controls.push(format!("RT-{id} {why}"));
                    dropped = Some(*id);
                    break;
                }
            }
        }
        match dropped {
            None => {
                if !left_out.is_empty() {
                    tracing::warn!(?left_out, "credential controls built without these tellers");
                }
                break (round1, round2);
            }
            Some(id) => pool.retain(|i| i + 1 != id),
        }
    };
    let mut said = std::collections::HashSet::new();
    for note in &refused_controls {
        if said.insert(note.clone()) {
            tracing::warn!("{note}");
        }
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
    // Sec. 3.4.2 / Sec. 3.9 step 19: the credential control elements are
    // written by the registration tellers themselves - t_RT of them agreeing
    // on the same data - not by the tabulation tellers.
    queue_rt_cosigned(
        &mut outbox,
        &rts,
        &rt_keys,
        &wbb_data_string(
            "tallying",
            "RT",
            "credential_control",
            cfg.t_rt,
            &ReEncryptionProofEntry::Controls {
                controls: controls.clone(),
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        cfg.t_rt,
        &mut clock,
    )
    .await?;

    // Sec. 3.9 steps 18-22: the credential checks, blinded with the tellers'
    // zeta shares (nobody holds zeta), threshold-decrypted, and the
    // invalid-vote filter.
    let checks = ThresholdTabulationTeller::credential_check_ciphertexts(
        &election_context,
        &shuffled_votes,
        &controls,
    )
    .map_err(|e| AdminError::Crypto(format!("credential checks failed: {e:?}")))?;
    let blinding = run_threshold_blinding(
        &tts,
        "acc",
        "acc",
        &pipeline,
        std::slice::from_ref(&checks),
        &election_context,
    )
    .await?;
    let blinded_checks = blinding.fp_lists[0].clone();
    let mut acc_answers = Vec::with_capacity(tts.len());
    for tt in &tts {
        acc_answers.push(
            tt.decrypt_acc_checks(&blinding, std::slice::from_ref(&checks))
                .await
                .map_err(|e| e.to_string()),
        );
    }
    let acc_partials = accept_teller_partials(
        "credential check decryption",
        acc_answers,
        |id, partials| {
            partials_are_the_tellers(id, partials, &blinded_checks, &election_context.pk.params)
        },
        |partials| vec![partials.len()],
        cfg.t_tt,
    )?;
    let (acc_checks, valid_votes) = {
        let ctx = election_context.clone();
        let pipeline = pipeline.clone();
        let controls = controls.clone();
        let mixed = vote_art.shuffled.clone();
        let blinding = blinding.clone();
        tokio::task::spawn_blocking(move || {
            let acc_checks = ThresholdTabulationTeller::combine_acc_checks(
                &ctx,
                &blinded_checks,
                &acc_partials,
            )?;
            pipeline.verify_acc_checks(&acc_checks, &controls, &mixed, &blinding)?;
            let valid = pipeline.filter_invalid(&mixed, &controls, &acc_checks, &blinding)?;
            Ok::<_, evoting::error::Error>((acc_checks, valid))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("ACC check failed: {e:?}")))?
    };
    let valid = valid_votes.len();
    queue_tt_cosigned(
        &mut outbox,
        &tts,
        &tt_keys,
        &wbb_data_string(
            "tallying",
            "TT",
            "re_encryption_proof",
            3,
            &ReEncryptionProofEntry::AccChecks {
                acc_checks: acc_checks.clone(),
                blinding: blinding.clone(),
            },
        )
        .map_err(|e| AdminError::Other(e.to_string()))?,
        &mut clock,
    )
    .await?;

    // Sec. 3.9 steps 23-27: mix the eligible public credentials, fingerprint,
    // threshold-decrypt, and discard the votes of unauthorised credentials
    // (Sec. 3.9 step 27 - a discard only: re-votes were resolved at step 10).
    // Read from the verified log, and exactly one entry: the public
    // credentials decide which votes the credential mix carries, so a second,
    // forged `acc_pub_key` must not be able to steer this driver (the auditor
    // refuses a duplicate too).
    let short_accs: Vec<ShortPublicACC<RistrettoGroup>> = {
        let entries = verified_entries(&wbb, &pinned_log).await?;
        let mut found: Vec<ShortPublicACC<RistrettoGroup>> = Vec::new();
        for (_, entry) in &entries {
            let Some(parsed) = entry
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(|b64| BASE64.decode(b64).ok())
                .and_then(|data| parse_wbb_data(&data))
            else {
                continue;
            };
            if parsed.entry_type == "acc_pub_key" {
                found = parsed
                    .decode_payload()
                    .map_err(|e| AdminError::Other(format!("acc_pub_key payload invalid: {e}")))?;
                if entries
                    .iter()
                    .filter(|(_, e)| {
                        e.get("data")
                            .and_then(|v| v.as_str())
                            .and_then(|b64| BASE64.decode(b64).ok())
                            .and_then(|data| parse_wbb_data(&data))
                            .is_some_and(|p| p.entry_type == "acc_pub_key")
                    })
                    .count()
                    > 1
                {
                    return Err(AdminError::Other(
                        "more than one acc_pub_key entry on the bulletin board".into(),
                    ));
                }
                break;
            }
        }
        if found.is_empty() {
            return Err(AdminError::Other("no acc_pub_key entry on the WBB".into()));
        }
        found
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

    let (cred_art, fp_inputs) = {
        let pipeline = pipeline.clone();
        let shorts = eligible_shorts.clone();
        let valid_votes = valid_votes.clone();
        tokio::task::spawn_blocking(move || {
            let art = pipeline.mix_credentials(&shorts, &mut rng);
            pipeline.verify_cred_mix(&shorts, &art)?;
            let inputs = pipeline.credential_fingerprint_inputs(&shorts, &art, &valid_votes)?;
            Ok::<_, evoting::error::Error>((art, inputs))
        })
        .await
        .map_err(|e| AdminError::Other(e.to_string()))?
        .map_err(|e| AdminError::Crypto(format!("credential mix failed: {e:?}")))?
    };
    // Sec. 3.9 steps 24-25: the credential fingerprints, blinded with the
    // tellers' zeta' shares.
    let fps2 = run_threshold_blinding(
        &tts,
        "fp",
        "credential_fingerprints",
        &pipeline,
        &fp_inputs,
        &election_context,
    )
    .await?;
    queue_tt_cosigned(
        &mut outbox,
        &tts,
        &tt_keys,
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

    let mut fps_answers = Vec::with_capacity(tts.len());
    for tt in &tts {
        fps_answers.push(
            tt.decrypt_fps(&fps2, &fp_inputs)
                .await
                .map_err(|e| e.to_string()),
        );
    }
    let fps_partials = accept_teller_partials(
        "credential fingerprint decryption",
        fps_answers,
        |id, (pub_fps, vote_fps)| {
            let params = &election_context.pk.params;
            partials_are_the_tellers(id, pub_fps, &fps2.fp_lists[0], params)?;
            partials_are_the_tellers(id, vote_fps, &fps2.fp_lists[1], params)
        },
        |(pub_fps, vote_fps)| vec![pub_fps.len(), vote_fps.len()],
        cfg.t_tt,
    )?;
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
            let legitimate = pipeline.filter_illicit(
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
    queue_tt_cosigned(
        &mut outbox,
        &tts,
        &tt_keys,
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

    // EVERYTHING THE TALLY IS COMPUTED FROM REACHES THE BOARD FIRST, which is
    // the order Sec. 3.9 has: the control elements go to the WBB at step 19
    // and the result only at step 30. The tellers recompute the sum they
    // decrypt from these published artifacts (Sec. 3.9 steps 28-29), so what
    // they decrypt is not a ciphertext this driver chose - it holds their
    // service tokens, and a teller that decrypted a list of its caller's
    // choosing under the master tally key would hand out
    // `g3^(PIN_used - PIN_real)` for every discarded credential check.
    //
    // The signed artifacts are saved before they are sent, so a flush cut off
    // part-way is finished by the next run rather than stranding the election
    // (the discipline this driver already used for the single final flush).
    save_tally(
        &cfg.ceremony_dir,
        &SavedTally {
            outbox: outbox.clone(),
            outcome: TallyOutcome {
                counts: crate::protocol::tally::TallyCounts {
                    blank: 0,
                    si: 0,
                    no: 0,
                },
                released,
                reconciled,
                deduped,
                valid,
                legitimate: legitimate_count,
            },
            complete: false,
            log_key: log_key_fingerprint(&pinned_log),
            tree_size: already.iter().map(|(leaf, _)| *leaf + 1).max().unwrap_or(0),
            release_cut,
        },
    )
    .await?;
    flush_publications(&wbb, &outbox, &already, &cfg.ceremony_dir, release_cut).await?;

    finish_tally(
        FinishTally {
            cfg: &cfg,
            http: &http,
            wbb: &wbb,
            tts: &tts,
            tt_keys: &tt_keys,
            election_context: &election_context,
            pinned_log: &pinned_log,
            already: &already,
        },
        outbox,
        TallyOutcome {
            counts: crate::protocol::tally::TallyCounts {
                blank: 0,
                si: 0,
                no: 0,
            },
            released,
            reconciled,
            deduped,
            valid,
            legitimate: legitimate_count,
        },
        &mut clock,
    )
    .await
}

/// What the tail of the tally needs from the pipeline that ran before it.
struct FinishTally<'a> {
    cfg: &'a TallyConfig,
    http: &'a reqwest::Client,
    wbb: &'a WbbClient,
    tts: &'a [crate::clients::tt::TtClient],
    tt_keys: &'a std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
    election_context: &'a ElectionContext<RistrettoGroup>,
    pinned_log: &'a p256::ecdsa::VerifyingKey,
    already: &'a [(i64, serde_json::Value)],
}

/// Sec. 3.9 steps 28-30: decrypt the tally and publish the result.
///
/// Separate from the pipeline because it must be RESUMABLE on its own. The
/// artifacts it works from are already on the board by the time it runs, and
/// it recomputes the sum from them rather than from the pipeline's own
/// values - so a run cut off here is finished by the next one without
/// re-running the mixes and proofs, whose nonces are fresh every time and
/// would take a second leaf on an append-only board.
async fn finish_tally(
    ctx: FinishTally<'_>,
    mut outbox: Vec<PendingPublication>,
    mut outcome: TallyOutcome,
    clock: &mut Clock,
) -> Result<TallyOutcome, AdminError> {
    use crate::protocol::tally::{
        encrypted_tally_from_entries, extract_counts, partials_are_the_tellers, TallyProofEntry,
    };
    use crate::protocol::voting::wbb_data_string;
    use dlog_sigma_primitives::elgamal::ciphertext::DiscreteLogTable;
    use evoting::api::prelude::ThresholdTabulationTeller;
    let FinishTally {
        cfg,
        http: _http,
        wbb,
        tts,
        tt_keys,
        election_context,
        pinned_log,
        already,
    } = ctx;
    // Sec. 3.9 steps 28-29. The sum is recomputed from the PUBLISHED
    // artifacts, exactly as the tellers recompute it: that is what makes this
    // step resumable without re-running the pipeline, whose proofs carry
    // fresh nonces every time and would take a second leaf on the board.
    let entries: Vec<serde_json::Value> = wbb
        .entries()
        .await
        .map_err(|e| AdminError::Other(format!("the bulletin board could not be read: {e}")))?
        .entries
        .into_iter()
        .map(|e| e.entry)
        .collect();
    let election_context = election_context.clone();
    let enc_tally = {
        let ctx = election_context.clone();
        tokio::task::spawn_blocking(move || encrypted_tally_from_entries(&entries, &ctx))
            .await
            .map_err(|e| AdminError::Other(e.to_string()))?
            .map_err(|e| AdminError::Other(format!("the published tally does not add up: {e}")))?
    };
    let pipeline = evoting::api::server::bb::PublicPipeline::new(
        evoting::api::server::bb::PublicElection::new(election_context.clone()),
    );
    let mut tally_answers = Vec::with_capacity(tts.len());
    for tt in tts.iter() {
        tally_answers.push(tt.decrypt_tally().await.map_err(|e| e.to_string()));
    }
    let tally_partials = accept_teller_partials(
        "tally decryption",
        tally_answers,
        |id, (l1, l2)| {
            let params = &election_context.pk.params;
            let (cts_l1, cts_l2) = enc_tally.ciphertexts();
            partials_are_the_tellers(id, l1, cts_l1, params)?;
            if l2.len() != cts_l2.len() {
                return Err(format!(
                    "TT-{id} returned {} second-level rows for {}",
                    l2.len(),
                    cts_l2.len()
                ));
            }
            for (row, cts) in l2.iter().zip(cts_l2) {
                partials_are_the_tellers(id, row, cts, params)?;
            }
            Ok(())
        },
        |(l1, l2)| {
            let mut shape = vec![l1.len(), l2.len()];
            shape.extend(l2.iter().map(Vec::len));
            shape
        },
        cfg.t_tt,
    )?;
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

    // Sec. 3.9 step 30: publish the proofs and the final counts.
    queue_tt_cosigned(
        &mut outbox,
        tts,
        tt_keys,
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
        clock,
    )
    .await?;
    queue_tt_cosigned(
        &mut outbox,
        tts,
        tt_keys,
        &wbb_data_string("tallying", "TT", "tally_result", 3, &counts)
            .map_err(|e| AdminError::Other(e.to_string()))?,
        clock,
    )
    .await?;

    outcome.counts = counts;

    // The pipeline has succeeded end to end: only now does anything reach
    // the board, in pipeline order (releases, mixes, proofs, result). The
    // signed artifacts are saved first, so a submission cut off part-way
    // (a lost request, a board restart) is finished by the next run
    // instead of stranding the election behind the once-only guard.
    save_tally(
        &cfg.ceremony_dir,
        &SavedTally {
            outbox,
            outcome,
            complete: true,
            log_key: log_key_fingerprint(pinned_log),
            tree_size: already.iter().map(|(leaf, _)| *leaf + 1).max().unwrap_or(0),
            release_cut: no_release_cut(),
        },
    )
    .await?;
    let saved = load_saved_tally(&cfg.ceremony_dir)
        .await?
        .ok_or_else(|| AdminError::Other("the saved tally could not be read back".into()))?;
    flush_publications(
        wbb,
        &saved.outbox,
        already,
        &cfg.ceremony_dir,
        no_release_cut(),
    )
    .await?;

    tracing::info!(
        released = outcome.released,
        reconciled = outcome.reconciled,
        deduped = outcome.deduped,
        valid = outcome.valid,
        legitimate = outcome.legitimate,
        blank = counts.blank,
        si = counts.si,
        no = counts.no,
        "tally pipeline complete"
    );

    Ok(outcome)
}

/// Keep the tellers' answers to one decryption request that pass `check`
/// (Sec. 3.9 step 16: shares without a valid binding are set aside, the
/// teller is named, and the step goes on with any `t_tt` good ones). Fewer
/// than `t_tt` good answers stop the tally, naming every teller set aside.
fn accept_teller_partials<T>(
    what: &str,
    answers: Vec<Result<T, String>>,
    check: impl Fn(usize, &T) -> Result<(), String>,
    shape: impl Fn(&T) -> Vec<usize>,
    t_tt: usize,
) -> Result<Vec<T>, AdminError> {
    let mut candidates = Vec::with_capacity(answers.len());
    let mut refused = Vec::new();
    for (i, answer) in answers.into_iter().enumerate() {
        let id = i + 1;
        match answer {
            Err(e) => refused.push(format!("TT-{id} failed: {e}")),
            Ok(partials) => match check(id, &partials) {
                Ok(()) => candidates.push((id, partials)),
                Err(e) => refused.push(e),
            },
        }
    }
    // Every honest teller answers one partial per ciphertext, in the same
    // order: an answer of another shape would make the combination fail for
    // everyone, unattributed. The shape the most tellers agree on is taken
    // as the honest one; a lone dissenter is set aside and named.
    let mut shapes: Vec<(Vec<usize>, usize)> = Vec::new();
    for (_, partials) in &candidates {
        let this = shape(partials);
        match shapes.iter_mut().find(|(known, _)| *known == this) {
            Some((_, count)) => *count += 1,
            None => shapes.push((this, 1)),
        }
    }
    let majority = shapes
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(shape, _)| shape.clone())
        .unwrap_or_default();
    let mut accepted = Vec::with_capacity(candidates.len());
    for (id, partials) in candidates {
        if shape(&partials) == majority {
            accepted.push(partials);
        } else {
            refused.push(format!(
                "TT-{id} returned partial decryptions of a shape the other tellers do not share"
            ));
        }
    }
    for reason in &refused {
        tracing::warn!(step = what, "teller set aside: {reason}");
    }
    if accepted.len() < t_tt {
        return Err(AdminError::Other(format!(
            "{what}: only {} of the tellers' answers can be used, threshold is {t_tt} ({})",
            accepted.len(),
            refused.join("; ")
        )));
    }
    Ok(accepted)
}

/// Run one threshold zeta VSS session over every TT (Sec. 3.9 steps 6-7,
/// 20, 24), then have every teller raise `ct_lists` to ITS sub-share with a
/// proof and combine the shares in the exponent. The blinding scalar exists
/// only as the tellers' shares: this driver never sees it, and what is
/// published (shares, VSS commitments, blinded lists) lets anyone re-verify.
/// A teller whose share does not verify is set aside and NAMED; any `t_tt`
/// good shares suffice. (This driver only RELAYS the VSS broadcasts - the
/// trusted-coordinator class of deviation 25, where the thesis's Protocol 2
/// assumes direct channels. Each evaluation share is sealed to its recipient
/// and each broadcast is signed by its dealer, so the relay can neither read
/// a share, alter one, nor deal a sharing of its own in a teller's name.)
async fn run_threshold_blinding(
    tts: &[crate::clients::tt::TtClient],
    session: &str,
    transcript_label: &str,
    pipeline: &evoting::api::server::bb::PublicPipeline<RistrettoGroup>,
    ct_lists: &[Vec<dlog_sigma_primitives::elgamal::ciphertext::Ciphertext<RistrettoGroup>>],
    election_context: &ElectionContext<RistrettoGroup>,
) -> Result<evoting::api::prelude::ThresholdFingerprints<RistrettoGroup>, AdminError> {
    use evoting::api::prelude::{BlindingShare, ThresholdFingerprints, ZetaCommitments};

    let transcript = match transcript_label {
        "ox" => pipeline.ox_transcript(),
        "acc" => pipeline.acc_transcript(),
        "credential_fingerprints" => pipeline.credential_fingerprint_transcript(),
        other => {
            return Err(AdminError::Other(format!(
                "unknown blinding transcript {other}"
            )))
        }
    };
    let transcript = &transcript;

    let mut broadcasts = Vec::with_capacity(tts.len());
    for (i, tt) in tts.iter().enumerate() {
        let signed = tt
            .zeta_round1(session)
            .await
            .map_err(|e| AdminError::Other(format!("zeta VSS round 1 failed: {e}")))?;
        // A teller that deals in another's name would strand the round and
        // the name in the failure would be the honest teller's; say here who
        // actually answered (Sec. 2.8 Protocol 2).
        if signed.broadcast.from_id != i + 1 {
            return Err(AdminError::Other(format!(
                "TT-{} dealt a zeta VSS broadcast in the name of TT-{}",
                i + 1,
                signed.broadcast.from_id
            )));
        }
        broadcasts.push(signed);
    }
    for tt in tts {
        tt.zeta_combine(session, &broadcasts)
            .await
            .map_err(|e| AdminError::Other(format!("zeta VSS combine failed: {e}")))?;
    }
    let commitments: Vec<ZetaCommitments<RistrettoGroup>> = broadcasts
        .iter()
        .map(|s| ZetaCommitments::from(&s.broadcast))
        .collect();

    let mut shares: Vec<BlindingShare<RistrettoGroup>> = Vec::with_capacity(tts.len());
    let mut refused = Vec::new();
    for (i, tt) in tts.iter().enumerate() {
        match tt.blind(&commitments, ct_lists, transcript_label).await {
            Ok(share) if share.from_id == i + 1 => shares.push(share),
            Ok(share) => refused.push(format!(
                "TT-{} returned a blinding share in the name of TT-{}",
                i + 1,
                share.from_id
            )),
            Err(e) => refused.push(format!("TT-{} did not blind: {e}", i + 1)),
        }
    }
    let params = &election_context.pk.params;
    let (n, t, base) = (params.tellers.n(), params.tellers.t, params.elgamal.g1);
    // Every share is verified on its own first, so a bad one is named and
    // set aside rather than failing the combination for everyone.
    let public = evoting::api::prelude::zeta_public_shares(&commitments, n, t)
        .map_err(|e| AdminError::Other(format!("zeta VSS commitments refused: {e:?}")))?;
    let mut good = Vec::with_capacity(shares.len());
    for share in shares {
        match share.verify(
            ct_lists,
            &base,
            &public[share.from_id - 1],
            &commitments,
            transcript,
        ) {
            Ok(()) => good.push(share),
            Err(e) => refused.push(format!(
                "TT-{} returned a blinding share that does not verify: {e:?}",
                share.from_id
            )),
        }
    }
    for reason in &refused {
        tracing::warn!(step = transcript_label, "teller set aside: {reason}");
    }
    if good.len() < t {
        return Err(AdminError::Other(format!(
            "{transcript_label} blinding: only {} of the tellers' shares can be used, \
             threshold is {t} ({})",
            good.len(),
            refused.join("; ")
        )));
    }
    let ct_lists = ct_lists.to_vec();
    let transcript = transcript.clone();
    let label = transcript_label.to_string();
    tokio::task::spawn_blocking(move || {
        ThresholdFingerprints::combine(commitments, good, &ct_lists, &base, n, t, &transcript)
    })
    .await
    .map_err(|e| AdminError::Other(e.to_string()))?
    .map_err(|e| AdminError::Crypto(format!("{label} blinding failed: {e:?}")))
}

/// One tally artifact, signed and ready for the board but not yet submitted.
///
/// The board is append-only and every tally artifact is once-only, so the
/// driver signs each artifact when the pipeline produces it and submits ALL
/// of them only after the last step has succeeded. A failure anywhere in the
/// pipeline then leaves the board exactly as it was, and the tally can simply
/// be run again.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PendingPublication {
    /// Every (partial) signature over `data`: one for a single-signer entry,
    /// one per teller for a co-signed one.
    entries: Vec<SignedEntry>,
    data: String,
    /// Who signs this artifact: needed to sign it AGAIN with a fresh
    /// timestamp when a cut-off submission is resumed later than the board's
    /// timestamp window allows.
    signer: Signer,
}

/// The authority behind one tally artifact.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum Signer {
    /// The tabulation tellers, co-signing.
    Tellers,
    /// The registration tellers, co-signing.
    Registrars,
    /// One ballot box, whose release the driver signs on its behalf (#25).
    BallotBox { entity_id: String },
}

/// The tally artifacts only the TELLERS can write (co-signed, thresholds 2
/// and 3): one of them on the board means a tally has at least been started
/// by a run of this driver. A ballot box's own entry type (`encrypted_ballot`,
/// threshold 1) is deliberately NOT here: one dishonest box could otherwise
/// plant an entry and block the tally for good.
const GUARDED_TALLY_ENTRY_TYPES: &[&str] = &[
    "mixed_ballots",
    "re_encryption_proof",
    "credential_control",
    "tally_proof",
    "tally_result",
];

/// A finished tally: its signed artifacts and its outcome, saved before the
/// first submission so that a cut-off submission can be resumed - on THIS
/// board: the pinned log key and the tree size the pipeline ran against are
/// saved with it, and a resume refuses a board that is not that one.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SavedTally {
    outbox: Vec<PendingPublication>,
    /// What the pipeline counted. `complete` says whether the COUNTS in it
    /// are real: the half-way save made before the tally decryption carries
    /// the pipeline's own counters (released, deduped, ...) but zero counts.
    outcome: TallyOutcome,
    /// Whether the result was reached. A save with `false` is finished by
    /// `finish_tally`, which recomputes the sum from the board - the pipeline
    /// is NOT run again, because its proofs carry fresh nonces every time and
    /// would take a second leaf on an append-only board.
    #[serde(default)]
    complete: bool,
    /// SHA-256 (hex) of the pinned log verifying key.
    log_key: String,
    /// The board's tree size when the pipeline read it; every artifact of this
    /// tally is sequenced after it.
    tree_size: i64,
    /// The board's size when the pipeline took in the releases already on
    /// it: a box release sequenced at or past this leaf that the outbox does
    /// not hold was not tallied, and must not precede the tally's start.
    #[serde(default = "no_release_cut")]
    release_cut: i64,
}

/// No release check: the save holds no releases still to publish.
fn no_release_cut() -> i64 {
    i64::MAX
}

fn log_key_fingerprint(key: &p256::ecdsa::VerifyingKey) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(key.to_encoded_point(true).as_bytes()))
}

const SAVED_TALLY_FILE: &str = "tally-outbox.json";

async fn save_tally(ceremony_dir: &Path, saved: &SavedTally) -> Result<(), AdminError> {
    write_secret_json(&ceremony_dir.join(SAVED_TALLY_FILE), saved).await
}

async fn load_saved_tally(ceremony_dir: &Path) -> Result<Option<SavedTally>, AdminError> {
    let path = ceremony_dir.join(SAVED_TALLY_FILE);
    match tokio::fs::read(&path).await {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AdminError::Other(format!(
            "failed to read {}: {e}",
            path.display()
        ))),
    }
}

/// Sign one TT-co-signed entry and queue it: all TTs sign the same data with
/// a shared logical timestamp; once submitted, the entry publishes when the
/// WBB staging threshold (t>=3) is met.
async fn queue_tt_cosigned(
    outbox: &mut Vec<PendingPublication>,
    tts: &[crate::clients::tt::TtClient],
    keys: &std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
    data: &str,
    clock: &mut Clock,
) -> Result<(), AdminError> {
    use crate::clients::tt::TtClient;

    let timestamp = clock.now_ms() as i64;
    clock.advance();

    let mut entries = Vec::with_capacity(tts.len());
    for (i, tt) in tts.iter().enumerate() {
        let response = tt
            .sign(data, timestamp)
            .await
            .map_err(|e| AdminError::Other(format!("TT co-signing failed: {e}")))?;
        let entry = TtClient::to_signed_entry(data, &response)
            .map_err(|e| AdminError::Other(e.to_string()))?;
        check_cosignature(&entry, &format!("TT-{}", i + 1), timestamp, keys)?;
        entries.push(entry);
    }
    outbox.push(PendingPublication {
        entries,
        data: data.to_string(),
        signer: Signer::Tellers,
    });
    Ok(())
}

/// Sign one RT-co-signed entry and queue it: every registration teller signs
/// the same data with a shared timestamp; once submitted, the entry publishes
/// when the board's RT threshold is met.
async fn queue_rt_cosigned(
    outbox: &mut Vec<PendingPublication>,
    rts: &[RtClient],
    keys: &std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
    data: &str,
    t_rt: usize,
    clock: &mut Clock,
) -> Result<(), AdminError> {
    let timestamp = clock.now_ms() as i64;
    clock.advance();

    // The entry declares the THRESHOLD it is published at, and the board
    // accepts it on that many signatures (Sec. 3.4.2). Requiring every teller
    // here would hand each of them a veto over a step that t_RT of them are
    // entitled to finish - which is the same denial Sec. 3.9 step 16 is
    // written to prevent, one line further on. A teller that will not sign is
    // NAMED and the entry goes out under the signatures it has.
    let mut entries = Vec::with_capacity(rts.len());
    let mut refused = Vec::new();
    for (i, rt) in rts.iter().enumerate() {
        let id = i + 1;
        let signed = match rt.sign(data, timestamp).await {
            Ok(response) => RtClient::to_signed_entry(data, &response)
                .map_err(|e| e.to_string())
                .and_then(|entry| {
                    check_cosignature(&entry, &format!("RT-{id}"), timestamp, keys)
                        .map(|()| entry)
                        .map_err(|e| e.to_string())
                }),
            Err(e) => Err(e.to_string()),
        };
        match signed {
            Ok(entry) => entries.push(entry),
            Err(why) => refused.push(format!("RT-{id} did not co-sign: {why}")),
        }
    }
    for note in &refused {
        tracing::warn!("{note}");
    }
    if entries.len() < t_rt {
        return Err(AdminError::Other(format!(
            "only {} registration tellers co-signed, {t_rt} are needed ({})",
            entries.len(),
            refused.join("; ")
        )));
    }
    outbox.push(PendingPublication {
        entries,
        data: data.to_string(),
        signer: Signer::Registrars,
    });
    Ok(())
}

/// Sign the artifacts of a saved tally that are not yet on the board again,
/// with fresh timestamps, by the authority each one belongs to. The data is
/// unchanged; only the signatures are new.
async fn resign_pending(
    cfg: &TallyConfig,
    http: &reqwest::Client,
    outbox: &[PendingPublication],
    board: &[(i64, serde_json::Value)],
    clock: &mut Clock,
) -> Result<Vec<PendingPublication>, AdminError> {
    use crate::clients::tt::TtClient;

    let on_board: std::collections::HashSet<&str> = board
        .iter()
        .filter_map(|(_, entry)| entry.get("data")?.as_str())
        .collect();
    let tt_keys = load_verifying_keys(&cfg.ceremony_dir, "tt", cfg.tt_urls.len()).await?;
    let rt_keys = load_verifying_keys(&cfg.ceremony_dir, "rt", cfg.rt_urls.len()).await?;
    let mut tts = Vec::with_capacity(cfg.tt_urls.len());
    for (i, url) in cfg.tt_urls.iter().enumerate() {
        let token = load_token_file(
            &cfg.ceremony_dir
                .join(format!("tt-{}-service-token.txt", i + 1)),
        )
        .await?;
        tts.push(TtClient::new(http.clone(), url.clone(), token));
    }
    let mut rts = Vec::with_capacity(cfg.rt_urls.len());
    for (i, url) in cfg.rt_urls.iter().enumerate() {
        let token = load_token_file(
            &cfg.ceremony_dir
                .join(format!("rt-{}-service-token.txt", i + 1)),
        )
        .await?;
        rts.push(RtClient::new(http.clone(), url.clone(), token));
    }

    let mut fresh = Vec::with_capacity(outbox.len());
    for pending in outbox {
        if on_board.contains(BASE64.encode(pending.data.as_bytes()).as_str()) {
            fresh.push(pending.clone());
            continue;
        }
        match &pending.signer {
            Signer::Tellers => {
                queue_tt_cosigned(&mut fresh, &tts, &tt_keys, &pending.data, clock).await?
            }
            Signer::Registrars => {
                queue_rt_cosigned(&mut fresh, &rts, &rt_keys, &pending.data, cfg.t_rt, clock)
                    .await?
            }
            Signer::BallotBox { entity_id } => {
                let name = entity_id.to_lowercase();
                let key =
                    load_signing_key(&cfg.ceremony_dir.join(format!("{name}-signing-key.bin")))
                        .await?;
                let timestamp = clock.now_ms() as i64;
                clock.advance();
                fresh.push(PendingPublication {
                    entries: vec![sign_entry(
                        pending.data.as_bytes(),
                        entity_id,
                        timestamp,
                        &key,
                    )],
                    data: pending.data.clone(),
                    signer: pending.signer.clone(),
                });
            }
        }
    }
    Ok(fresh)
}

/// Submit every queued artifact, in pipeline order, waiting for the board to
/// sequence each one before the next. Artifacts already on the board (a
/// resumed submission) are skipped; a partial the board already holds is
/// not an error.
///
/// The releases go first, and the tally's input is every release sequenced
/// before its first artifact (the auditor reads it so). Just before that
/// first artifact the board is read again: a release a box wrote at or past
/// `release_cut` that this outbox does not hold was not tallied, so nothing
/// more is published, the saved tally is dropped, and the next run takes the
/// release in (Sec. 3.9 step 2). A box can only release ballots it holds,
/// so this ends.
async fn flush_publications(
    wbb: &WbbClient,
    outbox: &[PendingPublication],
    board: &[(i64, serde_json::Value)],
    ceremony_dir: &Path,
    release_cut: i64,
) -> Result<(), AdminError> {
    let on_board: std::collections::HashSet<&str> = board
        .iter()
        .filter_map(|(_, entry)| entry.get("data")?.as_str())
        .collect();
    let is_release =
        |pending: &PendingPublication| matches!(pending.signer, Signer::BallotBox { .. });
    // The tally has started once one of its artifacts is on the board.
    let mut started = outbox.iter().any(|pending| {
        !is_release(pending) && on_board.contains(BASE64.encode(pending.data.as_bytes()).as_str())
    });
    for pending in outbox {
        if on_board.contains(BASE64.encode(pending.data.as_bytes()).as_str()) {
            continue;
        }
        if !started && !is_release(pending) {
            started = true;
            check_release_cut(wbb, outbox, ceremony_dir, release_cut).await?;
        }
        submit_cosigned_and_wait(wbb, &pending.entries, &pending.data).await?;
    }
    Ok(())
}

/// Refuse to start the tally over a release it did not take in (see
/// `flush_publications`).
async fn check_release_cut(
    wbb: &WbbClient,
    outbox: &[PendingPublication],
    ceremony_dir: &Path,
    release_cut: i64,
) -> Result<(), AdminError> {
    if release_cut == no_release_cut() {
        return Ok(());
    }
    let entries: Vec<(i64, serde_json::Value)> = wbb
        .entries()
        .await
        .map_err(|e| AdminError::Other(format!("WBB read failed: {e}")))?
        .entries
        .into_iter()
        .map(|sequenced| (sequenced.leaf_index, sequenced.entry))
        .collect();
    let ours: std::collections::HashSet<String> = outbox
        .iter()
        .map(|pending| BASE64.encode(pending.data.as_bytes()))
        .collect();
    let late: Vec<String> = crate::protocol::tally::board_releases(&entries)
        .into_iter()
        .filter(|release| release.leaf >= release_cut && !ours.contains(&release.data))
        .map(|release| format!("BB-{} at entry {}", release.bb_id, release.leaf))
        .collect();
    if late.is_empty() {
        return Ok(());
    }
    match tokio::fs::remove_file(ceremony_dir.join(SAVED_TALLY_FILE)).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(AdminError::Other(format!(
                "failed to drop the saved tally: {e}"
            )))
        }
    }
    Err(AdminError::Other(format!(
        "a ballot box released ballots on the bulletin board while the tally ran ({}): \
         nothing past the releases was published - run the tally again to take them in",
        late.join(", ")
    )))
}

/// Submit every partial signature of one co-signed entry and wait until the
/// board has sequenced it. A partial the board already holds (HTTP 409, a
/// resumed submission) counts as delivered; a failed request is retried once.
async fn submit_cosigned_and_wait(
    wbb: &WbbClient,
    entries: &[SignedEntry],
    data: &str,
) -> Result<(), AdminError> {
    for entry in entries {
        let mut attempt = 0;
        loop {
            match wbb.submit(entry).await {
                Ok(_) => break,
                Err(crate::clients::wbb::WbbError::Http(status, _))
                    if status == reqwest::StatusCode::CONFLICT =>
                {
                    break
                }
                Err(e) if attempt == 0 => {
                    attempt += 1;
                    tracing::warn!(entity = %entry.entity_id, "submission failed, retrying once: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
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

/// Load the verifying keys pinned at the ceremony for `prefix-1..=n`
/// (`tt-1-verifying-key.bin`, ...), keyed by entity id (`TT-1`, ...).
async fn load_verifying_keys(
    ceremony_dir: &Path,
    prefix: &str,
    n: usize,
) -> Result<std::collections::HashMap<String, ed25519_dalek::VerifyingKey>, AdminError> {
    let mut keys = std::collections::HashMap::with_capacity(n);
    for i in 1..=n {
        let path = ceremony_dir.join(format!("{prefix}-{i}-verifying-key.bin"));
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| AdminError::Other(format!("failed to read {}: {e}", path.display())))?;
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AdminError::Other(format!("{} must be 32 bytes", path.display())))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&raw)
            .map_err(|e| AdminError::Other(format!("{}: {e}", path.display())))?;
        keys.insert(format!("{}-{i}", prefix.to_uppercase()), key);
    }
    Ok(keys)
}

/// A teller's co-signature is queued only once it has been checked against
/// the key pinned for that teller at the ceremony: the board would refuse a
/// bad one, but only at flush time, after everything else was published -
/// a teller that signs wrongly is named here instead.
fn check_cosignature(
    entry: &SignedEntry,
    expected_entity: &str,
    expected_timestamp: i64,
    keys: &std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
) -> Result<(), AdminError> {
    if entry.entity_id != expected_entity {
        return Err(AdminError::Other(format!(
            "{expected_entity} returned a co-signature in the name of {}",
            entry.entity_id
        )));
    }
    if entry.timestamp != expected_timestamp {
        return Err(AdminError::Other(format!(
            "{expected_entity} co-signed with timestamp {} instead of {expected_timestamp}",
            entry.timestamp
        )));
    }
    let Some(key) = keys.get(expected_entity) else {
        return Err(AdminError::Other(format!(
            "no verifying key pinned for {expected_entity}"
        )));
    };
    if !entry.verify(key) {
        return Err(AdminError::Other(format!(
            "{expected_entity} returned an invalid co-signature"
        )));
    }
    Ok(())
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
/// `to` (forward-only `setup -> voting -> tallying`, enforced by the WBB).
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
