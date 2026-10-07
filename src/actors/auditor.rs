//! Universal-verification auditor (Sec. 3.10).
//!
//! Fetches everything from the WBB read API and re-runs the public pipeline:
//! entry signatures, phase transitions, ballot-release reconciliation (the
//! Sec. 3.8.5 bot filter), ox re-vote dedup, ballot/mix/ACC-check/credential
//! verification, filter recomputation, the homomorphic sum, and the tally
//! decryption proofs. Every step yields OK/FAIL; the CLI exits nonzero on any
//! FAIL. What the auditor PINS comes from local configuration: the entity
//! verifying keys, the cluster CA, the log key and log name, and the validator
//! keys. All election data is read from the log itself.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evoting::api::prelude::{ShortPublicACC, ThresholdDecOk};
use evoting::api::server::bb::{BallotRecord, ElectionContext, PublicElection, PublicPipeline};
use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::clients::wbb::WbbClient;
use crate::domain::Vid;
use crate::protocol::tally::{
    extract_counts, reconcile_ballots, teller_shares_bind_to_master, EncryptedBallotEntry,
    MixedBallotsEntry, ReEncryptionProofEntry, TallyCounts, TallyProofEntry, TellerPublicShare,
};
use crate::protocol::tls::reqwest_client_trusting_ca;
use crate::protocol::voting::{
    ballot_digest, parse_wbb_data, BallotDigestEntry, CaiEntry, ParsedWbbData,
};

type G = RistrettoGroup;

/// Configuration for a Sec. 3.10 audit run.
#[derive(Clone)]
pub struct AuditConfig {
    /// WBB log base URL.
    pub wbb_url: Url,
    /// Cluster CA PEM for TLS.
    pub ca_pem: String,
    /// The bulletin board's log public key, PINNED at the setup ceremony
    /// (never learned from the board): signed tree heads are checked with it.
    pub log_key: p256::ecdsa::VerifyingKey,
    /// The name the board signs its tree heads under (its host and path,
    /// e.g. `127.0.0.1/wbb`), pinned too: the same key must not vouch for
    /// another log.
    pub log_origin: String,
    /// Bulletin-board validators: id -> compressed BLS public key, PINNED by
    /// whoever runs the audit (never learned from the board). Empty when the
    /// election runs without validators; then their signatures are not audited.
    pub validator_keys: Vec<(String, Vec<u8>)>,
    /// Entity Ed25519 verifying keys, id -> key (PM/ER/RT/TT/BB).
    pub entity_keys: Vec<(String, VerifyingKey)>,
    /// Number of TT parties and reconstruction threshold - bounds for the
    /// master-key binding check on every published threshold decryption
    /// (share-forgery defense).
    pub n_tt: usize,
    pub t_tt: usize,
}

/// Required staging role and threshold per entry type - the fixed Sec. 3.4.2 write-
/// policy table. The auditor must not trust the attacker-authored threshold
/// field inside the entry data.
fn required_signing(entry_type: &str) -> Option<(&'static str, usize)> {
    Some(match entry_type {
        "election_pub_key"
        | "pseudonymous_id_count"
        | "voter_id_merkle_root"
        | "assigned_vids"
        | "tt_public_shares"
        | "revocation_commitment"
        | "eligible_vids" => ("ER", 1),
        "acc_pub_key" | "credential_control" => ("RT", 2),
        "ballot_digest" | "ballot_metadata" | "cast_intended_proof" | "encrypted_ballot" => {
            ("BB", 1)
        }
        "mixed_ballots" | "re_encryption_proof" | "tally_result" | "tally_proof" => ("TT", 3),
        "phase_transition" => ("PM", 1),
        _ => return None,
    })
}

/// One audited verification step.
#[derive(Debug, Clone)]
pub struct AuditStep {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// True when the step passed but found a ballot box (or another single
    /// authority) misbehaving in a way the protocol tolerates: the result is
    /// unaffected, the evidence is on the board, and here is who to blame.
    pub warning: bool,
}

/// Full per-step audit report (Sec. 3.10).
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    pub steps: Vec<AuditStep>,
}

impl AuditReport {
    /// True when every step passed.
    pub fn ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok)
    }

    /// The steps that passed with a warning: misbehaviour the protocol
    /// tolerates (thesis A9: one dishonest ballot box; Sec. 3.8.4 step 15:
    /// divergent data is published, not fatal), attributed to its author.
    pub fn warnings(&self) -> impl Iterator<Item = &AuditStep> {
        self.steps.iter().filter(|s| s.ok && s.warning)
    }

    fn pass(&mut self, name: &'static str, detail: impl Into<String>) {
        self.steps.push(AuditStep {
            name,
            ok: true,
            detail: detail.into(),
            warning: false,
        });
    }

    /// The step holds for the election, but an authority was caught lying
    /// or failing in a way the protocol survives. The election result is not
    /// in question; the authority is.
    fn warn(&mut self, name: &'static str, detail: impl Into<String>) {
        self.steps.push(AuditStep {
            name,
            ok: true,
            detail: format!("WARNING: {}", detail.into()),
            warning: true,
        });
    }

    fn fail(&mut self, name: &'static str, detail: impl Into<String>) {
        self.steps.push(AuditStep {
            name,
            ok: false,
            detail: detail.into(),
            warning: false,
        });
    }

    /// Render the report as the CLI's per-step OK/FAIL lines.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            let status = match (step.ok, step.warning) {
                (true, false) => "OK  ",
                (true, true) => "WARN",
                (false, _) => "FAIL",
            };
            out.push_str(&format!("[{status}] {:<24} {}\n", step.name, step.detail));
        }
        out.push_str(if self.ok() {
            "audit: PASS\n"
        } else {
            "audit: FAIL\n"
        });
        out
    }
}

/// Errors that prevent the audit from producing a report at all.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("WBB error: {0}")]
    Wbb(#[from] crate::clients::wbb::WbbError),
    #[error("TLS error: {0}")]
    Tls(#[from] crate::protocol::tls::TlsError),
}

/// One fetched log entry with its decoded data and signer set.
struct AuditedEntry {
    leaf_index: i64,
    data: Vec<u8>,
    /// The bytes the signatures on this leaf were made over. Normally `data`
    /// itself; for a late co-signer's leaf (`ref:N`, Sec. 3.4.2 threshold
    /// entries) the data of the entry it signs, at leaf N.
    signed_data: Vec<u8>,
    parsed: Option<ParsedWbbData>,
    /// `(entity_id, timestamp_ms, signature)` per signer.
    signers: Vec<(String, i64, Vec<u8>)>,
}

/// Run the full Sec. 3.10 audit against a WBB log.
///
/// Nothing the board serves is taken on trust: the entry list is first tied
/// to a tree head signed by the pinned log key (`log_integrity`), and only
/// the entries covered by that tree head are audited.
pub async fn run_audit(cfg: AuditConfig) -> Result<AuditReport, AuditError> {
    let http = reqwest_client_trusting_ca(&cfg.ca_pem)?;
    let wbb = WbbClient::new(http, cfg.wbb_url.clone());
    // The board appends while it runs: fetch the tree head, then the entries,
    // and if the list already outgrew the tree head, take a newer one.
    let mut checkpoint = wbb.checkpoint().await?;
    let mut entries = wbb.entries_raw().await?;
    for _ in 0..3 {
        match crate::protocol::tlog::verify_checkpoint(&checkpoint, &cfg.log_key) {
            Ok(head) if (head.size as usize) < entries.entries.len() => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                checkpoint = wbb.checkpoint().await?;
                entries = wbb.entries_raw().await?;
            }
            _ => break,
        }
    }
    Ok(audit_raw_log(&cfg, &checkpoint, entries.entries).await)
}

/// Audit a signed tree head plus the entry list served with it: first the
/// log itself (`log_integrity`), then - over exactly the entries the tree
/// head covers - everything `audit_raw_entries` checks. Public so tests can
/// replay a TAMPERED entry list against a genuine tree head.
pub async fn audit_raw_log(
    cfg: &AuditConfig,
    checkpoint: &[u8],
    entries: Vec<crate::clients::wbb::RawSequencedEntry>,
) -> AuditReport {
    let (mut report, covered) = audit_log_and_validators(cfg, checkpoint, &entries);
    let Some(covered) = covered else {
        return report;
    };
    let mut raw = Vec::with_capacity(covered);
    for entry in entries.iter().take(covered) {
        match serde_json::from_str::<serde_json::Value>(entry.entry.get()) {
            Ok(value) => raw.push((entry.leaf_index, value)),
            Err(e) => {
                report.fail(
                    "log_integrity",
                    format!("leaf {}: entry is not JSON ({e})", entry.leaf_index),
                );
                return report;
            }
        }
    }
    let rest = audit_raw_entries(cfg, raw).await;
    report.steps.extend(rest.steps);
    report
}

/// The part of the audit that concerns the board as a log: `log_integrity`
/// (the entry list against the signed tree head) and, when validator keys are
/// pinned, `validator_signatures`. Returns the report so far and the number
/// of entries the tree head covers (`None` when the log cannot be trusted).
pub fn audit_log_and_validators(
    cfg: &AuditConfig,
    checkpoint: &[u8],
    entries: &[crate::clients::wbb::RawSequencedEntry],
) -> (AuditReport, Option<usize>) {
    let mut report = AuditReport::default();
    let log = match verify_log(&cfg.log_key, &cfg.log_origin, checkpoint, entries) {
        Ok(log) => log,
        Err(problem) => {
            report.fail("log_integrity", problem);
            return (report, None);
        }
    };
    report.pass("log_integrity", log.detail.clone());
    let covered = log.leaves.len();

    if !cfg.validator_keys.is_empty() {
        match verify_validations(&cfg.validator_keys, &log, entries) {
            Ok(detail) => report.pass("validator_signatures", detail),
            Err(problem) => {
                report.fail("validator_signatures", problem);
                return (report, None);
            }
        }
    }
    (report, Some(covered))
}

/// Check every validator signature the board serves for the covered entries
/// against the PINNED validator keys. A validator signs slowly and on its own
/// schedule, so a missing signature is reported, not failed; a signature that
/// does not verify, or one attributed to an unknown validator, is a FAIL -
/// the board (or someone writing to it) is vouching falsely.
fn verify_validations(
    validator_keys: &[(String, Vec<u8>)],
    log: &VerifiedLog,
    entries: &[crate::clients::wbb::RawSequencedEntry],
) -> Result<String, String> {
    use crate::protocol::validators;
    let keys: HashMap<&str, &[u8]> = validator_keys
        .iter()
        .map(|(id, key)| (id.as_str(), key.as_slice()))
        .collect();
    let mut problems = Vec::new();
    let mut fully_validated = 0usize;
    let mut signatures = 0usize;
    for (index, (entry, leaf)) in entries.iter().zip(&log.leaves).enumerate() {
        let message = validators::validation_message(&log.origin, index as u64, leaf);
        let mut signers = HashSet::new();
        for validation in &entry.validations {
            let Some(key) = keys.get(validation.validator_id.as_str()) else {
                problems.push(format!(
                    "leaf {index}: signature attributed to unknown validator {}",
                    validation.validator_id
                ));
                continue;
            };
            let valid = BASE64
                .decode(&validation.signature)
                .map(|sig| validators::verify(key, &message, &sig))
                .unwrap_or(false);
            if valid {
                signers.insert(validation.validator_id.as_str());
                signatures += 1;
            } else {
                problems.push(format!(
                    "leaf {index}: signature of validator {} does not verify",
                    validation.validator_id
                ));
            }
        }
        if signers.len() == keys.len() {
            fully_validated += 1;
        }
    }
    if problems.is_empty() {
        // A validator that signed nothing at all under this tree head is
        // worth a loud line: the board may be withholding its signatures.
        let mut silent: Vec<&str> = keys
            .keys()
            .copied()
            .filter(|id| {
                !entries
                    .iter()
                    .take(log.leaves.len())
                    .any(|e| e.validations.iter().any(|v| v.validator_id == *id))
            })
            .collect();
        silent.sort_unstable();
        Ok(format!(
            "{signatures} validator signatures verify against the pinned keys; \
             {fully_validated} of {} entries are signed by all {} validators{}",
            log.leaves.len(),
            keys.len(),
            if silent.is_empty() {
                String::new()
            } else {
                format!(
                    "; WARNING: no signature at all from {} - they vouch for nothing here",
                    silent.join(", ")
                )
            }
        ))
    } else {
        Err(problems.join("; "))
    }
}

/// What `verify_log` established about a served entry list.
pub(crate) struct VerifiedLog {
    origin: String,
    /// Merkle leaf hashes of the covered entries, in order.
    pub(crate) leaves: Vec<crate::protocol::tlog::Hash>,
    detail: String,
}

/// Tie an entry list to a tree head signed by the pinned log key for the
/// pinned log name. A board can still show an OLDER genuine tree head (the
/// auditor keeps no state between runs): it then audits an older, consistent
/// prefix, and a missing later artifact fails further down.
pub(crate) fn verify_log(
    log_key: &p256::ecdsa::VerifyingKey,
    log_origin: &str,
    checkpoint: &[u8],
    entries: &[crate::clients::wbb::RawSequencedEntry],
) -> Result<VerifiedLog, String> {
    use crate::protocol::tlog;
    let head = tlog::verify_checkpoint(checkpoint, log_key).map_err(|e| e.to_string())?;
    if head.origin != log_origin {
        return Err(format!(
            "the tree head is for log {:?}, this audit is pinned to {log_origin:?}",
            head.origin
        ));
    }
    let size = head.size as usize;
    if entries.len() < size {
        return Err(format!(
            "the signed tree head covers {size} entries but the board serves {}",
            entries.len()
        ));
    }
    let mut leaves = Vec::with_capacity(size);
    for (position, entry) in entries.iter().take(size).enumerate() {
        if entry.leaf_index != position as i64 {
            return Err(format!(
                "leaf {} served at position {position}",
                entry.leaf_index
            ));
        }
        let leaf = tlog::leaf_hash(
            entry.entry.get().as_bytes(),
            position as u64,
            entry.timestamp,
        )
        .map_err(|e| format!("leaf {position}: {e}"))?;
        if let Some(claimed) = &entry.leaf_hash {
            if *claimed != hex::encode(leaf) {
                return Err(format!(
                    "leaf {position}: the board claims leaf hash {claimed}, its entry hashes to {}",
                    hex::encode(leaf)
                ));
            }
        }
        leaves.push(leaf);
    }
    match tlog::tree_root(&leaves) {
        Some(root) if root == head.root => Ok(VerifiedLog {
            detail: format!(
                "{size} entries hash to the root {} signed by the pinned log key ({}){}",
                hex::encode(&root[..8]),
                head.origin,
                match entries.len() - size {
                    0 => String::new(),
                    extra => format!(
                        "; {extra} newer served entries are not covered by this tree head and are NOT audited"
                    ),
                }
            ),
            origin: head.origin,
            leaves,
        }),
        Some(root) => Err(format!(
            "the served entries hash to root {}, the signed tree head says {}: \
             an entry was altered, dropped, reordered or re-timestamped",
            hex::encode(root),
            hex::encode(head.root)
        )),
        None => Err("the signed tree head is empty".to_string()),
    }
}

/// Audit a snapshot of raw log entries `(leaf_index, entry_json)`.
///
/// This is the same verification path `run_audit` uses after fetching; it is
/// public so the `auditor_detects_tamper` test can replay TAMPERED copies
/// of a fetched log and assert the failing step.
pub async fn audit_raw_entries(
    cfg: &AuditConfig,
    raw: Vec<(i64, serde_json::Value)>,
) -> AuditReport {
    let mut audited = Vec::with_capacity(raw.len());
    for (leaf_index, entry) in &raw {
        let Some(data_b64) = entry.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(data) = BASE64.decode(data_b64) else {
            continue;
        };
        let parsed = parse_wbb_data(&data);
        let signers = signers_of(entry);
        audited.push(AuditedEntry {
            leaf_index: *leaf_index,
            signed_data: data.clone(),
            data,
            parsed,
            signers,
        });
    }
    // A leaf the board writes when a co-signer arrives after publication: it
    // carries `ref:N` instead of the data, and a signature over the data of
    // leaf N. Resolve it, so a late signer neither escapes verification nor
    // fails it.
    let data_at: HashMap<i64, Vec<u8>> = audited
        .iter()
        .map(|e| (e.leaf_index, e.data.clone()))
        .collect();
    let mut dangling_refs = Vec::new();
    for entry in &mut audited {
        let Some(index) = entry
            .data
            .strip_prefix(b"ref:")
            .and_then(|rest| std::str::from_utf8(rest).ok())
            .and_then(|rest| rest.trim().parse::<i64>().ok())
        else {
            continue;
        };
        match data_at.get(&index) {
            Some(data) if index < entry.leaf_index => entry.signed_data = data.clone(),
            _ => dangling_refs.push(format!(
                "leaf {}: signs leaf {index}, which is not an earlier entry of this log",
                entry.leaf_index
            )),
        }
    }

    let keys: HashMap<String, VerifyingKey> = cfg.entity_keys.iter().cloned().collect();
    let (n_tt, t_tt) = (cfg.n_tt, cfg.t_tt);
    tokio::task::spawn_blocking(move || audit_entries(&audited, &keys, n_tt, t_tt, &dangling_refs))
        .await
        .unwrap_or_else(|e| {
            let mut report = AuditReport::default();
            report.fail("audit_execution", format!("audit task panicked: {e}"));
            report
        })
}

/// Extract `(entity_id, timestamp, signature)` triples from a raw log entry.
///
/// Join notes for a report line, one per DISTINCT note with a count: a box
/// that writes a thousand junk entries otherwise chooses how long the audit
/// report is, and the reader would count them by hand.
///
/// Notes about single board positions start with `leaf N: ` or `entry N: `,
/// so two notes about the same problem differ in that prefix only. They are
/// grouped by the rest of the text, and the positions are listed (the first
/// few of them) after it.
fn collapse_repeats(notes: &[String]) -> String {
    const SHOWN_POSITIONS: usize = 5;
    fn split(note: &str) -> (Option<(&str, &str)>, &str) {
        for kind in ["leaf ", "entry "] {
            if let Some(rest) = note.strip_prefix(kind) {
                if let Some((number, text)) = rest.split_once(": ") {
                    if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
                        return (Some((kind.trim_end(), number)), text);
                    }
                }
            }
        }
        (None, note)
    }
    let mut order: Vec<&str> = Vec::new();
    let mut groups: HashMap<&str, (usize, Vec<String>)> = HashMap::new();
    for note in notes {
        let (position, text) = split(note);
        let group = groups.entry(text).or_insert_with(|| {
            order.push(text);
            (0, Vec::new())
        });
        group.0 += 1;
        if let Some((kind, number)) = position {
            group.1.push(format!("{kind} {number}"));
        }
    }
    order
        .iter()
        .map(|text| {
            let (count, positions) = &groups[text];
            let at = match positions.len() {
                0 => String::new(),
                n if n <= SHOWN_POSITIONS => format!(" (at {})", positions.join(", ")),
                n => format!(
                    " (at {}, and {} more)",
                    positions[..SHOWN_POSITIONS].join(", "),
                    n - SHOWN_POSITIONS
                ),
            };
            match count {
                1 => format!("{text}{at}"),
                n => format!("{n} x {text}{at}"),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Who actually signed an entry, for the lines that name a liar: the entity
/// ids the signatures came under, never the id written inside the payload.
fn signer_names(entry: &AuditedEntry) -> String {
    if entry.signers.is_empty() {
        return "nobody".to_string();
    }
    entry
        .signers
        .iter()
        .map(|(id, _, _)| id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Single-signer entries carry `entity_id`/`signature`; co-signed entries
/// carry `entity_ids`/`signatures` with per-signer times in
/// `signer_timestamps` (the entry-level timestamp is last-submission-at).
fn signers_of(entry: &serde_json::Value) -> Vec<(String, i64, Vec<u8>)> {
    let entry_ts = entry.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
    let decode = |v: &serde_json::Value| -> Option<Vec<u8>> {
        v.as_str().and_then(|s| BASE64.decode(s).ok())
    };

    // One rule for who signed an entry, shared with the UIs: an entry that
    // carries both signer forms is signed by nobody (and fails below).
    let ids = crate::protocol::voting::entry_signer_ids(entry);
    if ids.is_empty() {
        return Vec::new();
    }
    if entry.get("entity_id").is_some() {
        return entry
            .get("signature")
            .and_then(decode)
            .map(|signature| vec![(ids[0].clone(), entry_ts, signature)])
            .unwrap_or_default();
    }

    let mut per_signer_ts: HashMap<String, i64> = HashMap::new();
    if let Some(times) = entry.get("signer_timestamps").and_then(|v| v.as_array()) {
        for t in times {
            if let (Some(id), Some(ts)) = (
                t.get("entity_id").and_then(|v| v.as_str()),
                t.get("timestamp").and_then(|v| v.as_i64()),
            ) {
                per_signer_ts.insert(id.to_string(), ts);
            }
        }
    }
    let sigs: Vec<Vec<u8>> = entry
        .get("signatures")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(decode).collect())
        .unwrap_or_default();
    ids.into_iter()
        .zip(sigs)
        .map(|(id, sig)| {
            let ts = per_signer_ts.get(&id).copied().unwrap_or(entry_ts);
            (id, ts, sig)
        })
        .collect()
}

/// The synchronous audit body (crypto-heavy, runs in `spawn_blocking`).
fn audit_entries(
    entries: &[AuditedEntry],
    keys: &HashMap<String, VerifyingKey>,
    n_tt: usize,
    t_tt: usize,
    dangling_refs: &[String],
) -> AuditReport {
    let mut report = AuditReport::default();

    // -- Step 1: every entry signature verifies against a known entity key,
    //    with the role/threshold requirements of the FIXED Sec. 3.4.2 write-policy table --
    let mut bad_signatures = dangling_refs.to_vec();
    for entry in entries {
        if let Some(parsed) = &entry.parsed {
            match required_signing(&parsed.entry_type) {
                Some((role, min_signers)) => {
                    if parsed.role != role {
                        bad_signatures.push(format!(
                            "leaf {}: {} entry declares role {}, policy requires {role}",
                            entry.leaf_index, parsed.entry_type, parsed.role
                        ));
                    }
                    // Only signers of the REQUIRED role count towards the
                    // threshold - the auditor must not delegate that check to
                    // the WBB's own policy enforcement.
                    let role_prefix = format!("{role}-");
                    let distinct: HashSet<&String> = entry
                        .signers
                        .iter()
                        .map(|(id, _, _)| id)
                        .filter(|id| id.starts_with(&role_prefix))
                        .collect();
                    if distinct.len() < min_signers || parsed.threshold < min_signers {
                        bad_signatures.push(format!(
                            "leaf {}: {} needs {min_signers} distinct {role} signers, \
                             got {} (declared threshold {})",
                            entry.leaf_index,
                            parsed.entry_type,
                            distinct.len(),
                            parsed.threshold
                        ));
                    }
                }
                None => bad_signatures.push(format!(
                    "leaf {}: unknown entry type {}",
                    entry.leaf_index, parsed.entry_type
                )),
            }
        }
        for (entity_id, timestamp, signature) in &entry.signers {
            let Some(key) = keys.get(entity_id) else {
                bad_signatures.push(format!(
                    "leaf {}: unknown entity {entity_id}",
                    entry.leaf_index
                ));
                continue;
            };
            let mut hasher = Sha256::new();
            hasher.update(&entry.signed_data);
            hasher.update(entity_id.as_bytes());
            hasher.update(format!("{timestamp}").as_bytes());
            let message = hasher.finalize();
            let valid = Signature::from_slice(signature)
                .map(|sig| key.verify(&message, &sig).is_ok())
                .unwrap_or(false);
            if !valid {
                bad_signatures.push(format!(
                    "leaf {}: invalid signature by {entity_id}",
                    entry.leaf_index
                ));
            }
        }
    }
    if bad_signatures.is_empty() {
        report.pass(
            "entry_signatures",
            format!("{} entries verified", entries.len()),
        );
    } else {
        report.fail("entry_signatures", collapse_repeats(&bad_signatures));
    }

    // -- Step 2: phase transitions form setup -> voting -> tallying ----------
    let transitions: Vec<(&str, &str)> = entries
        .iter()
        .filter_map(|e| e.parsed.as_ref())
        .filter(|p| p.entry_type == "phase_transition")
        .map(|p| (p.phase.as_str(), p.content.as_str()))
        .collect();
    if transitions == vec![("setup", "voting"), ("voting", "tallying")] {
        report.pass("phase_transitions", "setup -> voting -> tallying");
    } else {
        report.fail(
            "phase_transitions",
            format!("unexpected transition chain: {transitions:?}"),
        );
    }

    // -- Step 3: parse the election context and public parameters ----------
    let Some(context) =
        decode_single::<ElectionContext<G>>(entries, "election_pub_key", &mut report)
    else {
        return report;
    };
    let pipeline = PublicPipeline::new(PublicElection::new(context.clone()));

    let Some(counts_meta) =
        decode_single::<serde_json::Value>(entries, "pseudonymous_id_count", &mut report)
    else {
        return report;
    };
    let n_acc = counts_meta
        .get("n_acc")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let n_v = counts_meta.get("n_v").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let Some(short_accs) =
        decode_single::<Vec<ShortPublicACC<G>>>(entries, "acc_pub_key", &mut report)
    else {
        return report;
    };
    if short_accs.len() == n_acc && n_acc > 0 {
        report.pass(
            "election_setup",
            format!("context hash ok, {n_acc} public credentials"),
        );
    } else {
        report.fail(
            "election_setup",
            format!("{} public credentials vs n_acc {n_acc}", short_accs.len()),
        );
        return report;
    }

    // The tabulation tellers' public key shares (Sec. 3.5.2): exactly one
    // list, one share per teller, every t_tt of them interpolating to the
    // election key. Each threshold decryption below is held to them teller
    // by teller, so a partial under a key of the prover's own choosing is
    // attributed to the teller that returned it (Protocol 12).
    let Some(teller_shares) =
        decode_single::<Vec<TellerPublicShare>>(entries, "tt_public_shares", &mut report)
    else {
        return report;
    };
    if let Err(e) =
        teller_shares_bind_to_master(&teller_shares, &context.pk.params.tally.h, n_tt, t_tt)
    {
        report.fail("teller_shares", e);
        return report;
    }
    // The election context carries the same set (the library holds every
    // decryption and blinding to it): the two publications must agree.
    let in_context = &context.pk.params.tellers;
    if in_context.t != t_tt
        || in_context.n() != n_tt
        || teller_shares
            .iter()
            .any(|share| in_context.share_of(share.id) != Some(&share.h))
    {
        report.fail(
            "teller_shares",
            "the published teller shares differ from the election context's",
        );
        return report;
    }
    report.pass(
        "teller_shares",
        format!(
            "{n_tt} published teller shares interpolate to the election key and match the context"
        ),
    );

    let Some(eligible) = decode_single::<Vec<Vid>>(entries, "eligible_vids", &mut report) else {
        return report;
    };
    // The list of eligible identifiers is the electoral roll's word, and the
    // credential mix is built from it (Sec. 3.9 step 23): an identifier left
    // out loses its holder's vote at the very last filter, with every earlier
    // step still green. The roll published how many voters there are at
    // setup, so the list is checked against that: one entry per registered
    // voter, no repeats, all within the credential pool. A revocation swaps
    // an identifier for a spare, so the COUNT never changes.
    let Some(assigned) = decode_single::<Vec<u64>>(entries, "assigned_vids", &mut report) else {
        return report;
    };
    let assigned_set: HashSet<u64> = assigned.iter().copied().collect();
    // Revocations published by the roll: each one may swap ONE assigned
    // identifier for a spare, and nothing else may change the list.
    let revocations = entries
        .iter()
        .filter(|e| {
            e.parsed
                .as_ref()
                .is_some_and(|p| p.entry_type == "revocation_commitment")
        })
        .count();

    let mut eligible_problems = Vec::new();
    // What the roll committed to at setup - before anyone voted - is what
    // the tally-time list is held to.
    if assigned_set.len() != assigned.len() {
        eligible_problems.push("the identifiers assigned at setup contain repeats".to_string());
    }
    if assigned.len() != n_v {
        eligible_problems.push(format!(
            "{} identifiers were assigned at setup for {n_v} registered voters",
            assigned.len()
        ));
    }
    if let Some(out) = assigned
        .iter()
        .find(|vid| **vid == 0 || **vid as usize > n_acc)
    {
        eligible_problems.push(format!(
            "assigned identifier {out} is outside the credential pool 1..={n_acc}"
        ));
    }
    let swapped_in: Vec<u64> = eligible
        .iter()
        .map(|vid| vid.value())
        .filter(|vid| !assigned_set.contains(vid))
        .collect();
    if swapped_in.len() > revocations {
        eligible_problems.push(format!(
            "{} eligible identifiers were never assigned at setup ({:?}) but only {revocations} \
             revocations were published: an identifier was swapped without one",
            swapped_in.len(),
            swapped_in
        ));
    }
    if n_v == 0 {
        eligible_problems.push("the published voter count is missing or zero".to_string());
    } else if eligible.len() != n_v {
        eligible_problems.push(format!(
            "{} eligible identifiers for {n_v} registered voters: {} of them cannot vote",
            eligible.len(),
            n_v.saturating_sub(eligible.len())
        ));
    }
    let distinct: HashSet<u64> = eligible.iter().map(|vid| vid.value()).collect();
    if distinct.len() != eligible.len() {
        eligible_problems.push(format!(
            "{} of the {} eligible identifiers are repeats",
            eligible.len() - distinct.len(),
            eligible.len()
        ));
    }
    if let Some(out_of_range) = eligible
        .iter()
        .find(|vid| vid.value() == 0 || vid.value() as usize > n_acc)
    {
        eligible_problems.push(format!(
            "identifier {} is outside the credential pool 1..={n_acc}",
            out_of_range.value()
        ));
    }
    if eligible_problems.is_empty() {
        report.pass(
            "eligible_identifiers",
            format!(
                "{n_v} registered voters, {n_v} distinct eligible identifiers; {} of them differ \
                 from the identifiers assigned at setup, covered by {revocations} published \
                 revocations",
                swapped_in.len()
            ),
        );
    } else {
        report.fail("eligible_identifiers", collapse_repeats(&eligible_problems));
        return report;
    }

    // -- Step 4: ballot release - signer/bb linkage + digest linkage -------
    // Acceptance evidence from the voting phase: which distinct BBs signed a
    // `ballot_digest` entry for each digest (basis of the censorship
    // check).  A payload whose `receipt.bb_id` is not backed by that BB's own
    // signature on the entry does not count as acceptance evidence.
    let mut accepted_by: HashMap<crate::domain::BallotDigest, HashSet<u64>> = HashMap::new();
    // What each BB published next to a digest: the ballot emoji and the
    // PublicPINEmoji (Sec. 3.8.4 step 2), re-derived from the released ballot
    // further down.
    // EVERY entry counts, not the last one: a voter may have compared with
    // any of them.
    type PublishedEmoji = (i64, Vec<String>, Vec<String>);
    let mut published_emoji: HashMap<(crate::domain::BallotDigest, u64), Vec<PublishedEmoji>> =
        HashMap::new();
    // `ballot_digest` entries nobody can read: shown to voters all the same,
    // so they fail the emoji step instead of vanishing from it.
    let mut unreadable_digest_entries: Vec<i64> = Vec::new();
    let mut mislabelled_entries: Vec<String> = Vec::new();
    // The receipt a ballot box published for a ballot at cast time, by
    // (digest, box): `(seq_no, received_at_unix_ms)`. The box must release
    // the SAME receipt at tally - the sequence number decides which of a
    // voter's ballots the re-vote filter keeps (Sec. 3.9 step 10).
    // Every valid acceptance with the leaf it was published at: the board's
    // own order, which is what orders the tally (Sec. 3.9 step 10) - never a
    // ballot box's `seq_no`.
    let mut accepted_at: Vec<(u64, crate::domain::BallotDigest)> = Vec::new();
    let mut published_receipts: HashMap<(crate::domain::BallotDigest, u64), BTreeSet<(u64, u64)>> =
        HashMap::new();
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        if parsed.entry_type != "ballot_digest" {
            continue;
        }
        let Ok(payload) = parsed.decode_payload::<BallotDigestEntry>() else {
            unreadable_digest_entries.push(entry.leaf_index);
            continue;
        };
        let bb_id = payload.receipt.bb_id;
        let expected_signer = format!("BB-{bb_id}");
        if entry
            .signers
            .iter()
            .any(|(id, _, _)| *id == expected_signer)
        {
            accepted_by.entry(payload.digest).or_default().insert(bb_id);
            accepted_at.push((entry.leaf_index.max(0) as u64, payload.digest));
            published_receipts
                .entry((payload.digest, bb_id))
                .or_default()
                .insert((payload.receipt.seq_no, payload.receipt.received_at_unix_ms));
            published_emoji
                .entry((payload.digest, bb_id))
                .or_default()
                .push((
                    entry.leaf_index,
                    payload.emoji.clone(),
                    payload.public_pin_emoji.clone(),
                ));
        } else {
            // Signed by one ballot box, speaking for another: it proves
            // nothing, yet anyone reading the board sees it.
            mislabelled_entries.push(format!(
                "entry {}: a ballot_digest entry for BB-{bb_id} that BB-{bb_id} did not sign - \
                 signed by {}",
                entry.leaf_index,
                signer_names(entry)
            ));
        }
    }
    let voting_digests: HashSet<crate::domain::BallotDigest> =
        accepted_by.keys().copied().collect();

    // Confirmation evidence (Sec. 3.8.4 steps 13-15): which BBs published a
    // self-signed `cast_intended_proof` for each digest, with the disclosure
    // itself so it can be re-verified against the released ballot (Sec. 3.10
    // 1(d)).
    // EVERY confirmation is kept: the voter may have looked at any of them.
    let mut confirmed_by: HashMap<crate::domain::BallotDigest, HashMap<u64, Vec<CaiEntry>>> =
        HashMap::new();
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        if parsed.entry_type != "cast_intended_proof" {
            continue;
        }
        let Ok(payload) = parsed.decode_payload::<CaiEntry>() else {
            mislabelled_entries.push(format!(
                "entry {}: a cast_intended_proof entry that cannot be read",
                entry.leaf_index
            ));
            continue;
        };
        let expected_signer = format!("BB-{}", payload.bb_id);
        if entry
            .signers
            .iter()
            .any(|(id, _, _)| *id == expected_signer)
        {
            confirmed_by
                .entry(payload.digest)
                .or_default()
                .entry(payload.bb_id)
                .or_default()
                .push(payload);
        } else {
            mislabelled_entries.push(format!(
                "entry {}: a cast_intended_proof entry for BB-{} that BB-{} did not sign - \
                 signed by {}",
                entry.leaf_index,
                payload.bb_id,
                payload.bb_id,
                signer_names(entry)
            ));
        }
    }

    // `ballot_metadata` (Sec. 3.8.4): signed by the box it names, and about a
    // ballot that box really accepted. Its `bb_id_enc` is not used by this
    // PoC's tally (see the deviations register), so this is all that can be
    // said about it from the log.
    let mut metadata_problems = Vec::new();
    let mut metadata_checked = 0usize;
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        if parsed.entry_type != "ballot_metadata" {
            continue;
        }
        let Ok(payload) = parsed.decode_payload::<crate::protocol::voting::BallotMetadataEntry>()
        else {
            metadata_problems.push(format!(
                "entry {}: a ballot_metadata entry that cannot be read",
                entry.leaf_index
            ));
            continue;
        };
        let signer = format!("BB-{}", payload.bb_id);
        if !entry.signers.iter().any(|(id, _, _)| *id == signer) {
            metadata_problems.push(format!(
                "entry {}: ballot_metadata for BB-{} that BB-{} did not sign - signed by {}",
                entry.leaf_index,
                payload.bb_id,
                payload.bb_id,
                signer_names(entry)
            ));
        } else if !published_emoji.contains_key(&(payload.digest, payload.bb_id)) {
            metadata_problems.push(format!(
                "entry {}: BB-{} published metadata for digest {}, which it never accepted",
                entry.leaf_index, payload.bb_id, payload.digest
            ));
        } else {
            metadata_checked += 1;
        }
    }

    // What the board says counts (Sec. 3.9 steps 3 and 5): a digest at least
    // one box published, with at least one published disclosure - the same
    // rule the tally driver and the voter app apply. Whether a disclosure is
    // VALID is settled below, against the released ballots; the counted set
    // proper is `counted`, defined there.
    let counted_on_board = crate::protocol::voting::counted_digests(
        accepted_by
            .iter()
            .flat_map(|(digest, boxes)| boxes.iter().map(move |bb| (*digest, *bb))),
        confirmed_by
            .iter()
            .flat_map(|(digest, boxes)| boxes.keys().map(move |bb| (*digest, *bb))),
    );

    // -- What the ballot boxes published for the voters to look at must at
    //    least be readable, and be the word of the box it names (Sec. 3.8.4
    //    step 2, Sec. 3.8.5). Whether it is TRUE is settled further down,
    //    against the released ballots.
    let entry_problems: Vec<String> = metadata_problems
        .into_iter()
        .chain(
            unreadable_digest_entries
                .iter()
                .map(|leaf| format!("entry {leaf}: a ballot_digest entry that cannot be read")),
        )
        .chain(mislabelled_entries.iter().cloned())
        .collect();
    if entry_problems.is_empty() {
        report.pass(
            "published_entries",
            format!(
                "{} digest entries, {} confirmations and {metadata_checked} metadata entries \
                 are readable and signed by the ballot box they name",
                published_emoji.values().map(Vec::len).sum::<usize>(),
                confirmed_by
                    .values()
                    .map(|m| m.values().map(Vec::len).sum::<usize>())
                    .sum::<usize>()
            ),
        );
    } else {
        // These entries count for nothing (the apps ignore them, the auditor
        // does not use them), so the result is untouched: what they are is
        // evidence against the box that signed them (Sec. 3.8.4 step 15:
        // divergent data is published, and visible).
        report.warn("published_entries", collapse_repeats(&entry_problems));
    }

    let mut per_bb: BTreeMap<u64, Vec<BallotRecord<G>>> = BTreeMap::new();
    let mut released_by: HashMap<crate::domain::BallotDigest, HashSet<u64>> = HashMap::new();
    let mut release_problems = Vec::new();
    // The tally's input is fixed when the tally starts: the releases
    // sequenced before its first artifact (the driver publishes every
    // release first, and refuses to start over one it did not take in). A
    // release written after that changed nothing the tally used: it is
    // named, not counted.
    let tally_start = entries
        .iter()
        .filter(|entry| {
            entry.parsed.as_ref().is_some_and(|parsed| {
                matches!(
                    parsed.entry_type.as_str(),
                    "mixed_ballots"
                        | "re_encryption_proof"
                        | "credential_control"
                        | "tally_proof"
                        | "tally_result"
                )
            })
        })
        .map(|entry| entry.leaf_index)
        .min()
        .unwrap_or(i64::MAX);
    // A tally that states its input in its first artifact (the release
    // entries it took in) is audited on exactly that input: a release any
    // box wrote outside it - even in the moment before that artifact - is
    // named and not counted. Without a statement, the cut above applies.
    let stated_inputs: Option<HashSet<String>> = entries
        .iter()
        .filter_map(|entry| {
            let parsed = entry.parsed.as_ref()?;
            if parsed.entry_type != "re_encryption_proof" {
                return None;
            }
            match parsed.decode_payload::<ReEncryptionProofEntry>().ok()? {
                ReEncryptionProofEntry::OxFingerprints { inputs, .. } if !inputs.is_empty() => {
                    Some(inputs.into_iter().collect())
                }
                _ => None,
            }
        })
        .next();
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        if parsed.entry_type != "encrypted_ballot" {
            continue;
        }
        if stated_inputs.is_none() && entry.leaf_index > tally_start {
            release_problems.push(format!(
                "leaf {}: {} released a ballot after the tally had started (entry {}); \
                 not part of the tally input",
                entry.leaf_index,
                entry
                    .signers
                    .first()
                    .map(|(id, _, _)| id.as_str())
                    .unwrap_or("an unknown signer"),
                tally_start
            ));
            continue;
        }
        let record = match parsed.decode_payload::<EncryptedBallotEntry>() {
            Ok(e) => e.record,
            Err(e) => {
                release_problems.push(format!(
                    "leaf {}: {} released a record that cannot be read ({e})",
                    entry.leaf_index,
                    entry
                        .signers
                        .first()
                        .map(|(id, _, _)| id.as_str())
                        .unwrap_or("an unknown signer")
                ));
                continue;
            }
        };
        let bb_id = record.receipt.bb_id;
        let expected_signer = format!("BB-{bb_id}");
        if !entry
            .signers
            .iter()
            .any(|(id, _, _)| *id == expected_signer)
        {
            // A box speaking for another one: this release is nobody's.
            release_problems.push(format!(
                "leaf {}: released by {:?}, receipt claims {expected_signer}",
                entry.leaf_index,
                entry
                    .signers
                    .iter()
                    .map(|(id, _, _)| id)
                    .collect::<Vec<_>>()
            ));
            continue;
        }
        match ballot_digest(&record.ballot) {
            Ok(digest) if voting_digests.contains(&digest) => {
                // Sec. 3.4.2: a box writes each release once. A second copy
                // changes nothing (the reconciliation keeps one) but is named.
                if !released_by.entry(digest).or_default().insert(bb_id) {
                    release_problems.push(format!(
                        "leaf {}: BB-{bb_id} released digest {digest} a second time",
                        entry.leaf_index
                    ));
                }
                // The receipt released at tally must be the one published
                // during voting: otherwise a single box could re-order a
                // voter's ballots by sequence number and decide which one
                // the re-vote filter keeps - invisibly, since everything it
                // releases would still be self-consistent.
                let released = (record.receipt.seq_no, record.receipt.received_at_unix_ms);
                match published_receipts.get(&(digest, bb_id)) {
                    // The release rule (Sec. 3.9 step 3) releases a counted
                    // ballot whose digest ANY box published: this box's own
                    // publication may have been lost on its channel to the
                    // board, and releasing on another box's is what it must
                    // do - not misconduct.
                    None => {}
                    Some(published) if !published.contains(&released) => {
                        release_problems.push(format!(
                            "leaf {}: BB-{bb_id} releases digest {digest} with receipt \
                             (seq_no {}, received {}) but published {published:?}",
                            entry.leaf_index, released.0, released.1
                        ))
                    }
                    Some(published) if published.len() > 1 => release_problems.push(format!(
                        "leaf {}: BB-{bb_id} published {} different receipts for digest \
                         {digest} and could pick between them at tally",
                        entry.leaf_index,
                        published.len()
                    )),
                    Some(_) => {}
                }
            }
            Ok(digest) => {
                // A ballot the voting phase never saw: it cannot count
                // (Sec. 3.9 step 3) and is not taken into the tally input.
                release_problems.push(format!(
                    "leaf {}: BB-{bb_id} released digest {digest}, which no box published \
                     during voting",
                    entry.leaf_index
                ));
                continue;
            }
            Err(e) => {
                release_problems.push(format!("leaf {}: digest error ({e})", entry.leaf_index));
                continue;
            }
        }
        // Every check above names what this release says about its box,
        // counted or not; only now is it held to the tally's stated input.
        if let Some(stated) = &stated_inputs {
            if !stated.contains(&crate::protocol::tally::release_input_id(&entry.data)) {
                release_problems.push(format!(
                    "leaf {}: BB-{bb_id} released a ballot the tally did not take in (its \
                     first artifact states its input); not counted",
                    entry.leaf_index
                ));
                continue;
            }
        }
        per_bb.entry(bb_id).or_default().push(record);
    }
    let released: usize = per_bb.values().map(Vec::len).sum();
    if released == 0 {
        report.fail("ballot_release", "no encrypted_ballot entries");
        return report;
    }
    if release_problems.is_empty() {
        report.pass(
            "ballot_release",
            format!("{released} released records across {} BBs", per_bb.len()),
        );
    } else {
        // None of this changes the result: the cast order comes from the
        // board, a phantom or foreign release is left out, and the ballot is
        // counted from an honest copy. It is evidence against the box.
        report.warn(
            "ballot_release",
            format!(
                "{released} released records across {} BBs; {}",
                per_bb.len(),
                collapse_repeats(&release_problems)
            ),
        );
    }

    // Ground truth for everything a ballot box published about a digest: the
    // ballot RELEASED for it, by whichever box released it. The digest binds
    // the ballot, so any release serves - a box cannot escape the check by
    // publishing about a ballot it never releases itself.
    let mut released_ballot: HashMap<
        crate::domain::BallotDigest,
        &evoting::api::prelude::Ballot<G>,
    > = HashMap::new();
    let mut digestless_releases = Vec::new();
    // Who released each digest, to name a box that released a record that is
    // not a ballot at all.
    let mut released_by: HashMap<crate::domain::BallotDigest, Vec<u64>> = HashMap::new();
    for (bb_id, records) in &per_bb {
        for record in records {
            match ballot_digest(&record.ballot) {
                Ok(digest) => {
                    released_ballot.entry(digest).or_insert(&record.ballot);
                    released_by.entry(digest).or_default().push(*bb_id);
                }
                Err(_) => {
                    digestless_releases
                        .push(format!("BB-{bb_id} released a ballot that has no digest"));
                }
            }
        }
    }

    // -- Sec. 3.9 step 2 / Sec. 3.10 1(d): a released ballot counts on ONE
    //    published disclosure that opens on it. Every published disclosure is
    //    re-opened on the released ballot; a box whose disclosure does not
    //    open, or shows values the ballot does not hold, is named - the
    //    ballot still counts if another box's disclosure opens (Sec. 3.8.4
    //    step 15: divergent data is published, visible, not fatal). A box
    //    releasing a ballot it never confirmed itself, or confirming a ballot
    //    whose digest it never published, is named too: Sec. 3.9 step 2 has
    //    a box release what IT received a valid disclosure for, and Sec.
    //    3.8.4 step 13 has it open the disclosure of a ballot it holds.
    let mut box_conduct: Vec<String> = Vec::new();
    let mut confirmed_releases = 0usize;
    // Releases made on ANOTHER box's published disclosure: what A9 asks of an
    // honest box when its own `/cai` round trip failed (Sec. 3.8.4 step 15
    // publishes every box's disclosure, and step 2 releases what carries a
    // valid one). This is not misconduct and must not read like it; the boxes
    // that release something NO valid disclosure covers are named further
    // down, once the disclosures have been opened on the released ballots.
    let mut released_on_another_boxes_word = 0usize;
    for (bb_id, records) in &per_bb {
        for record in records {
            let Ok(digest) = ballot_digest(&record.ballot) else {
                continue; // reported below
            };
            if confirmed_by
                .get(&digest)
                .and_then(|m| m.get(bb_id))
                .is_none()
            {
                released_on_another_boxes_word += 1;
            } else {
                confirmed_releases += 1;
            }
        }
    }
    for (digest, per_box) in &confirmed_by {
        for bb_id in per_box.keys() {
            if !published_emoji.contains_key(&(*digest, *bb_id)) {
                box_conduct.push(format!(
                    "digest {digest}: BB-{bb_id} published a confirmation for a ballot whose \
                     digest it never published - it held the ballot and did not publish it"
                ));
            }
        }
    }
    let all_confirmations: Vec<CaiEntry> = confirmed_by
        .values()
        .flat_map(|per_box| per_box.values().flatten().cloned())
        .collect();
    let released_owned: HashMap<crate::domain::BallotDigest, evoting::api::prelude::Ballot<G>> =
        released_ballot
            .iter()
            .map(|(digest, ballot)| (*digest, (*ballot).clone()))
            .collect();
    let disclosures =
        crate::protocol::tally::valid_disclosures(&released_owned, &all_confirmations, &context);
    box_conduct.extend(disclosures.misconduct.iter().cloned());
    // A released record whose own proofs do not verify is not a ballot: it
    // cannot count, and it cannot be "revealed" either. The box that released
    // it is named (Sec. 3.9 step 5 discards it; Sec. 3.10 1(d) checks against
    // ballots).
    for digest in &disclosures.not_ballots {
        let boxes: Vec<String> = released_by
            .get(digest)
            .into_iter()
            .flatten()
            .map(|bb_id| format!("BB-{bb_id}"))
            .collect();
        box_conduct.push(format!(
            "digest {digest}: {} released a record that is not a ballot - its proofs do not \
             verify - and nothing published for it is weighed",
            boxes.join(", ")
        ));
    }
    // A ballot opened on two different slots is not one box's word against
    // another: the vote is public and nothing can undo it, so this FAILS.
    let revealed = disclosures.revealed.clone();
    box_conduct.extend(disclosures.unaccounted.iter().cloned());
    // The counted set proper: what the board counts AND a valid disclosure
    // was published for. A released ballot the board counts whose every
    // published disclosure fails is not counted - and the boxes that
    // published those disclosures are named above.
    let counted: HashSet<crate::domain::BallotDigest> = counted_on_board
        .iter()
        .filter(|digest| disclosures.valid.contains(digest))
        .copied()
        .collect();
    let not_counted_after_all = counted_on_board
        .iter()
        .filter(|digest| released_ballot.contains_key(digest) && !counted.contains(digest))
        .count();
    // A box that released a ballot NO published disclosure opens on is the
    // one worth naming: it released something nobody confirmed. A box that
    // released one covered by another box's valid disclosure did what A9
    // asks of it.
    for (bb_id, records) in &per_bb {
        for record in records {
            if let Ok(digest) = ballot_digest(&record.ballot) {
                if !disclosures.valid.contains(&digest) {
                    box_conduct.push(format!(
                        "digest {digest} released by BB-{bb_id}, which no published \
                         cast-as-intended disclosure opens on"
                    ));
                }
            }
        }
    }
    // Two different counts, and they must not be confused: how many RELEASED
    // ballots carry no valid disclosure at all (Sec. 3.10 1(c)-(d) discards
    // them), and how many of those the board nevertheless counted.
    let released_without_valid = released_ballot
        .keys()
        .filter(|digest| !disclosures.valid.contains(digest))
        .count();
    let summary = format!(
        "{} counted ballots have a valid disclosure, {released_without_valid} released \
         ballot(s) have none ({not_counted_after_all} of them counted on the board and \
         therefore dropped); {confirmed_releases} released records carry the releasing box's \
         own disclosure and {released_on_another_boxes_word} another box's",
        counted.len()
    );
    if !revealed.is_empty() {
        report.fail(
            "cai_confirmation",
            format!("{summary}; {}", collapse_repeats(&revealed)),
        );
    } else if box_conduct.is_empty() {
        report.pass("cai_confirmation", summary);
    } else {
        report.warn(
            "cai_confirmation",
            format!("{summary}; {}", collapse_repeats(&box_conduct)),
        );
    }

    // -- Published emoji (Sec. 3.8.4 step 2, Sec. 3.8.5 item 2): what a BB
    //    published for the voter to compare must be what the released ballot
    //    really hashes to.
    let mut emoji_problems: Vec<String> = digestless_releases;
    let mut emoji_checked = 0usize;
    let mut unreleased = 0usize;
    for (bb_id, records) in &per_bb {
        for record in records {
            if let Ok(digest) = ballot_digest(&record.ballot) {
                // Only a ballot NO box published a digest entry for: the
                // release rule has a box release on another box's entry.
                if !published_emoji
                    .keys()
                    .any(|(published, _)| *published == digest)
                {
                    emoji_problems.push(format!(
                        "digest {digest}: BB-{bb_id} released a ballot no box published a digest entry for"
                    ));
                }
            }
        }
    }
    for ((digest, bb_id), published) in &published_emoji {
        let Some(ballot) = released_ballot.get(digest) else {
            unreleased += published.len();
            continue; // never released: only the voter can check it
        };
        let as_strings =
            |emoji: Vec<&str>| emoji.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let ballot_emoji = as_strings(ballot.to_emoji());
        let pin_emoji = as_strings(ballot.public_pin_emoji());
        for (leaf, shown_ballot_emoji, shown_pin_emoji) in published {
            if *shown_ballot_emoji != ballot_emoji {
                emoji_problems.push(format!(
                    "digest {digest}, entry {leaf}: BB-{bb_id} published a ballot emoji the released ballot does not hash to"
                ));
            } else if *shown_pin_emoji != pin_emoji {
                emoji_problems.push(format!(
                    "digest {digest}, entry {leaf}: BB-{bb_id} published a public PIN emoji the released ballot does not hash to"
                ));
            } else {
                emoji_checked += 1;
            }
        }
    }
    if emoji_problems.is_empty() {
        report.pass(
            "published_emoji",
            format!(
                "{emoji_checked} digest entries show the emoji of the released ballot; \
                 {unreleased} are about ballots nobody released (unconfirmed ones), which \
                 only their voter can check"
            ),
        );
    } else {
        // A wrong emoji next to a digest is a lie by the box that published
        // it, visible to the voter it was shown to; the released ballot is
        // what it is, and it is what gets counted.
        report.warn(
            "published_emoji",
            format!(
                "{emoji_checked} digest entries verified; {}",
                collapse_repeats(&emoji_problems)
            ),
        );
    }

    // From here on the boxes' own sequence numbers play no part: every
    // record is re-keyed with the board's order (Sec. 3.9 step 10).
    let board_order = crate::protocol::tally::board_cast_order(accepted_at);
    let per_bb_lists: Vec<Vec<BallotRecord<G>>> = match per_bb
        .into_values()
        .map(|records| crate::protocol::tally::order_by_board(records, &board_order))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(lists) => lists,
        Err(e) => {
            report.fail("ballot_reconciliation", e.to_string());
            return report;
        }
    };
    let records = match reconcile_ballots(&per_bb_lists, &counted) {
        Ok(records) => {
            report.pass(
                "ballot_reconciliation",
                format!("{} ballots after the bot filter", records.len()),
            );
            records
        }
        Err(e) => {
            report.fail("ballot_reconciliation", e.to_string());
            return report;
        }
    };

    // -- Release completeness (Sec. 3.9 step 3, thesis A9): every ballot the
    //    board counts should be in the tally input. Released by nobody is a
    //    censored ballot: Sec. 3.9 step 4 NAMES every box that published its
    //    digest and the count goes on without it, so it is a named WARNING,
    //    not a failure (a failure would hand one box that fabricates a
    //    confirmation a veto over the election). Released by one box while
    //    another that accepted and confirmed it withheld it is that box's
    //    misconduct, and the ballot is counted from the copy released -----
    let reconciled_digests: HashSet<crate::domain::BallotDigest> = records
        .iter()
        .filter_map(|r| ballot_digest(&r.ballot).ok())
        .collect();
    let mut unreleased: Vec<String> = Vec::new();
    let mut withholding: BTreeMap<u64, usize> = BTreeMap::new();
    let mut accepted_but_unconfirmed = 0usize;
    for (digest, acceptors) in &accepted_by {
        if !counted_on_board.contains(digest) {
            // Unconfirmed during voting: exclusion is the protocol outcome.
            // Nobody can be blamed from the log alone (the voter may never
            // have confirmed), so it is reported, not failed.
            accepted_but_unconfirmed += 1;
            continue;
        }
        if !released_owned.contains_key(digest) {
            // Published and confirmed, released by nobody: every box that
            // published the digest held the ballot and did not release it -
            // or the confirmation was never the voter's, made up by the box
            // that published it. Either way the boxes are named (Sec. 3.9
            // step 4 attributes exactly this) and the ballot is not counted.
            let mut boxes: Vec<u64> = acceptors.iter().copied().collect();
            boxes.sort_unstable();
            unreleased.push(format!(
                "digest {digest} published and confirmed on the board but released by NO box: \
                 held back by {} (or its confirmation was never the voter's)",
                boxes
                    .iter()
                    .map(|bb| format!("BB-{bb}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            continue;
        }
        if !counted.contains(digest) {
            continue; // released, but no valid disclosure: named in cai_confirmation
        }
        if !reconciled_digests.contains(digest) {
            // Released and counted, yet missing from the reconciled list:
            // the reconciliation step above would have failed.
            continue;
        }
        let releasers = released_by.get(digest).cloned().unwrap_or_default();
        let confirmers: Vec<u64> = confirmed_by
            .get(digest)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for bb in crate::protocol::voting::counting_ballot_boxes(
            &acceptors.iter().copied().collect::<Vec<_>>(),
            &confirmers,
        ) {
            if !releasers.contains(&bb) {
                *withholding.entry(bb).or_default() += 1;
            }
        }
    }
    let summary = format!(
        "all {} counted ballots present in the release; {accepted_but_unconfirmed} more were \
         published during voting but never confirmed on the board, and are not counted",
        counted.len()
    );
    let mut conduct: Vec<String> = unreleased;
    conduct.extend(withholding.iter().map(|(bb, n)| {
        format!(
            "BB-{bb} accepted and confirmed {n} ballot(s) it then did NOT release \
             (counted from another box's copy)"
        )
    }));
    if conduct.is_empty() {
        report.pass("release_completeness", summary);
    } else {
        report.warn(
            "release_completeness",
            format!("{summary}; {}", collapse_repeats(&conduct)),
        );
    }

    // -- Step 5: strict artifact inventory, then ox dedup -------------
    // Exactly one proof entry per pipeline stage and one mix artifact per
    // kind; a malformed or duplicate artifact of a known type is a FAIL, not
    // something to skip past.
    let mut inventory_problems = Vec::new();
    let mut proofs = Vec::new();
    let mut mixes = Vec::new();
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        match parsed.entry_type.as_str() {
            // The control elements are the registration tellers' to write
            // (Sec. 3.4.2); every other tally proof is the tabulation
            // tellers'. A proof under the wrong authorship is not accepted.
            "re_encryption_proof" => match parsed.decode_payload::<ReEncryptionProofEntry>() {
                Ok(ReEncryptionProofEntry::Controls { .. }) => inventory_problems.push(format!(
                    "leaf {}: credential control elements published by the TTs, not the RTs",
                    entry.leaf_index
                )),
                Ok(proof) => proofs.push(proof),
                Err(e) => inventory_problems.push(format!(
                    "leaf {}: undecodable proof ({e})",
                    entry.leaf_index
                )),
            },
            "credential_control" => match parsed.decode_payload::<ReEncryptionProofEntry>() {
                Ok(proof @ ReEncryptionProofEntry::Controls { .. }) => proofs.push(proof),
                Ok(_) => inventory_problems.push(format!(
                    "leaf {}: a credential_control entry that carries another proof",
                    entry.leaf_index
                )),
                Err(e) => inventory_problems.push(format!(
                    "leaf {}: undecodable credential control elements ({e})",
                    entry.leaf_index
                )),
            },
            "mixed_ballots" => match parsed.decode_payload::<MixedBallotsEntry>() {
                Ok(mix) => mixes.push(mix),
                Err(e) => inventory_problems
                    .push(format!("leaf {}: undecodable mix ({e})", entry.leaf_index)),
            },
            _ => {}
        }
    }
    let mut ox = None;
    let mut controls_entry = None;
    let mut acc = None;
    let mut cred_fps = None;
    for proof in proofs {
        let (slot, kind): (&mut Option<_>, _) = match proof {
            ReEncryptionProofEntry::OxFingerprints { .. } => (&mut ox, "ox_fingerprints"),
            ReEncryptionProofEntry::Controls { .. } => (&mut controls_entry, "controls"),
            ReEncryptionProofEntry::AccChecks { .. } => (&mut acc, "acc_checks"),
            ReEncryptionProofEntry::CredentialFingerprints { .. } => {
                (&mut cred_fps, "credential_fingerprints")
            }
        };
        if slot.replace(proof).is_some() {
            inventory_problems.push(format!("duplicate {kind} proof entry"));
        }
    }
    let mut vote_mix = None;
    let mut cred_mix = None;
    for mix in mixes {
        let (slot, kind): (&mut Option<_>, _) = match mix {
            MixedBallotsEntry::Votes { .. } => (&mut vote_mix, "votes"),
            MixedBallotsEntry::Credentials { .. } => (&mut cred_mix, "credentials"),
        };
        if slot.replace(mix).is_some() {
            inventory_problems.push(format!("duplicate {kind} mix entry"));
        }
    }
    for (missing, name) in [
        (ox.is_none(), "ox_fingerprints proof"),
        (controls_entry.is_none(), "controls proof"),
        (acc.is_none(), "acc_checks proof"),
        (cred_fps.is_none(), "credential_fingerprints proof"),
        (vote_mix.is_none(), "votes mix"),
        (cred_mix.is_none(), "credentials mix"),
    ] {
        if missing {
            inventory_problems.push(format!("missing {name} entry"));
        }
    }
    if inventory_problems.is_empty() {
        report.pass(
            "artifact_inventory",
            "exactly one proof entry per stage, one mix per kind",
        );
    } else {
        report.fail("artifact_inventory", collapse_repeats(&inventory_problems));
        return report;
    }
    let Some(ReEncryptionProofEntry::OxFingerprints {
        fps: ox_fps,
        decryptions: dec_ox,
        ..
    }) = ox
    else {
        unreachable!("inventory guarantees the ox slot holds the ox variant");
    };
    let params = &context.pk.params;
    // Every published threshold decryption must verify AND every partial in
    // it must carry the share published for the teller that signed it -
    // otherwise a teller (or colluding signers) can fabricate
    // self-consistent decryptions under keys of their own.
    let check_decs = |decs: &[ThresholdDecOk<G>]| -> Result<(), String> {
        for (i, dec) in decs.iter().enumerate() {
            // `verify` holds every partial to the tellers' published shares
            // (id, key share, proof, and the share the proof covers) and the
            // interpolation to the plaintext; a failing partial names its teller.
            dec.verify(params).map_err(|e| match e {
                evoting::error::Error::FailedVerifiableDecryption(id) => format!(
                    "decryption {i}: the partial of TT-{id} is not under its published share, \
                     its proof does not hold, or its share is not the one proven"
                ),
                evoting::error::Error::IdOutOfRange(id) => {
                    format!("decryption {i}: a partial from TT-{id}, which is no teller")
                }
                other => format!("decryption proof {i} invalid: {other:?}"),
            })?;
        }
        Ok(())
    };

    if let Err(e) = check_decs(&dec_ox) {
        report.fail("ox_dedup", format!("ox {e}"));
        return report;
    }
    // An honest ox fingerprint is the re-vote handle blinded with a secret
    // scalar; it is the group identity only when that scalar is zero, which
    // would collapse every ballot to the same handle and let the re-vote
    // filter keep just one for the whole election (Sec. 3.9 steps 6-10). The
    // blinding factor itself is never published, so this is what the log can
    // be asked about.
    if dec_ox
        .iter()
        .any(|dec| <G as dlog_group::group::GroupPoint>::is_id(&dec.plaintext))
    {
        report.fail(
            "ox_dedup",
            "an ox fingerprint decrypts to the identity: the re-vote handles were blinded \
             with zero, which makes every ballot look like the same voter's"
                .to_string(),
        );
        return report;
    }
    let deduped = match pipeline.filter_revotes_ox(&records, &ox_fps, &dec_ox) {
        Ok(deduped) => {
            report.pass(
                "ox_dedup",
                format!("{} ballots after last-vote-wins", deduped.len()),
            );
            deduped
        }
        Err(e) => {
            report.fail("ox_dedup", format!("{e:?}"));
            return report;
        }
    };

    // -- Step 6: ballot proofs + vote mix ----------------------------------
    let originals = match pipeline.verify_ballots(&deduped) {
        Ok(originals) => {
            report.pass(
                "ballot_validity",
                format!("{} ballot proof sets verified", originals.len()),
            );
            originals
        }
        Err(e) => {
            report.fail("ballot_validity", format!("{e:?}"));
            return report;
        }
    };

    let Some(MixedBallotsEntry::Votes { artifact: vote_art }) = vote_mix else {
        unreachable!("inventory guarantees the votes slot holds the votes variant");
    };
    match pipeline.verify_vote_mix(&originals, &vote_art) {
        Ok(()) => report.pass(
            "vote_mix",
            format!(
                "shuffle proof over {} votes verified",
                vote_art.shuffled.len()
            ),
        ),
        Err(e) => {
            report.fail("vote_mix", format!("{e:?}"));
            return report;
        }
    }

    // -- Step 7: controls + ACC checks + invalid-vote filter ---------------
    let Some(ReEncryptionProofEntry::Controls { controls }) = controls_entry else {
        unreachable!("inventory guarantees the controls slot holds the controls variant");
    };
    let Some(ReEncryptionProofEntry::AccChecks {
        acc_checks,
        blinding,
    }) = acc
    else {
        unreachable!("inventory guarantees the acc slot holds the acc_checks variant");
    };
    if let Err(e) = check_decs(&acc_checks) {
        report.fail("acc_checks", format!("ACC-check {e}"));
        return report;
    }
    // The blinding is the tellers' threshold secret: every share is
    // re-verified against the re-derived checks and the VSS commitments
    // inside `verify_acc_checks` / `filter_invalid`. A degenerate blinding is
    // refused by the library's own combination, not here: an identity public
    // share, and a joint exponent of zero, which would make every blinded
    // check the identity - Sec. 3.9 step 22's "valid credential" verdict.
    if let Err(e) =
        pipeline.verify_acc_checks(&acc_checks, &controls, &vote_art.shuffled, &blinding)
    {
        report.fail("acc_checks", format!("{e:?}"));
        return report;
    }
    let valid = match pipeline.filter_invalid(&vote_art.shuffled, &controls, &acc_checks, &blinding)
    {
        Ok(valid) => {
            report.pass(
                "acc_checks",
                format!("{} votes hold a well-formed credential", valid.len()),
            );
            valid
        }
        Err(e) => {
            report.fail("acc_checks", format!("{e:?}"));
            return report;
        }
    };

    // -- Step 8: credential mix over the eligible list ---------------------
    let mut eligible_shorts = Vec::with_capacity(eligible.len());
    for vid in &eligible {
        match short_accs.get((vid.value() - 1) as usize) {
            Some(short) => eligible_shorts.push(short.clone()),
            None => {
                report.fail(
                    "credential_mix",
                    format!("eligible vid {vid} has no public credential"),
                );
                return report;
            }
        }
    }
    let Some(MixedBallotsEntry::Credentials { artifact: cred_art }) = cred_mix else {
        unreachable!("inventory guarantees the credentials slot holds the credentials variant");
    };
    match pipeline.verify_cred_mix(&eligible_shorts, &cred_art) {
        Ok(()) => report.pass(
            "credential_mix",
            format!(
                "shuffle proof over {} eligible credentials verified",
                eligible_shorts.len()
            ),
        ),
        Err(e) => {
            report.fail("credential_mix", format!("{e:?}"));
            return report;
        }
    }

    // -- Step 9: credential fingerprints + the Sec. 3.9 step 27 discard ------
    let Some(ReEncryptionProofEntry::CredentialFingerprints { fps: fps2, bundle }) = cred_fps
    else {
        unreachable!("inventory guarantees the fps slot holds the fingerprints variant");
    };
    if let Err(e) = check_decs(&bundle.dec_pub_fps).and_then(|()| check_decs(&bundle.dec_votes_fps))
    {
        report.fail("illicit_filter", format!("fingerprint {e}"));
        return report;
    }
    // As for the ox handles: a credential fingerprint that decrypts to the
    // identity means the blinding was zero, and every credential would then
    // match every other.
    if bundle
        .dec_pub_fps
        .iter()
        .chain(bundle.dec_votes_fps.iter())
        .any(|dec| <G as dlog_group::group::GroupPoint>::is_id(&dec.plaintext))
    {
        report.fail(
            "illicit_filter",
            "a credential fingerprint decrypts to the identity: the credentials were blinded \
             with zero, which makes them all look alike"
                .to_string(),
        );
        return report;
    }
    let legitimate = match pipeline.filter_illicit(
        &valid,
        &cred_art,
        &fps2,
        &bundle.dec_pub_fps,
        &bundle.dec_votes_fps,
    ) {
        Ok(legitimate) => {
            report.pass(
                "illicit_filter",
                format!(
                    "{} legitimate votes (one per authorised credential)",
                    legitimate.len()
                ),
            );
            legitimate
        }
        Err(e) => {
            report.fail("illicit_filter", format!("{e:?}"));
            return report;
        }
    };

    // -- Step 10: homomorphic sum + tally decryption + counts --------------
    let Some(tally_proof) = decode_single::<TallyProofEntry>(entries, "tally_proof", &mut report)
    else {
        return report;
    };
    let recomputed_sum = pipeline.homomorphic_sum(legitimate);
    if recomputed_sum == tally_proof.enc_tally {
        report.pass("tally_sum", "homomorphic sum matches the published one");
    } else {
        report.fail("tally_sum", "recomputed homomorphic sum differs");
        return report;
    }
    match pipeline.verify_decrypted_tally(&tally_proof.enc_tally, &tally_proof.decrypted) {
        Ok(()) => {}
        Err(e) => {
            report.fail("tally_decryption", format!("{e:?}"));
            return report;
        }
    }
    // The same binding for the tally itself: the `DecryptedTally` internals are private to
    // the library, so extract its `ThresholdDecOk` lists via the same serde
    // round-trip used for counts and bind them to the master key too.
    match tally_dec_oks(&tally_proof.decrypted) {
        Ok(decs) => {
            if let Err(e) = check_decs(&decs) {
                report.fail("tally_decryption", format!("tally {e}"));
                return report;
            }
            report.pass(
                "tally_decryption",
                format!(
                    "threshold decryption proofs verified and master-key-bound ({})",
                    decs.len()
                ),
            );
        }
        Err(e) => {
            report.fail("tally_decryption", e);
            return report;
        }
    }
    let Some(published_counts) = decode_single::<TallyCounts>(entries, "tally_result", &mut report)
    else {
        return report;
    };
    match extract_counts(&tally_proof.decrypted) {
        Ok(counts) if counts == published_counts => report.pass(
            "tally_result",
            format!("Blank={} Approve={} Reject={}", counts.blank, counts.si, counts.no),
        ),
        Ok(counts) => report.fail(
            "tally_result",
            format!("recomputed {counts:?} != published {published_counts:?}"),
        ),
        Err(e) => report.fail("tally_result", e.to_string()),
    }

    report
}

/// Extract every `ThresholdDecOk` inside a `DecryptedTally` (l1_d + flattened
/// l2_d) via a serde round-trip - the fields are private to the library.
fn tally_dec_oks(
    decrypted: &evoting::api::prelude::DecryptedTally<G>,
) -> Result<Vec<ThresholdDecOk<G>>, String> {
    let value =
        serde_json::to_value(decrypted).map_err(|e| format!("tally serialization failed: {e}"))?;
    let l1: Vec<ThresholdDecOk<G>> = serde_json::from_value(
        value
            .get("l1_d")
            .cloned()
            .ok_or_else(|| "decrypted tally has no l1_d".to_string())?,
    )
    .map_err(|e| format!("l1_d decode failed: {e}"))?;
    let l2: Vec<Vec<ThresholdDecOk<G>>> = serde_json::from_value(
        value
            .get("l2_d")
            .cloned()
            .ok_or_else(|| "decrypted tally has no l2_d".to_string())?,
    )
    .map_err(|e| format!("l2_d decode failed: {e}"))?;
    Ok(l1.into_iter().chain(l2.into_iter().flatten()).collect())
}

/// Decode the single expected entry of `entry_type`; FAIL the report when it
/// is absent, duplicated, or malformed.
fn decode_single<T: serde::de::DeserializeOwned>(
    entries: &[AuditedEntry],
    entry_type: &'static str,
    report: &mut AuditReport,
) -> Option<T> {
    let matches: Vec<&ParsedWbbData> = entries
        .iter()
        .filter_map(|e| e.parsed.as_ref())
        .filter(|p| p.entry_type == entry_type)
        .collect();
    match matches.as_slice() {
        [single] => match single.decode_payload::<T>() {
            Ok(value) => Some(value),
            Err(e) => {
                report.fail(entry_type, format!("payload invalid: {e}"));
                None
            }
        },
        [] => {
            report.fail(entry_type, "entry missing from the log");
            None
        }
        many => {
            report.fail(
                entry_type,
                format!("{} entries, expected exactly 1", many.len()),
            );
            None
        }
    }
}

#[cfg(test)]
mod collapse_tests {
    use super::collapse_repeats;

    #[test]
    fn notes_that_differ_only_by_position_collapse() {
        let notes: Vec<String> = (10..18)
            .map(|leaf| format!("leaf {leaf}: BB-2 released digest X a second time"))
            .chain(["entry 3: a ballot_metadata entry that cannot be read".to_string()])
            .chain(["the board has no checkpoint".to_string()])
            .chain(["the board has no checkpoint".to_string()])
            .collect();
        let line = collapse_repeats(&notes);
        assert_eq!(
            line,
            "8 x BB-2 released digest X a second time (at leaf 10, leaf 11, leaf 12, \
             leaf 13, leaf 14, and 3 more); a ballot_metadata entry that cannot be read \
             (at entry 3); 2 x the board has no checkpoint"
        );
    }

    #[test]
    fn a_colon_later_in_the_text_is_not_a_position() {
        let notes = vec!["leafy: not a position".to_string()];
        assert_eq!(collapse_repeats(&notes), "leafy: not a position");
    }
}
