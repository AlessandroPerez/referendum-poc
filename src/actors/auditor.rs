//! Universal-verification auditor (M8, §3.10 / roadmap §8.6).
//!
//! Fetches everything from the WBB read API and re-runs the public pipeline:
//! entry signatures, phase transitions, ballot-release reconciliation (the
//! §3.8.5 ⊥ filter), ox re-vote dedup, ballot/mix/ACC-check/credential
//! verification, filter recomputation, the homomorphic sum, and the tally
//! decryption proofs. Every step yields OK/FAIL; the CLI exits nonzero on any
//! FAIL. Only the entity verifying keys and the cluster CA come from local
//! configuration — all election data is read from the log itself.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::{GroupPoint, GroupScalar};
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evoting::api::prelude::{ShortPublicACC, ThresholdDecOk};
use evoting::api::server::bb::{BallotRecord, ElectionContext, PublicElection, PublicPipeline};
use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::clients::wbb::WbbClient;
use crate::domain::Vid;
use crate::protocol::tally::{
    extract_counts, reconcile_ballots, EncryptedBallotEntry, MixedBallotsEntry,
    ReEncryptionProofEntry, TallyCounts, TallyProofEntry,
};
use crate::protocol::tls::reqwest_client_trusting_ca;
use crate::protocol::voting::{
    ballot_digest, parse_wbb_data, BallotDigestEntry, ParsedWbbData, NO_BOT_MIN_BBS,
};

type G = RistrettoGroup;

/// Configuration for a §3.10 audit run.
#[derive(Clone)]
pub struct AuditConfig {
    /// WBB log base URL.
    pub wbb_url: Url,
    /// Cluster CA PEM for TLS.
    pub ca_pem: String,
    /// Entity Ed25519 verifying keys, id → key (PM/ER/RT/TT/BB).
    pub entity_keys: Vec<(String, VerifyingKey)>,
    /// Number of TT parties and reconstruction threshold — bounds for the
    /// master-key binding check on every published threshold decryption
    /// (M8 round-1 finding M2).
    pub n_tt: usize,
    pub t_tt: usize,
}

/// Required staging role and threshold per entry type — the fixed §4.4/write-
/// policy table. The auditor must not trust the attacker-authored threshold
/// field inside the entry data (M8 round-1 finding L2).
fn required_signing(entry_type: &str) -> Option<(&'static str, usize)> {
    Some(match entry_type {
        "election_pub_key"
        | "pseudonymous_id_count"
        | "voter_id_merkle_root"
        | "revocation_commitment"
        | "eligible_vids" => ("ER", 1),
        "acc_pub_key" => ("RT", 2),
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
}

/// Full per-step audit report (§8.6).
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    pub steps: Vec<AuditStep>,
}

impl AuditReport {
    /// True when every step passed.
    pub fn ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok)
    }

    fn pass(&mut self, name: &'static str, detail: impl Into<String>) {
        self.steps.push(AuditStep {
            name,
            ok: true,
            detail: detail.into(),
        });
    }

    fn fail(&mut self, name: &'static str, detail: impl Into<String>) {
        self.steps.push(AuditStep {
            name,
            ok: false,
            detail: detail.into(),
        });
    }

    /// Render the report as the CLI's per-step OK/FAIL lines.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            let status = if step.ok { "OK  " } else { "FAIL" };
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
    parsed: Option<ParsedWbbData>,
    /// `(entity_id, timestamp_ms, signature)` per signer.
    signers: Vec<(String, i64, Vec<u8>)>,
}

/// Run the full §3.10 audit against a WBB log.
pub async fn run_audit(cfg: AuditConfig) -> Result<AuditReport, AuditError> {
    let http = reqwest_client_trusting_ca(&cfg.ca_pem)?;
    let wbb = WbbClient::new(http, cfg.wbb_url.clone());
    let entries = wbb.entries().await?;
    let raw = entries
        .entries
        .iter()
        .map(|s| (s.leaf_index, s.entry.clone()))
        .collect();
    Ok(audit_raw_entries(&cfg, raw).await)
}

/// Audit a snapshot of raw log entries `(leaf_index, entry_json)`.
///
/// This is the same verification path `run_audit` uses after fetching; it is
/// public so the §13 `auditor_detects_tamper` test can replay TAMPERED copies
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
            data,
            parsed,
            signers,
        });
    }

    let keys: HashMap<String, VerifyingKey> = cfg.entity_keys.iter().cloned().collect();
    let (n_tt, t_tt) = (cfg.n_tt, cfg.t_tt);
    tokio::task::spawn_blocking(move || audit_entries(&audited, &keys, n_tt, t_tt))
        .await
        .unwrap_or_else(|e| {
            let mut report = AuditReport::default();
            report.fail("audit_execution", format!("audit task panicked: {e}"));
            report
        })
}

/// Extract `(entity_id, timestamp, signature)` triples from a raw log entry.
///
/// Single-signer entries carry `entity_id`/`signature`; co-signed entries
/// carry `entity_ids`/`signatures` with per-signer times in
/// `signer_timestamps` (the entry-level timestamp is last-submission-at).
fn signers_of(entry: &serde_json::Value) -> Vec<(String, i64, Vec<u8>)> {
    let entry_ts = entry.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
    let decode = |v: &serde_json::Value| -> Option<Vec<u8>> {
        v.as_str().and_then(|s| BASE64.decode(s).ok())
    };

    if let Some(entity_id) = entry.get("entity_id").and_then(|v| v.as_str()) {
        if let Some(signature) = entry.get("signature").and_then(decode) {
            return vec![(entity_id.to_string(), entry_ts, signature)];
        }
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
    let ids: Vec<String> = entry
        .get("entity_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
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
) -> AuditReport {
    let mut report = AuditReport::default();

    // ── Step 1: every entry signature verifies against a known entity key,
    //    with the role/threshold requirements of the FIXED §4.4 table (L2) ──
    let mut bad_signatures = Vec::new();
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
                    // N1: only signers of the REQUIRED role count towards the
                    // threshold — the auditor must not delegate that check to
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
            hasher.update(&entry.data);
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
        report.fail("entry_signatures", bad_signatures.join("; "));
    }

    // ── Step 2: phase transitions form setup → voting → tallying ──────────
    let transitions: Vec<(&str, &str)> = entries
        .iter()
        .filter_map(|e| e.parsed.as_ref())
        .filter(|p| p.entry_type == "phase_transition")
        .map(|p| (p.phase.as_str(), p.content.as_str()))
        .collect();
    if transitions == vec![("setup", "voting"), ("voting", "tallying")] {
        report.pass("phase_transitions", "setup → voting → tallying");
    } else {
        report.fail(
            "phase_transitions",
            format!("unexpected transition chain: {transitions:?}"),
        );
    }

    // ── Step 3: parse the election context and public parameters ──────────
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

    let Some(eligible) = decode_single::<Vec<Vid>>(entries, "eligible_vids", &mut report) else {
        return report;
    };

    // ── Step 4: ballot release — signer/bb linkage + digest linkage ───────
    // Acceptance evidence from the voting phase: which distinct BBs signed a
    // `ballot_digest` entry for each digest (basis of the M1 censorship
    // check).  A payload whose `receipt.bb_id` is not backed by that BB's own
    // signature on the entry does not count as acceptance evidence.
    let mut accepted_by: HashMap<crate::domain::BallotDigest, HashSet<u64>> = HashMap::new();
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        if parsed.entry_type != "ballot_digest" {
            continue;
        }
        let Ok(payload) = parsed.decode_payload::<BallotDigestEntry>() else {
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
        }
    }
    let voting_digests: HashSet<crate::domain::BallotDigest> =
        accepted_by.keys().copied().collect();

    let mut per_bb: BTreeMap<u64, Vec<BallotRecord<G>>> = BTreeMap::new();
    let mut released_by: HashMap<crate::domain::BallotDigest, HashSet<u64>> = HashMap::new();
    let mut release_problems = Vec::new();
    for entry in entries {
        let Some(parsed) = &entry.parsed else {
            continue;
        };
        if parsed.entry_type != "encrypted_ballot" {
            continue;
        }
        let record = match parsed.decode_payload::<EncryptedBallotEntry>() {
            Ok(e) => e.record,
            Err(e) => {
                release_problems.push(format!("leaf {}: bad payload ({e})", entry.leaf_index));
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
            release_problems.push(format!(
                "leaf {}: released by {:?}, receipt claims {expected_signer}",
                entry.leaf_index,
                entry
                    .signers
                    .iter()
                    .map(|(id, _, _)| id)
                    .collect::<Vec<_>>()
            ));
        }
        match ballot_digest(&record.ballot) {
            Ok(digest) if voting_digests.contains(&digest) => {
                released_by.entry(digest).or_default().insert(bb_id);
            }
            Ok(digest) => release_problems.push(format!(
                "leaf {}: digest {digest} missing from voting-phase log",
                entry.leaf_index
            )),
            Err(e) => {
                release_problems.push(format!("leaf {}: digest error ({e})", entry.leaf_index))
            }
        }
        per_bb.entry(bb_id).or_default().push(record);
    }
    let released: usize = per_bb.values().map(Vec::len).sum();
    if release_problems.is_empty() && released > 0 {
        report.pass(
            "ballot_release",
            format!("{released} released records across {} BBs", per_bb.len()),
        );
    } else {
        report.fail(
            "ballot_release",
            if released == 0 {
                "no encrypted_ballot entries".to_string()
            } else {
                release_problems.join("; ")
            },
        );
        return report;
    }

    let per_bb_lists: Vec<Vec<BallotRecord<G>>> = per_bb.into_values().collect();
    let records = match reconcile_ballots(&per_bb_lists) {
        Ok(records) => {
            report.pass(
                "ballot_reconciliation",
                format!("{} ballots after the ⊥ filter", records.len()),
            );
            records
        }
        Err(e) => {
            report.fail("ballot_reconciliation", e.to_string());
            return report;
        }
    };

    // ── M1: release completeness — every ballot accepted during voting by
    //    ≥ NO_BOT_MIN_BBS distinct BBs must survive release + reconciliation;
    //    a coordinator or colluding BB omitting one must not pass the audit ──
    let reconciled_digests: HashSet<crate::domain::BallotDigest> = records
        .iter()
        .filter_map(|r| ballot_digest(&r.ballot).ok())
        .collect();
    let mut completeness_problems = Vec::new();
    let mut accepted_count = 0usize;
    for (digest, acceptors) in &accepted_by {
        if acceptors.len() < NO_BOT_MIN_BBS {
            continue; // ⊥ during voting; exclusion is the protocol outcome.
        }
        accepted_count += 1;
        if !reconciled_digests.contains(digest) {
            completeness_problems.push(format!(
                "digest {digest} accepted by {} BBs during voting but censored \
                 from the tally release",
                acceptors.len()
            ));
        } else if released_by
            .get(digest)
            .map_or(true, |r| r.len() < acceptors.len())
        {
            completeness_problems.push(format!(
                "digest {digest} released by fewer BBs than accepted it \
                 ({:?} vs {:?})",
                released_by.get(digest),
                acceptors
            ));
        }
    }
    if completeness_problems.is_empty() {
        report.pass(
            "release_completeness",
            format!("all {accepted_count} accepted ballots present in the release"),
        );
    } else {
        report.fail("release_completeness", completeness_problems.join("; "));
        return report;
    }

    // ── Step 5: strict artifact inventory (L2), then ox dedup ─────────────
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
            "re_encryption_proof" => match parsed.decode_payload::<ReEncryptionProofEntry>() {
                Ok(proof) => proofs.push(proof),
                Err(e) => inventory_problems.push(format!(
                    "leaf {}: undecodable proof ({e})",
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
        report.fail("artifact_inventory", inventory_problems.join("; "));
        return report;
    }
    let Some(ReEncryptionProofEntry::OxFingerprints {
        fps: ox_fps,
        decryptions: dec_ox,
    }) = ox
    else {
        unreachable!("inventory guarantees the ox slot holds the ox variant");
    };
    let params = &context.pk.params.elgamal;
    // M2: every published threshold decryption must verify AND its embedded
    // partial public-key shares must interpolate to the election master key —
    // otherwise colluding signers can fabricate self-consistent decryptions.
    let master_h = context.pk.params.tally.h;
    let check_decs = |decs: &[ThresholdDecOk<G>]| -> Result<(), String> {
        for (i, dec) in decs.iter().enumerate() {
            dec.verify(params)
                .map_err(|e| format!("decryption proof {i} invalid: {e:?}"))?;
            verify_master_key_binding(dec, &master_h, n_tt, t_tt)
                .map_err(|e| format!("decryption {i} not bound to the master key: {e}"))?;
        }
        Ok(())
    };

    if let Err(e) = check_decs(&dec_ox) {
        report.fail("ox_dedup", format!("ox {e}"));
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

    // ── Step 6: ballot proofs + vote mix ──────────────────────────────────
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

    // ── Step 7: controls + ACC checks + invalid-vote filter ───────────────
    let Some(ReEncryptionProofEntry::Controls { controls }) = controls_entry else {
        unreachable!("inventory guarantees the controls slot holds the controls variant");
    };
    let Some(ReEncryptionProofEntry::AccChecks { acc_checks, zeta }) = acc else {
        unreachable!("inventory guarantees the acc slot holds the acc_checks variant");
    };
    if let Err(e) = check_decs(&acc_checks) {
        report.fail("acc_checks", format!("ACC-check {e}"));
        return report;
    }
    if let Err(e) = pipeline.verify_acc_checks(&acc_checks, &controls, &vote_art.shuffled, zeta) {
        report.fail("acc_checks", format!("{e:?}"));
        return report;
    }
    let valid = match pipeline.filter_invalid(&vote_art.shuffled, &controls, &acc_checks, zeta) {
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

    // ── Step 8: credential mix over the eligible list ─────────────────────
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

    // ── Step 9: credential fingerprints + illicit/keep-last filter ────────
    let Some(ReEncryptionProofEntry::CredentialFingerprints { fps: fps2, bundle }) = cred_fps
    else {
        unreachable!("inventory guarantees the fps slot holds the fingerprints variant");
    };
    if let Err(e) = check_decs(&bundle.dec_pub_fps).and_then(|()| check_decs(&bundle.dec_votes_fps))
    {
        report.fail("illicit_filter", format!("fingerprint {e}"));
        return report;
    }
    let legitimate = match pipeline.filter_illicit_keep_last(
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
                    "{} legitimate votes (keep-last per credential)",
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

    // ── Step 10: homomorphic sum + tally decryption + counts ──────────────
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
    // M2 for the tally itself: the `DecryptedTally` internals are private to
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
            format!("blank={} si={} no={}", counts.blank, counts.si, counts.no),
        ),
        Ok(counts) => report.fail(
            "tally_result",
            format!("recomputed {counts:?} ≠ published {published_counts:?}"),
        ),
        Err(e) => report.fail("tally_result", e.to_string()),
    }

    report
}

/// Lagrange basis coefficient λ_i(0) over `participants` in the scalar field.
fn lagrange_basis_at_zero(i: usize, participants: &[usize]) -> <G as GroupScalar>::Scalar {
    let mut num = <G as GroupScalar>::Scalar::from(1u64);
    let mut den = <G as GroupScalar>::Scalar::from(1u64);
    let i_scalar = <G as GroupScalar>::Scalar::from(i as u64);
    for &j in participants {
        if j != i {
            let j_scalar = <G as GroupScalar>::Scalar::from(j as u64);
            num *= j_scalar;
            den *= j_scalar - i_scalar;
        }
    }
    num * G::scalar_inv(den)
}

/// M2 fix: bind a published threshold decryption to the election master key.
///
/// `ThresholdDecOk::verify` only proves each partial is consistent with the
/// `public_key_share` H_i *embedded in the partial itself*. Here the auditor
/// additionally requires ≥ `t_tt` partials from distinct in-range signer ids
/// whose H_i interpolate at 0 to the master M-ElGamal public key from the
/// published election context — making fabricated self-consistent share sets
/// detectable.
fn verify_master_key_binding(
    dec: &ThresholdDecOk<G>,
    master_h: &<G as GroupPoint>::Point,
    n_tt: usize,
    t_tt: usize,
) -> Result<(), String> {
    let ids: Vec<usize> = dec.partial_decryptions.iter().map(|p| p.from_id).collect();
    let distinct: HashSet<usize> = ids.iter().copied().collect();
    if distinct.len() != ids.len() {
        return Err("duplicate signer ids".into());
    }
    if ids.len() < t_tt {
        return Err(format!("only {} partials, threshold is {t_tt}", ids.len()));
    }
    if ids.iter().any(|&id| id == 0 || id > n_tt) {
        return Err(format!("signer id out of range 1..={n_tt}"));
    }
    let mut sum = G::identity();
    for partial in &dec.partial_decryptions {
        let lambda = lagrange_basis_at_zero(partial.from_id, &ids);
        sum += partial.public_key_share * lambda;
    }
    if sum != *master_h {
        return Err("interpolated key shares do not equal the election master key".into());
    }
    Ok(())
}

/// Extract every `ThresholdDecOk` inside a `DecryptedTally` (l1_d + flattened
/// l2_d) via a serde round-trip — the fields are private to the library.
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
