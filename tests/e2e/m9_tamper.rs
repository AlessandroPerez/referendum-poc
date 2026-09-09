//! §13 `auditor_detects_tamper`: the auditor FAILs — identifying the step —
//! on tampered copies of the log. Three insider-grade tampers (re-signed
//! with the REAL ceremony keys, so only the cryptographic checks can catch
//! them) plus a plain signature flip:
//!
//!   t1  a censored `encrypted_ballot` release        → `release_completeness`
//!   t2  a forged decryption share (ox pipeline)      → `ox_dedup`
//!   t3  forged `tally_result` counts                 → `tally_result`
//!   t4  a flipped signature byte                     → `entry_signatures`

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use referendum_poc::actors::auditor::audit_raw_entries;
use referendum_poc::protocol::voting::parse_wbb_data;
use sha2::{Digest, Sha256};

use super::helpers::{ElectionCluster, ElectionOpts};

type RawEntries = Vec<(i64, serde_json::Value)>;

#[tokio::test]
async fn auditor_detects_tamper() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject", "blank"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;
    cluster.tally().await;

    let cfg = cluster.audit_config();
    let entries = cluster.wbb.client.entries().await.expect("wbb entries");
    let raw: RawEntries = entries
        .entries
        .iter()
        .map(|e| (e.leaf_index, e.entry.clone()))
        .collect();

    // Baseline: the untampered snapshot passes.
    let clean = audit_raw_entries(&cfg, raw.clone()).await;
    assert!(clean.ok(), "clean log must pass:\n{}", clean.render());

    // Signing keys an insider (colluding authorities) would hold.
    let keys: HashMap<String, SigningKey> = [
        ("ER-1", "er"),
        ("TT-1", "tt-1"),
        ("TT-2", "tt-2"),
        ("TT-3", "tt-3"),
        ("BB-1", "bb-1"),
        ("BB-2", "bb-2"),
    ]
    .into_iter()
    .map(|(id, name)| (id.to_string(), cluster.signing_key(name)))
    .collect();

    // ── t1: censor one encrypted_ballot release (coordinator/BB collusion) ─
    let mut censored = raw.clone();
    let victim = censored
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("encrypted_ballot"))
        .expect("an encrypted_ballot entry");
    censored.remove(victim);
    let report = audit_raw_entries(&cfg, censored).await;
    assert!(!report.ok(), "censored release must FAIL");
    assert_step_failed(&report, "release_completeness");

    // ── t2: forge a decryption share in the ox pipeline, re-signed by all
    //        three TTs — caught by the per-partial proof check against the
    //        embedded H_i and/or the master-key binding ────────────────────
    let mut forged = raw.clone();
    let ox_pos = forged
        .iter()
        .position(|(_, e)| {
            entry_type_of(e).as_deref() == Some("re_encryption_proof")
                && payload_of(e)
                    .map(|p| p["kind"] == "ox_fingerprints")
                    .unwrap_or(false)
        })
        .expect("the OxFingerprints re_encryption_proof entry");
    {
        let entry = &mut forged[ox_pos].1;
        let mut payload = payload_of(entry).expect("decodable ox payload");
        let swapped = swap_two_values_of_key(&mut payload, "public_key_share");
        assert!(swapped, "expected >=2 distinct public_key_share values");
        rewrite_and_resign(entry, &payload, &keys);
    }
    let report = audit_raw_entries(&cfg, forged).await;
    assert!(!report.ok(), "forged decryption share must FAIL");
    assert_step_failed(&report, "ox_dedup");

    // ── t2b: swap the `from_id` labels of two partials. The per-partial
    //        NIZKs ignore `from_id`, but the Lagrange aggregation inside
    //        `ThresholdDecOk::verify` (and the master-key binding behind it)
    //        depends on the labels, so the decryption check fails ──────────
    let mut mislabeled = raw.clone();
    {
        let entry = &mut mislabeled[ox_pos].1;
        let mut payload = payload_of(entry).expect("decodable ox payload");
        let swapped = swap_two_values_of_key(&mut payload, "from_id");
        assert!(swapped, "expected >=2 distinct from_id values");
        rewrite_and_resign(entry, &payload, &keys);
    }
    let report = audit_raw_entries(&cfg, mislabeled).await;
    assert!(!report.ok(), "mislabeled decryption shares must FAIL");
    assert_step_failed(&report, "ox_dedup");

    // ── t2c: the pure M8-M2 attack — replace the ox decryptions with a
    //        COMPLETE fake-DKG set. Three fabricated TT shares produce
    //        partials whose NIZKs are all honest w.r.t. their own embedded
    //        H_i and whose aggregation is self-consistent, so
    //        `ThresholdDecOk::verify` passes; ONLY the auditor's master-key
    //        binding (interpolating the H_i against the ceremony master
    //        key) can catch it ──────────────────────────────────────────────
    let mut fake_dkg = raw.clone();
    {
        use dlog_group::group::GroupScalar as _;
        use dlog_group::ristretto::RistrettoGroup as G;
        use evoting::api::prelude::{
            TTSecretKeyShare, ThresholdTabulationTeller, VerifiableFingerprints,
        };
        use rand::SeedableRng as _;
        use referendum_poc::protocol::tally::reconstruct_tt_teller;

        let ctx: evoting::api::server::bb::ElectionContext<G> = serde_json::from_slice(
            &std::fs::read(cluster.ceremony_dir().join("election_context.json")).unwrap(),
        )
        .unwrap();
        let mut payload = payload_of(&fake_dkg[ox_pos].1).expect("decodable ox payload");
        let fps: VerifiableFingerprints<G> =
            serde_json::from_value(payload["fps"].clone()).expect("decodable fps");

        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x5e; 32]);
        let mut partials = Vec::new();
        for id in 1..=3 {
            let teller = reconstruct_tt_teller(TTSecretKeyShare {
                id,
                meg_sk1_share: G::scalar_random(&mut rng),
                meg_sk2_share: G::scalar_random(&mut rng),
            });
            partials.push(
                teller
                    .partial_decrypt_ox_fps(&ctx, &fps, &mut rng)
                    .expect("fake partial decryption"),
            );
        }
        let fake_decs =
            ThresholdTabulationTeller::combine_ox_fps_decryptions(&ctx, &fps, &partials)
                .expect("fake decryptions combine and self-verify");

        payload["decryptions"] = serde_json::to_value(&fake_decs).unwrap();
        rewrite_and_resign(&mut fake_dkg[ox_pos].1, &payload, &keys);
    }
    let report = audit_raw_entries(&cfg, fake_dkg).await;
    assert!(!report.ok(), "fake-DKG decryptions must FAIL");
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "ox_dedup" && !s.ok)
        .unwrap_or_else(|| panic!("expected ox_dedup to FAIL, got:\n{}", report.render()));
    assert!(
        step.detail.contains("interpolated"),
        "the master-key binding (not the self-verification) must catch the \
         fake DKG, got: {}",
        step.detail
    );

    // ── t3: forge the announced counts, re-signed by all three TTs ────────
    let mut cooked = raw.clone();
    let result_pos = cooked
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("tally_result"))
        .expect("the tally_result entry");
    {
        let entry = &mut cooked[result_pos].1;
        let mut payload = payload_of(entry).expect("decodable tally_result");
        let si = payload["si"].as_u64().unwrap();
        payload["si"] = serde_json::json!(si + 1);
        rewrite_and_resign(entry, &payload, &keys);
    }
    let report = audit_raw_entries(&cfg, cooked).await;
    assert!(!report.ok(), "forged counts must FAIL");
    assert_step_failed(&report, "tally_result");

    // ── t4: flip a signature byte (no insider keys involved) ──────────────
    let mut flipped = raw.clone();
    let sig_pos = flipped
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("eligible_vids"))
        .expect("the eligible_vids entry");
    {
        let entry = &mut flipped[sig_pos].1;
        let sig_b64 = entry["signature"].as_str().expect("single-signer entry");
        let mut sig = BASE64.decode(sig_b64).unwrap();
        sig[0] ^= 0x01;
        entry["signature"] = serde_json::json!(BASE64.encode(sig));
    }
    let report = audit_raw_entries(&cfg, flipped).await;
    assert!(!report.ok(), "flipped signature must FAIL");
    assert_step_failed(&report, "entry_signatures");
}

fn assert_step_failed(report: &referendum_poc::actors::auditor::AuditReport, step: &str) {
    assert!(
        report.steps.iter().any(|s| !s.ok && s.name == step),
        "expected step `{step}` to FAIL, got:\n{}",
        report.render()
    );
}

/// The §4.4 entry type of a raw log entry, if its data decodes.
fn entry_type_of(entry: &serde_json::Value) -> Option<String> {
    let data = BASE64.decode(entry.get("data")?.as_str()?).ok()?;
    Some(parse_wbb_data(&data)?.entry_type)
}

/// Decode the JSON payload inside a raw entry's data string.
fn payload_of(entry: &serde_json::Value) -> Option<serde_json::Value> {
    let data = BASE64.decode(entry.get("data")?.as_str()?).ok()?;
    let parsed = parse_wbb_data(&data)?;
    let json = BASE64.decode(parsed.content).ok()?;
    serde_json::from_slice(&json).ok()
}

/// Swap the first two DISTINCT values found under `key` anywhere in the
/// document — structure-agnostic share forgery.
fn swap_two_values_of_key(value: &mut serde_json::Value, key: &str) -> bool {
    fn collect(v: &serde_json::Value, key: &str, path: &str, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    let p = format!("{path}/{k}");
                    if k == key {
                        out.push(p.clone());
                    }
                    collect(child, key, &p, out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    collect(child, key, &format!("{path}/{i}"), out);
                }
            }
            _ => {}
        }
    }
    let mut paths = Vec::new();
    collect(value, key, "", &mut paths);
    let first = match paths.first() {
        Some(p) => p.clone(),
        None => return false,
    };
    let a = value.pointer(&first).cloned().unwrap();
    for other in &paths[1..] {
        let b = value.pointer(other).cloned().unwrap();
        if a != b {
            *value.pointer_mut(&first).unwrap() = b;
            *value.pointer_mut(other).unwrap() = a;
            return true;
        }
    }
    false
}

/// Rebuild the entry's data string around `payload` and re-sign it with the
/// REAL entity keys at the entry's original timestamps (insider tamper).
fn rewrite_and_resign(
    entry: &mut serde_json::Value,
    payload: &serde_json::Value,
    keys: &HashMap<String, SigningKey>,
) {
    let old = BASE64
        .decode(entry["data"].as_str().unwrap())
        .expect("data b64");
    let parsed = parse_wbb_data(&old).expect("parsable data");
    let json = serde_json::to_string(payload).unwrap();
    let new_data = format!(
        "{},{},{},{},{}",
        parsed.phase,
        parsed.role,
        parsed.entry_type,
        parsed.threshold,
        BASE64.encode(json.as_bytes())
    );
    let data = new_data.as_bytes();
    entry["data"] = serde_json::json!(BASE64.encode(data));

    let sign = |id: &str, ts: i64| -> String {
        let key = keys.get(id).expect("insider key for signer");
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(id.as_bytes());
        hasher.update(format!("{ts}").as_bytes());
        BASE64.encode(key.sign(&hasher.finalize()).to_bytes())
    };

    if let Some(id) = entry.get("entity_id").and_then(|v| v.as_str()) {
        let id = id.to_string();
        let ts = entry["timestamp"].as_i64().unwrap_or(0);
        entry["signature"] = serde_json::json!(sign(&id, ts));
        return;
    }

    let entry_ts = entry["timestamp"].as_i64().unwrap_or(0);
    let ids: Vec<String> = serde_json::from_value(entry["entity_ids"].clone()).unwrap();
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
    let signatures: Vec<String> = ids
        .iter()
        .map(|id| sign(id, per_signer_ts.get(id).copied().unwrap_or(entry_ts)))
        .collect();
    entry["signatures"] = serde_json::json!(signatures);
}
