//! `auditor_detects_tamper`: the auditor's verdicts on tampered copies of the
//! log. A tamper that would CHANGE THE RESULT fails the named step. A lie by
//! ONE ballot box that the protocol survives (thesis A9; Sec. 3.8.4 step 15
//! publishes divergent data rather than failing on it) PASSES the audit with
//! a WARNING at the named step that names the box - the result stands, the
//! evidence is on the board. Insider-grade tampers are re-signed with the
//! REAL ceremony keys, so only the cryptographic checks can catch them:
//!
//!   t1  one box withholds a release -> WARN; every box withholds it -> `release_completeness`
//!   t2  a forged decryption share (ox pipeline)      -> `ox_dedup`
//!   t3  forged `tally_result` counts                 -> `tally_result`
//!   t5  a released ballot with one confirmation gone -> WARN + FAIL (mismatch)
//!   t6  a ballot box publishing a forged opened control value -> WARN `cai_confirmation`
//!   t7  the RTs' control elements re-labelled as a TT-signed proof -> `artifact_inventory`
//!   t8  the control elements published twice -> `artifact_inventory`
//!   t9  another proof smuggled under `credential_control` -> `artifact_inventory`
//!   t10 a ballot box publishing a forged ballot emoji or public PIN emoji -> `published_emoji`
//!   t10b the forgery covered by a later, correct entry -> `published_emoji`
//!   t10c the forgery hidden in an unreadable entry     -> `published_entries`
//!   t10d a ballot box speaking for another one          -> `published_entries`
//!   t10e an unreadable confirmation next to the genuine one -> `published_entries`
//!   t10f a forged opened value covered by a later, genuine confirmation -> `cai_confirmation`
//!   t10g both signer forms on one entry (shadowed signer) -> `entry_signatures`
//!   t10h a forged opening for a digest the forging box never releases -> `cai_confirmation`
//!   t11 a ballot box releasing ballots under swapped receipts -> `ballot_release`
//!   t12 ballot_metadata that is unreadable, another box's, or about a ballot
//!       that box never accepted                         -> `published_entries`
//!   t13 a release with no published receipt, and two receipts for one ballot
//!                                                       -> `ballot_release`
//!   t14 a voter left off (or repeated in) the eligible list -> `eligible_identifiers`
//!   t15 the credential check blinded with zero          -> `acc_checks`
//!   t4  a flipped signature byte                     -> `entry_signatures`

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
        ("RT-1", "rt-1"),
        ("RT-2", "rt-2"),
        ("RT-3", "rt-3"),
    ]
    .into_iter()
    .map(|(id, name)| (id.to_string(), cluster.signing_key(name)))
    .collect();

    // -- t1: censor one encrypted_ballot release (coordinator/BB collusion) -
    let mut censored = raw.clone();
    let victim = censored
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("encrypted_ballot"))
        .expect("an encrypted_ballot entry");
    let withheld_digest = payload_of(&censored[victim].1).unwrap()["record"].clone();
    censored.remove(victim);
    let report = audit_raw_entries(&cfg, censored).await;
    // One box withholding a ballot the other released: the ballot is counted
    // from the honest copy (Sec. 3.9 step 3), the box is named.
    assert_step_warned(&report, "release_completeness", "did NOT release");

    // -- t1b: EVERY box withholds the same ballot: no honest box is left.
    //         Both boxes are named (Sec. 3.9 step 4), and the audit fails
    //         because the published pipeline still covers the ballot ------
    let mut censored_all = raw.clone();
    let victim_ballot = withheld_digest["ballot"].clone();
    censored_all.retain(|(_, e)| {
        entry_type_of(e).as_deref() != Some("encrypted_ballot")
            || payload_of(e).is_none_or(|p| p["record"]["ballot"] != victim_ballot)
    });
    let report = audit_raw_entries(&cfg, censored_all).await;
    assert_warned_and_failed(&report, "release_completeness", "released by NO box");
    let named = report
        .warnings()
        .find(|s| s.name == "release_completeness")
        .expect("warned");
    assert!(
        named.detail.contains("BB-1") && named.detail.contains("BB-2"),
        "{}",
        named.detail
    );

    // -- t2: forge a decryption share in the ox pipeline, re-signed by all
    //        three TTs - caught by the per-partial proof check against the
    //        embedded H_i and/or the master-key binding --------------------
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

    // -- t2b: swap the `from_id` labels of two partials. The per-partial
    //        NIZKs ignore `from_id`, but the Lagrange aggregation inside
    //        `ThresholdDecOk::verify` (and the master-key binding behind it)
    //        depends on the labels, so the decryption check fails ----------
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

    // -- t2c: the pure share-forgery attack - replace the ox decryptions with a
    //        COMPLETE fake-DKG set. Three fabricated TT shares produce
    //        partials whose NIZKs are all honest w.r.t. their own embedded
    //        H_i and whose aggregation is self-consistent, so
    //        `ThresholdDecOk::verify` passes; ONLY the auditor's master-key
    //        binding (interpolating the H_i against the ceremony master
    //        key) can catch it ----------------------------------------------
    let mut fake_dkg = raw.clone();
    {
        use dlog_group::group::GroupScalar as _;
        use dlog_group::ristretto::RistrettoGroup as G;
        use evoting::api::prelude::{TTSecretKeyShare, ThresholdDecOk, ThresholdFingerprints};
        use rand::SeedableRng as _;
        use referendum_poc::protocol::tally::reconstruct_tt_teller;

        let ctx: evoting::api::server::bb::ElectionContext<G> = serde_json::from_slice(
            &std::fs::read(cluster.ceremony_dir().join("election_context.json")).unwrap(),
        )
        .unwrap();
        let mut payload = payload_of(&fake_dkg[ox_pos].1).expect("decodable ox payload");
        let fps: ThresholdFingerprints<G> =
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
        // The library no longer combines partials under self-declared keys,
        // so the tamper assembles the decryptions by hand, as a colluding set
        // of fake tellers would: each partial's own proof verifies against
        // the key it embeds.
        let fake_decs: Vec<ThresholdDecOk<G>> = fps.fp_lists[0]
            .iter()
            .enumerate()
            .map(|(i, ct)| ThresholdDecOk {
                ciphertext: *ct,
                plaintext: <G as dlog_group::group::GroupPoint>::identity(),
                partial_decryptions: partials.iter().map(|p| p[i].clone()).collect(),
            })
            .collect();

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
        step.detail.contains("not under its published share") && step.detail.contains("TT-1"),
        "the binding to the published teller shares (not the self-verification) must \
         catch the fake DKG and name a teller, got: {}",
        step.detail
    );

    // -- t3: forge the announced counts, re-signed by all three TTs --------
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

    // -- t5: drop one cast_intended_proof - a BB releasing a ballot without
    //        its published confirmation violates Sec. 3.9 step 2 / Sec. 3.10 1(d) --
    let mut unconfirmed = raw.clone();
    let cai_pos = unconfirmed
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("cast_intended_proof"))
        .expect("a cast_intended_proof entry");
    let dropped_digest = payload_of(&unconfirmed[cai_pos].1).unwrap()["digest"].clone();
    unconfirmed.remove(cai_pos);
    let report = audit_raw_entries(&cfg, unconfirmed.clone()).await;
    // With ONE confirmation gone the other box still vouches for the ballot
    // (Sec. 3.10 1(d): one valid disclosure). The ballot is counted and the
    // box that released it without a disclosure of its OWN did what A9 asks
    // of it - so the audit passes with no accusation, and says plainly how
    // many releases rest on another box's word.
    assert!(report.ok(), "audit:\n{}", report.render());
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "cai_confirmation")
        .expect("cai_confirmation");
    assert!(
        !step.warning,
        "a lawful release must not be warned about: {}",
        step.detail
    );
    assert!(
        step.detail.contains("and 1 another box's"),
        "the release on another box's disclosure must be counted: {}",
        step.detail
    );
    // -- t5b: EVERY confirmation of that ballot gone: nothing on the board
    //         opens on it any more, so the box that released it is named -
    //         and the published tally artifacts still cover the ballot, so
    //         the audit FAILS on the mismatch --
    unconfirmed.retain(|(_, e)| {
        entry_type_of(e).as_deref() != Some("cast_intended_proof")
            || payload_of(e).is_none_or(|p| p["digest"] != dropped_digest)
    });
    let report = audit_raw_entries(&cfg, unconfirmed).await;
    assert_warned_and_failed(
        &report,
        "cai_confirmation",
        "which no published cast-as-intended disclosure opens on",
    );

    // -- t6: a ballot box lies about the opened control value (re-signed with
    //        its real key): the voter would see the number they expect while
    //        the ballot seals another one --
    let mut lying = raw.clone();
    let lie_pos = lying
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("cast_intended_proof"))
        .expect("a cast_intended_proof entry");
    {
        let entry = &mut lying[lie_pos].1;
        let mut payload = payload_of(entry).expect("decodable cast_intended_proof");
        let l1 = payload["opened"]["l1"]
            .as_object()
            .expect("opened l1")
            .clone();
        let (slot, value) = l1.iter().next().expect("one opened slot");
        let forged = (value.as_u64().unwrap() + 1) % 100;
        payload["opened"]["l1"] = serde_json::json!({ slot.as_str(): forged });
        rewrite_and_resign(entry, &payload, &keys);
    }
    let report = audit_raw_entries(&cfg, lying).await;
    // The other box vouches for the ballot correctly: it is counted, and the
    // lying box is named with what it lied about.
    assert_step_warned(&report, "cai_confirmation", "published opened values");

    // -- t7: the control elements re-labelled as a tabulation-teller entry
    //        (re-signed by all three TTs): authorship is the RTs' (Sec. 3.4.2) --
    let mut relabelled = raw.clone();
    let control_pos = relabelled
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("credential_control"))
        .expect("the credential_control entry");
    {
        let entry = &mut relabelled[control_pos].1;
        let payload = payload_of(entry).expect("decodable credential_control");
        let json = serde_json::to_string(&payload).unwrap();
        let data = format!(
            "tallying,TT,re_encryption_proof,3,{}",
            BASE64.encode(json.as_bytes())
        );
        entry["data"] = serde_json::json!(BASE64.encode(data.as_bytes()));
        let ids = ["TT-1", "TT-2", "TT-3"];
        entry["entity_ids"] = serde_json::json!(ids);
        let ts = entry["timestamp"].as_i64().unwrap_or(0);
        let signatures: Vec<String> = ids
            .iter()
            .map(|id| {
                let mut hasher = Sha256::new();
                hasher.update(data.as_bytes());
                hasher.update(id.as_bytes());
                hasher.update(format!("{ts}").as_bytes());
                BASE64.encode(keys[*id].sign(&hasher.finalize()).to_bytes())
            })
            .collect();
        entry["signatures"] = serde_json::json!(signatures);
        entry["signer_timestamps"] = serde_json::json!(ids
            .iter()
            .map(|id| serde_json::json!({ "entity_id": id, "timestamp": ts }))
            .collect::<Vec<_>>());
    }
    let report = audit_raw_entries(&cfg, relabelled).await;
    assert!(!report.ok(), "TT-authored control elements must FAIL");
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "artifact_inventory" && !s.ok)
        .unwrap_or_else(|| {
            panic!(
                "expected artifact_inventory to FAIL, got:\n{}",
                report.render()
            )
        });
    assert!(
        step.detail.contains("published by the TTs"),
        "authorship, not a signature, must be what fails: {}",
        step.detail
    );

    // -- t8: the control elements published twice by the RTs ---------------
    let mut doubled = raw.clone();
    let control_pos = doubled
        .iter()
        .position(|(_, e)| entry_type_of(e).as_deref() == Some("credential_control"))
        .expect("the credential_control entry");
    let copy = doubled[control_pos].clone();
    doubled.insert(control_pos + 1, copy);
    let report = audit_raw_entries(&cfg, doubled).await;
    assert!(!report.ok(), "duplicate control elements must FAIL");
    assert_step_failed(&report, "artifact_inventory");

    // -- t9: a credential_control entry carrying ANOTHER proof (the ACC
    //        checks), re-signed by the RTs' real keys ----------------------
    {
        let mut smuggled = raw.clone();
        let acc_payload = smuggled
            .iter()
            .filter(|(_, e)| entry_type_of(e).as_deref() == Some("re_encryption_proof"))
            .filter_map(|(_, e)| payload_of(e))
            .find(|p| p["kind"] == "acc_checks")
            .expect("the ACC checks proof");
        let control_pos = smuggled
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("credential_control"))
            .unwrap();
        rewrite_and_resign(&mut smuggled[control_pos].1, &acc_payload, &keys);
        let report = audit_raw_entries(&cfg, smuggled).await;
        assert!(
            !report.ok(),
            "a foreign proof under credential_control must FAIL"
        );
        let step = report
            .steps
            .iter()
            .find(|s| s.name == "artifact_inventory" && !s.ok)
            .unwrap_or_else(|| panic!("expected artifact_inventory to FAIL:\n{}", report.render()));
        assert!(
            step.detail.contains("carries another proof"),
            "the foreign payload itself must be reported, got: {}",
            step.detail
        );
    }

    // -- t10: a ballot box publishes, next to a genuine digest, an emoji
    //         string (or a public PIN emoji) its ballot does not hash to,
    //         signed with its real key -------------------------------------
    for field in ["emoji", "public_pin_emoji"] {
        let mut forged = raw.clone();
        let pos = forged
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("ballot_digest"))
            .expect("a ballot_digest entry");
        let mut payload = payload_of(&forged[pos].1).unwrap();
        let list = payload[field].as_array_mut().expect("emoji list");
        assert!(list.len() > 1, "{field} is published");
        list.swap(0, 1);
        if list[0] == list[1] {
            list[0] = serde_json::json!("?");
        }
        rewrite_and_resign(&mut forged[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, forged).await;
        assert_step_warned(&report, "published_emoji", "does not hash to");
    }

    // -- t10b: the forged emoji shown FIRST, a correct entry for the same
    //          digest published later to cover it: every entry is audited --
    {
        let mut covered = raw.clone();
        let pos = covered
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("ballot_digest"))
            .unwrap();
        let genuine_entry = covered[pos].clone();
        let mut payload = payload_of(&covered[pos].1).unwrap();
        payload["emoji"][0] = serde_json::json!("?");
        rewrite_and_resign(&mut covered[pos].1, &payload, &keys);
        covered.insert(pos + 1, genuine_entry);
        let report = audit_raw_entries(&cfg, covered).await;
        assert_step_warned(&report, "published_emoji", "does not hash to");
    }

    // -- t10c: a forged emoji next to a field of the wrong shape, so that
    //          the entry cannot be read at all -----------------------------
    {
        let mut unreadable = raw.clone();
        let pos = unreadable
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("ballot_digest"))
            .unwrap();
        let mut payload = payload_of(&unreadable[pos].1).unwrap();
        payload["emoji"][0] = serde_json::json!("?");
        payload["public_pin_emoji"] = serde_json::json!("x");
        rewrite_and_resign(&mut unreadable[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, unreadable).await;
        // The box is named; the other box's acceptance still counts the
        // ballot (one honest box suffices), so the audit passes.
        assert!(report.ok(), "audit:\n{}", report.render());
        assert_step_warned(&report, "published_entries", "cannot be read");
    }

    // -- t10d: a ballot box speaking for ANOTHER one: BB-x signs an entry
    //          (forged emoji) whose payload names the other ballot box, next
    //          to its genuine entry. Same for a confirmation. -------------
    for (entry_type, id_path) in [
        ("ballot_digest", "/receipt/bb_id"),
        ("cast_intended_proof", "/bb_id"),
    ] {
        let mut mislabelled = raw.clone();
        let pos = mislabelled
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some(entry_type))
            .unwrap();
        let genuine_entry = mislabelled[pos].clone();
        let mut payload = payload_of(&mislabelled[pos].1).unwrap();
        let id = payload.pointer(id_path).and_then(|v| v.as_u64()).unwrap();
        *payload.pointer_mut(id_path).unwrap() = serde_json::json!(if id == 1 { 2 } else { 1 });
        if entry_type == "ballot_digest" {
            payload["emoji"][0] = serde_json::json!("?");
        }
        rewrite_and_resign(&mut mislabelled[pos].1, &payload, &keys);
        mislabelled.insert(pos + 1, genuine_entry);
        let report = audit_raw_entries(&cfg, mislabelled).await;
        assert_step_warned(&report, "published_entries", "did not sign");
        // The line's job is attribution: it names the box that SIGNED, not
        // only the one the payload claims to speak for.
        assert_step_warned(&report, "published_entries", &format!("signed by BB-{id}"));
    }

    // -- t10e: an unreadable confirmation slipped in next to the genuine
    //          one (a reader of the board still sees "a confirmation") ------
    {
        let mut unreadable = raw.clone();
        let pos = unreadable
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("cast_intended_proof"))
            .unwrap();
        let genuine_entry = unreadable[pos].clone();
        let mut payload = payload_of(&unreadable[pos].1).unwrap();
        payload["bb_id"] = serde_json::json!(payload["bb_id"].as_u64().unwrap().to_string());
        rewrite_and_resign(&mut unreadable[pos].1, &payload, &keys);
        unreadable.insert(pos + 1, genuine_entry);
        let report = audit_raw_entries(&cfg, unreadable).await;
        assert_step_warned(&report, "published_entries", "cannot be read");
    }

    // -- t10f: a forged opened value shown FIRST, the genuine confirmation
    //          published later to cover it: every confirmation is audited --
    {
        let mut covered = raw.clone();
        let pos = covered
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("cast_intended_proof"))
            .unwrap();
        let genuine_entry = covered[pos].clone();
        let mut payload = payload_of(&covered[pos].1).unwrap();
        let level = payload["opened"]["l1"].as_object_mut().expect("opened l1");
        let slot = level.keys().next().unwrap().clone();
        let value = level[&slot].as_u64().unwrap();
        level.insert(slot, serde_json::json!(value + 1));
        rewrite_and_resign(&mut covered[pos].1, &payload, &keys);
        covered.insert(pos + 1, genuine_entry);
        let report = audit_raw_entries(&cfg, covered).await;
        assert_step_warned(&report, "cai_confirmation", "published opened values");
    }

    // -- t10g: a ballot box shadowing the signer list: its OWN signature
    //          under `entity_id`, plus an `entity_ids` naming another box.
    //          The board verifies one form and logs whatever else it is
    //          sent, so an entry carrying both counts as signed by nobody --
    {
        let mut shadowed = raw.clone();
        let pos = shadowed
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("ballot_digest"))
            .unwrap();
        let mut payload = payload_of(&shadowed[pos].1).unwrap();
        let id = payload["receipt"]["bb_id"].as_u64().unwrap();
        let other = if id == 1 { 2 } else { 1 };
        payload["receipt"]["bb_id"] = serde_json::json!(other);
        payload["emoji"][0] = serde_json::json!("?");
        rewrite_and_resign(&mut shadowed[pos].1, &payload, &keys);
        shadowed[pos].1["entity_ids"] = serde_json::json!([format!("BB-{other}")]);
        let report = audit_raw_entries(&cfg, shadowed).await;
        assert!(!report.ok(), "an entry with both signer forms must FAIL");
        assert_step_failed(&report, "entry_signatures");
    }

    // -- t10h: a ballot box forging an opened value while releasing
    //          nothing at all: the check is against the ballot released by
    //          ANY box, so withholding its own release hides nothing ------
    {
        let mut cross = raw.clone();
        let pos = cross
            .iter()
            .position(|(_, e)| {
                entry_type_of(e).as_deref() == Some("cast_intended_proof")
                    && payload_of(e).is_some_and(|p| p["bb_id"] == 1)
            })
            .unwrap();
        let mut payload = payload_of(&cross[pos].1).unwrap();
        let level = payload["opened"]["l1"].as_object_mut().unwrap();
        let slot = level.keys().next().unwrap().clone();
        let value = level[&slot].as_u64().unwrap();
        level.insert(slot, serde_json::json!(value + 1));
        rewrite_and_resign(&mut cross[pos].1, &payload, &keys);
        cross.retain(|(_, e)| {
            entry_type_of(e).as_deref() != Some("encrypted_ballot")
                || e.get("entity_id").and_then(|v| v.as_str()) != Some("BB-1")
        });
        let report = audit_raw_entries(&cfg, cross).await;
        assert_step_warned(
            &report,
            "cai_confirmation",
            "but the released ballot opens to",
        );
    }

    // -- t11: a ballot box that swaps the SEQUENCE NUMBERS of the ballots
    //         it releases. Everything it published during voting stays
    //         untouched and its release is signed and self-consistent, but
    //         the sequence number decides which ballot the re-vote filter
    //         keeps: one box would silently choose for the voter ----------
    {
        let mut swapped = raw.clone();
        let mut positions: Vec<usize> = swapped
            .iter()
            .enumerate()
            .filter(|(_, (_, e))| {
                entry_type_of(e).as_deref() == Some("encrypted_ballot")
                    && e.get("entity_id").and_then(|v| v.as_str()) == Some("BB-1")
            })
            .map(|(i, _)| i)
            .collect();
        assert!(positions.len() >= 2, "BB-1 released several ballots");
        positions.truncate(2);
        let seq_of = |value: &serde_json::Value| -> u64 {
            payload_of(value).unwrap()["record"]["receipt"]["seq_no"]
                .as_u64()
                .unwrap()
        };
        let (a, b) = (
            seq_of(&swapped[positions[0]].1),
            seq_of(&swapped[positions[1]].1),
        );
        assert_ne!(a, b);
        for (pos, seq) in [(positions[0], b), (positions[1], a)] {
            let mut payload = payload_of(&swapped[pos].1).unwrap();
            payload["record"]["receipt"]["seq_no"] = serde_json::json!(seq);
            rewrite_and_resign(&mut swapped[pos].1, &payload, &keys);
        }
        let report = audit_raw_entries(&cfg, swapped).await;
        // The order no longer comes from receipts, so the lie changes nothing;
        // it is still a lie, and named.
        assert_step_warned(&report, "ballot_release", "but published");
    }

    // -- t12: what a ballot box publishes ABOUT a ballot (`ballot_metadata`)
    //         must be readable, its own, and about a ballot it accepted ----
    {
        let pos_of = |raw: &RawEntries| {
            raw.iter()
                .position(|(_, e)| entry_type_of(e).as_deref() == Some("ballot_metadata"))
                .expect("a ballot_metadata entry")
        };
        // (a) signed by one box, naming the other.
        let mut mislabelled = raw.clone();
        let pos = pos_of(&mislabelled);
        let mut payload = payload_of(&mislabelled[pos].1).unwrap();
        let id = payload["bb_id"].as_u64().unwrap();
        payload["bb_id"] = serde_json::json!(if id == 1 { 2 } else { 1 });
        rewrite_and_resign(&mut mislabelled[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, mislabelled).await;
        assert_step_warned(&report, "published_entries", "did not sign");

        // (b) about a ballot that box never accepted.
        let mut foreign = raw.clone();
        let pos = pos_of(&foreign);
        let mut payload = payload_of(&foreign[pos].1).unwrap();
        payload["digest"] = serde_json::json!("A".repeat(43));
        rewrite_and_resign(&mut foreign[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, foreign).await;
        assert_step_warned(&report, "published_entries", "never accepted");

        // (c) unreadable.
        let mut unreadable = raw.clone();
        let pos = pos_of(&unreadable);
        rewrite_and_resign(
            &mut unreadable[pos].1,
            &serde_json::json!({ "nothing": true }),
            &keys,
        );
        let report = audit_raw_entries(&cfg, unreadable).await;
        assert_step_warned(&report, "published_entries", "cannot be read");
    }

    // -- t13: the other two receipt rules of `ballot_release` -------------
    {
        // (a) a box releasing a ballot it never published a receipt for.
        let mut unpublished = raw.clone();
        let pos = unpublished
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("ballot_digest"))
            .unwrap();
        let bb_id = payload_of(&unpublished[pos].1).unwrap()["receipt"]["bb_id"]
            .as_u64()
            .unwrap();
        let digest = payload_of(&unpublished[pos].1).unwrap()["digest"]
            .as_str()
            .unwrap()
            .to_string();
        unpublished.remove(pos);
        // Its metadata entry goes with it: otherwise that entry, now about a
        // ballot this box has no acceptance for, fails a step earlier.
        unpublished.retain(|(_, e)| {
            entry_type_of(e).as_deref() != Some("ballot_metadata")
                || payload_of(e).is_some_and(|p| {
                    p["digest"] != serde_json::json!(digest) || p["bb_id"] != bb_id
                })
        });
        let report = audit_raw_entries(&cfg, unpublished).await;
        // Releasing it is NOT misconduct: the release rule (Sec. 3.9 step 3)
        // releases a counted ballot whose digest ANY box published, and this
        // box's own publication may simply have been lost on its channel.
        // Confirming a ballot whose digest it never published still is named
        // (an honest box publishes its digest before it confirms); the other
        // box's acceptance counts the ballot, so the audit passes.
        assert!(report.ok(), "audit:\n{}", report.render());
        assert!(
            !report.steps.iter().any(|s| s.name == "ballot_release"
                && s.detail.contains("without having published a receipt")),
            "a release on another box's digest was reported as misconduct:\n{}",
            report.render()
        );
        assert_step_warned(
            &report,
            "cai_confirmation",
            "whose digest it never published",
        );

        // (b) a box publishing two DIFFERENT receipts for one ballot: it
        //     could then pick which one to release.
        let mut two_receipts = raw.clone();
        let pos = two_receipts
            .iter()
            .position(|(_, e)| {
                entry_type_of(e).as_deref() == Some("ballot_digest")
                    && payload_of(e).is_some_and(|p| p["digest"] == serde_json::json!(digest))
            })
            .unwrap();
        let copy = two_receipts[pos].clone();
        let mut payload = payload_of(&copy.1).unwrap();
        payload["receipt"]["seq_no"] =
            serde_json::json!(payload["receipt"]["seq_no"].as_u64().unwrap() + 100);
        let mut second = copy.clone();
        rewrite_and_resign(&mut second.1, &payload, &keys);
        two_receipts.insert(pos + 1, second);
        let report = audit_raw_entries(&cfg, two_receipts).await;
        // Nothing depends on the receipt any more; the box is still named.
        assert_step_warned(&report, "ballot_release", "different receipts");
        let _ = bb_id;
    }

    // -- t14: the electoral roll leaving a voter off the eligible list. The
    //         ballot is accepted, confirmed, released and reconciled; it
    //         dies unremarked in the last filter, whose credential mix has
    //         no credential for that identifier ---------------------------
    {
        let mut shortened = raw.clone();
        let pos = shortened
            .iter()
            .position(|(_, e)| entry_type_of(e).as_deref() == Some("eligible_vids"))
            .expect("the eligible_vids entry");
        let mut payload = payload_of(&shortened[pos].1).unwrap();
        let list = payload.as_array_mut().expect("a list of identifiers");
        assert!(list.len() > 1);
        list.pop();
        rewrite_and_resign(&mut shortened[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, shortened).await;
        assert!(!report.ok(), "a voter left off the eligible list must FAIL");
        assert_step_failed(&report, "eligible_identifiers");
        let step = report
            .steps
            .iter()
            .find(|s| s.name == "eligible_identifiers" && !s.ok)
            .unwrap();
        assert!(step.detail.contains("cannot vote"), "{}", step.detail);

        // The same list with a repeat instead of a missing identifier.
        let mut repeated = raw.clone();
        let mut payload = payload_of(&repeated[pos].1).unwrap();
        let list = payload.as_array_mut().unwrap();
        let first = list[0].clone();
        *list.last_mut().unwrap() = first;
        rewrite_and_resign(&mut repeated[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, repeated).await;
        assert!(!report.ok(), "a repeated identifier must FAIL");
        assert_step_failed(&report, "eligible_identifiers");
    }

    // -- t15: the credential-check blinding is the tellers' threshold secret
    //         (Sec. 3.9 steps 20-21): the published artifact holds every
    //         teller's blinding share with its proof and the interpolation.
    //         (a) two blinded checks swapped in the interpolated list: not
    //         the interpolation of the shares any more; (b) two entries
    //         swapped inside ONE teller's share: that teller's proof fails
    //         and the teller is named. No scalar is published to tamper with.
    {
        let pos = raw
            .iter()
            .position(|(_, e)| {
                entry_type_of(e).as_deref() == Some("re_encryption_proof")
                    && payload_of(e).is_some_and(|p| p["kind"] == "acc_checks")
            })
            .expect("the ACC checks entry");
        let mut swapped = raw.clone();
        let mut payload = payload_of(&swapped[pos].1).unwrap();
        assert!(
            payload.get("zeta").is_none(),
            "no blinding scalar is published"
        );
        let list = payload["blinding"]["fp_lists"][0].as_array_mut().unwrap();
        list.swap(0, 1);
        rewrite_and_resign(&mut swapped[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, swapped).await;
        assert!(
            !report.ok(),
            "a blinding that is not the shares' interpolation must FAIL"
        );
        assert_step_failed(&report, "acc_checks");

        let mut one_share = raw.clone();
        let mut payload = payload_of(&one_share[pos].1).unwrap();
        let share = payload["blinding"]["shares"][0]["fp_lists"][0]
            .as_array_mut()
            .unwrap();
        share.swap(0, 1);
        rewrite_and_resign(&mut one_share[pos].1, &payload, &keys);
        let report = audit_raw_entries(&cfg, one_share).await;
        assert!(!report.ok(), "a blinding share whose proof fails must FAIL");
        let step = report
            .steps
            .iter()
            .find(|s| s.name == "acc_checks" && !s.ok)
            .expect("acc_checks fails");
        assert!(
            step.detail.contains("FailedVerifiableDecryption(1)") || step.detail.contains("TT-1"),
            "the teller whose share fails must be named: {}",
            step.detail
        );
    }

    // -- t4: flip a signature byte (no insider keys involved) --------------
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

/// The audit PASSES - the result stands - but `step` carries a WARNING naming
/// the misbehaviour (thesis A9: one dishonest ballot box is survived; Sec. 3.8.4
/// step 15: divergent data is published, not fatal). `needle` must appear in
/// the warning, so the right lie is the one reported.
fn assert_step_warned(
    report: &referendum_poc::actors::auditor::AuditReport,
    step: &str,
    needle: &str,
) {
    assert!(
        report.ok(),
        "the result is unaffected, so the audit must PASS:\n{}",
        report.render()
    );
    let warned = report
        .steps
        .iter()
        .find(|s| s.name == step && s.warning)
        .unwrap_or_else(|| panic!("expected step `{step}` to WARN, got:\n{}", report.render()));
    assert!(
        warned.detail.contains(needle),
        "the warning at `{step}` must report {needle:?}, got: {}",
        warned.detail
    );
}

/// The misbehaviour is named at `step` AND the audit fails: the tamper edited
/// the log after an honest tally, so the board no longer counts a ballot the
/// published pipeline contains (live, the driver would not have counted it
/// either - the two would agree).
fn assert_warned_and_failed(
    report: &referendum_poc::actors::auditor::AuditReport,
    step: &str,
    needle: &str,
) {
    let warned = report
        .steps
        .iter()
        .find(|s| s.name == step && s.warning)
        .unwrap_or_else(|| panic!("expected step `{step}` to WARN, got:\n{}", report.render()));
    assert!(
        warned.detail.contains(needle),
        "the warning at `{step}` must report {needle:?}, got: {}",
        warned.detail
    );
    assert!(
        !report.ok(),
        "the published pipeline covers a ballot the board no longer counts:\n{}",
        report.render()
    );
}

fn assert_step_failed(report: &referendum_poc::actors::auditor::AuditReport, step: &str) {
    assert!(
        report.steps.iter().any(|s| !s.ok && s.name == step),
        "expected step `{step}` to FAIL, got:\n{}",
        report.render()
    );
}

/// The entry type of a raw log entry, if its data decodes.
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
/// document - structure-agnostic share forgery.
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

/// The auditor does not take the board's entry list on trust (Sec. 3.4:
/// insert-only, inconsistent views detectable): it ties the list to a tree
/// head signed by the log key PINNED at the ceremony. Any entry that is
/// altered, dropped, reordered or re-timestamped, a list shorter than the
/// tree head, a lying `leaf_hash`, or a tree head from another key must fail
/// the very first step, before any artifact is looked at.
#[tokio::test]
async fn auditor_verifies_the_log_itself() {
    use referendum_poc::actors::auditor::audit_raw_log;
    use referendum_poc::clients::wbb::RawSequencedEntry;

    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;
    cluster.tally().await;

    let cfg = cluster.audit_config();
    let checkpoint = cluster.wbb.client.checkpoint().await.expect("checkpoint");
    let genuine = cluster
        .wbb
        .client
        .entries_raw()
        .await
        .expect("entries")
        .entries;
    assert!(genuine.len() > 10);

    // Baseline: the genuine log passes, and the first step is the log check.
    let report = audit_raw_log(&cfg, &checkpoint, genuine.clone()).await;
    assert!(report.ok(), "genuine log:\n{}", report.render());
    assert_eq!(report.steps[0].name, "log_integrity");
    assert!(report.steps[0]
        .detail
        .contains("signed by the pinned log key"));

    // Rebuild one entry from edited JSON (RawValue keeps the exact bytes).
    let edit =
        |entry: &RawSequencedEntry, f: &dyn Fn(&mut serde_json::Value)| -> RawSequencedEntry {
            let mut value = serde_json::json!({
                "leaf_index": entry.leaf_index,
                "timestamp": entry.timestamp,
                "entry": serde_json::from_str::<serde_json::Value>(entry.entry.get()).unwrap(),
            });
            f(&mut value);
            let mut rebuilt: RawSequencedEntry = serde_json::from_value(value).unwrap();
            rebuilt.leaf_hash = None; // let the ROOT catch it, not the claimed hash
            rebuilt
        };
    let expect_log_failure = |report: referendum_poc::actors::auditor::AuditReport, what: &str| {
        assert!(!report.ok(), "{what} must FAIL");
        assert_eq!(
            report.steps.len(),
            1,
            "{what}: nothing is audited past a broken log"
        );
        assert_eq!(report.steps[0].name, "log_integrity", "{what}");
        report.steps[0].detail.clone()
    };

    // 1. One character of one entry altered.
    let mut altered = genuine.clone();
    altered[3] = edit(&genuine[3], &|v| {
        let data = v["entry"]["data"].as_str().unwrap().to_string();
        let flipped = if data.ends_with('A') { "B" } else { "A" };
        v["entry"]["data"] = serde_json::json!(format!("{}{flipped}", &data[..data.len() - 1]));
    });
    let detail = expect_log_failure(
        audit_raw_log(&cfg, &checkpoint, altered).await,
        "altered entry",
    );
    assert!(detail.contains("altered, dropped, reordered"), "{detail}");

    // 2. An entry dropped from the middle (indices no longer line up).
    let mut dropped = genuine.clone();
    dropped.remove(5);
    expect_log_failure(
        audit_raw_log(&cfg, &checkpoint, dropped).await,
        "dropped entry",
    );

    // 3. The list cut short: fewer entries than the tree head covers.
    let truncated = genuine[..genuine.len() - 1].to_vec();
    let detail = expect_log_failure(
        audit_raw_log(&cfg, &checkpoint, truncated).await,
        "truncated list",
    );
    assert!(detail.contains("covers"), "{detail}");

    // 4. Two entries swapped, with their indices fixed up to look tidy.
    let mut swapped = genuine.clone();
    swapped[6] = edit(&genuine[7], &|v| v["leaf_index"] = serde_json::json!(6));
    swapped[7] = edit(&genuine[6], &|v| v["leaf_index"] = serde_json::json!(7));
    expect_log_failure(
        audit_raw_log(&cfg, &checkpoint, swapped).await,
        "reordered entries",
    );

    // 5. A sequencing timestamp changed.
    let mut retimed = genuine.clone();
    retimed[2] = edit(&genuine[2], &|v| {
        v["timestamp"] = serde_json::json!(v["timestamp"].as_i64().unwrap() + 1)
    });
    expect_log_failure(
        audit_raw_log(&cfg, &checkpoint, retimed).await,
        "re-timestamped entry",
    );

    // 6. The board lies about a leaf hash while the entry is genuine.
    let mut lying = genuine.clone();
    lying[1].leaf_hash = Some("00".repeat(32));
    let detail = expect_log_failure(
        audit_raw_log(&cfg, &checkpoint, lying).await,
        "lying leaf hash",
    );
    assert!(detail.contains("claims leaf hash"), "{detail}");

    // 7. A tree head that is not signed by the PINNED key: an auditor pinned
    //    to another log's key refuses this board's genuine tree head.
    let mut other = cfg.clone();
    other.log_key = referendum_poc::protocol::tlog::derive_log_public_key(&[9u8; 32]).unwrap();
    let detail = expect_log_failure(
        audit_raw_log(&other, &checkpoint, genuine.clone()).await,
        "foreign key",
    );
    assert!(
        detail.contains("not signed by the pinned log key"),
        "{detail}"
    );

    // 8. Entries appended after the tree head are simply not audited: the
    //    report equals the genuine one.
    let mut longer = genuine.clone();
    longer.push(edit(&genuine[0], &|v| {
        v["leaf_index"] = serde_json::json!(genuine.len());
    }));
    let report = audit_raw_log(&cfg, &checkpoint, longer).await;
    assert!(
        report.ok(),
        "entries beyond the tree head are ignored:\n{}",
        report.render()
    );
    assert!(
        report.steps[0]
            .detail
            .contains("1 newer served entries are not covered"),
        "what is left unaudited is said out loud: {}",
        report.steps[0].detail
    );

    // 9-10. The tree head itself edited under its genuine signature: a
    //       smaller size (to hide the tail) or another root.
    let text = String::from_utf8(checkpoint.clone()).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let size: usize = lines[1].parse().unwrap();
    let mut shrunk = lines.clone();
    shrunk[1] = (size - 1).to_string();
    let mut rerooted = lines.clone();
    rerooted[2] = BASE64.encode([7u8; 32]);
    for (what, edited) in [
        ("shrunk tree head", shrunk),
        ("re-rooted tree head", rerooted),
    ] {
        let edited = format!("{}\n", edited.join("\n")).into_bytes();
        let detail = expect_log_failure(audit_raw_log(&cfg, &edited, genuine.clone()).await, what);
        assert!(
            detail.contains("not signed by the pinned log key"),
            "{what}: {detail}"
        );
    }

    // 11. A genuine tree head of ANOTHER log name under the same key is not
    //     this election's log.
    lines.clear();
    let mut renamed = cfg.clone();
    renamed.log_origin = "elsewhere.example/wbb".to_string();
    let detail = expect_log_failure(
        audit_raw_log(&renamed, &checkpoint, genuine.clone()).await,
        "foreign log name",
    );
    assert!(detail.contains("pinned to"), "{detail}");
}

/// Sec. 3.9 step 10: which of a voter's ballots counts is decided by the
/// BOARD's order - the leaf each ballot's first acceptance was published at -
/// and not by the `seq_no` a ballot box mints for itself.
///
/// Here BB-1 numbers its ballots backwards, consistently: the receipts it
/// published when it accepted them and the ones it releases at tally agree,
/// so nothing it says is self-contradictory. The audit must still PASS (it
/// has nothing to accuse BB-1 of) and the re-vote must still win.
#[tokio::test]
async fn the_board_orders_the_tally_not_the_ballot_boxes() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    // Voter 0 votes, then changes their mind: only the re-vote may count.
    let pin0 = cluster.pin(0).await;
    cluster.vote_and_cast(0, "approve", pin0).await;
    cluster.vote_and_cast(0, "reject", pin0).await;
    for (i, option) in [(1usize, "reject"), (2, "blank")] {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 0, 2),
        "the re-vote wins"
    );

    let cfg = cluster.audit_config();
    let keys: HashMap<String, SigningKey> = ["1", "2"]
        .into_iter()
        .map(|i| (format!("BB-{i}"), cluster.signing_key(&format!("bb-{i}"))))
        .collect();
    let raw: RawEntries = cluster
        .wbb
        .client
        .entries_raw()
        .await
        .expect("entries")
        .entries
        .into_iter()
        .map(|e| {
            (
                e.leaf_index,
                serde_json::from_str::<serde_json::Value>(e.entry.get()).unwrap(),
            )
        })
        .collect();
    assert!(audit_raw_entries(&cfg, raw.clone()).await.ok());

    // BB-1 numbers backwards, in BOTH what it published and what it released.
    let mut backwards = raw.clone();
    for (_, entry) in backwards.iter_mut() {
        if entry.get("entity_id").and_then(|v| v.as_str()) != Some("BB-1") {
            continue;
        }
        let Some(kind) = entry_type_of(entry) else {
            continue;
        };
        let pointer = match kind.as_str() {
            "ballot_digest" => "/receipt/seq_no",
            "encrypted_ballot" => "/record/receipt/seq_no",
            _ => continue,
        };
        let Some(mut payload) = payload_of(entry) else {
            continue;
        };
        let Some(seq) = payload.pointer(pointer).and_then(|v| v.as_u64()) else {
            continue;
        };
        *payload.pointer_mut(pointer).unwrap() = serde_json::json!(u64::MAX - seq);
        rewrite_and_resign(entry, &payload, &keys);
    }
    let report = audit_raw_entries(&cfg, backwards).await;
    assert!(
        report.ok(),
        "a ballot box's own numbering is nobody's business:\n{}",
        report.render()
    );
}

/// The bulletin board logs a co-signature that arrives after publication as a
/// leaf whose data is `ref:N` and whose signature is over the data of leaf N
/// (Sec. 3.4.2 threshold entries: a teller can always be late). The auditor
/// must resolve it - neither failing an honest late signer nor accepting a
/// reference to anything else.
#[tokio::test]
async fn auditor_resolves_a_late_co_signature() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;
    cluster.tally().await;

    let cfg = cluster.audit_config();
    let raw: RawEntries = cluster
        .wbb
        .client
        .entries_raw()
        .await
        .expect("entries")
        .entries
        .into_iter()
        .map(|e| {
            (
                e.leaf_index,
                serde_json::from_str::<serde_json::Value>(e.entry.get()).unwrap(),
            )
        })
        .collect();
    assert!(audit_raw_entries(&cfg, raw.clone()).await.ok());

    // A co-signed entry and a teller that signs it after publication.
    let (index, data_b64) = raw
        .iter()
        .find(|(_, e)| e.get("entity_ids").is_some())
        .map(|(i, e)| (*i, e["data"].as_str().unwrap().to_string()))
        .expect("a co-signed entry");
    let signed_ids: Vec<String> =
        serde_json::from_value(raw[index as usize].1["entity_ids"].clone()).unwrap();
    let late = ["RT-1", "RT-2", "RT-3"]
        .into_iter()
        .find(|id| !signed_ids.contains(&id.to_string()))
        .unwrap_or("RT-3");
    let key = cluster.signing_key(&late.to_lowercase());
    let timestamp = raw.last().unwrap().1["timestamp"].as_i64().unwrap() + 1;
    let signature = {
        let mut hasher = Sha256::new();
        hasher.update(BASE64.decode(&data_b64).unwrap());
        hasher.update(late.as_bytes());
        hasher.update(format!("{timestamp}").as_bytes());
        BASE64.encode(key.sign(&hasher.finalize()).to_bytes())
    };
    let leaf = |reference: &str| -> (i64, serde_json::Value) {
        (
            raw.len() as i64,
            serde_json::json!({
                "data": BASE64.encode(reference.as_bytes()),
                "timestamp": timestamp,
                "entity_id": late,
                "signature": signature,
            }),
        )
    };

    // The genuine late co-signature: the audit still passes.
    let mut with_late = raw.clone();
    with_late.push(leaf(&format!("ref:{index}")));
    let report = audit_raw_entries(&cfg, with_late).await;
    assert!(report.ok(), "an honest late signer:\n{}", report.render());

    // The same signature pointed at anything else must not verify, and a
    // reference to no entry at all is refused outright.
    for reference in [
        format!("ref:{}", index + 1),
        format!("ref:{}", raw.len() + 5),
        "ref:-1".to_string(),
        "ref:99999999999999999999".to_string(),
    ] {
        let mut bad = raw.clone();
        bad.push(leaf(&reference));
        let report = audit_raw_entries(&cfg, bad).await;
        assert!(!report.ok(), "{reference} must FAIL");
        assert_step_failed(&report, "entry_signatures");
    }
}
