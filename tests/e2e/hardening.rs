//! Regressions for the guarantees an adversarial review found bent:
//! the boxes' one-slot rule (Sec. 3.8.4 steps 13-16), the tellers' zeta VSS
//! deal (Sec. 2.8 Protocol 2), the roll's once-only setup publication
//! (Sec. 3.5.2 on an append-only board), and the voter-side cover story and
//! device recovery of Sec. 3.7.3 / 3.7.4.

use std::time::Duration;

use super::helpers::{self, ElectionCluster, ElectionOpts};

/// Sec. 3.8.4 steps 13-16: a ballot box opens ONE cast-as-intended slot of a
/// ballot. The two slots of a level together are `sum - code` - the vote - so
/// a second confirmation of the same ballot must leave the board exactly as
/// the first one did, however it reaches the box and however often.
///
/// The OTHER slot cannot be offered to a box from outside the device at all:
/// the app pins the voter's choice and destroys the unused openings before
/// anything is sent, and no ballot is written to disk or into the recovery
/// blob (Sec. 3.6.1 lists what is saved). What a second caller can hold is
/// therefore the published disclosure, and that is what is replayed here.
#[tokio::test(flavor = "multi_thread")]
async fn a_ballot_box_never_opens_the_second_slot_of_a_ballot() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;

    let vote = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = vote["digest"].as_str().expect("digest").to_string();

    let first = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
                "l1": "code", "l2": "sum",
            }),
        )
        .await;
    assert_eq!(first["l1"], "code");

    // A device that has confirmed holds nothing to confirm again: the
    // openings are gone and the cast ballot with them.
    let again = cluster
        .client
        .post(format!("{}/api/confirm", cluster.voter_urls[0]))
        .json(&serde_json::json!({
            "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
            "l1": "sum", "l2": "code",
        }))
        .send()
        .await
        .expect("second confirmation");
    let status = again.status();
    assert!(
        status.is_client_error(),
        "the device refuses a second confirmation: {status} {}",
        again.text().await.unwrap_or_default()
    );

    let published = published_cai(&cluster, &digest).await;
    assert!(!published.is_empty(), "the confirmation reached the board");
    let before = cluster.entry_type_count("cast_intended_proof").await;

    // Whoever reads the board holds the disclosure: replaying it at every box
    // must answer with the values already opened and add nothing to the board.
    for (bb_id, entry) in &published {
        let port = cluster.ports.bb[(*bb_id as usize) - 1];
        let response = cluster
            .client
            .post(format!("https://127.0.0.1:{port}/cai"))
            .json(&serde_json::json!({
                "digest": entry["digest"], "disclosure": entry["disclosure"],
            }))
            .send()
            .await
            .expect("replayed confirmation");
        assert!(
            response.status().is_success(),
            "BB-{bb_id} answers a replay: {}",
            response.status()
        );
        let body: serde_json::Value = response.json().await.expect("replay body");
        assert_eq!(
            body["opened"], entry["opened"],
            "BB-{bb_id} answers with the values it opened the first time"
        );
    }
    assert_eq!(
        cluster.entry_type_count("cast_intended_proof").await,
        before,
        "a replayed confirmation adds nothing to the board"
    );

    // One opening per box, and it is the slot the device chose first.
    let opened = openings_on_board(&cluster, &digest).await;
    for (bb_id, values) in &opened {
        assert_eq!(
            values.len(),
            1,
            "BB-{bb_id} published {} openings for one ballot: {values:?}",
            values.len()
        );
        assert_eq!(
            values[0]["l1"].as_object().and_then(|m| m.keys().next()),
            Some(&"Code".to_string()),
            "BB-{bb_id} published the slot the device chose first"
        );
    }
}

/// The published `cast_intended_proof` entries for `digest`, by ballot box.
async fn published_cai(
    cluster: &ElectionCluster,
    digest: &str,
) -> std::collections::BTreeMap<u64, serde_json::Value> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let entries = cluster.wbb.client.entries().await.expect("wbb entries");
    let mut out: std::collections::BTreeMap<u64, serde_json::Value> = Default::default();
    for sequenced in &entries.entries {
        let Some(raw) = sequenced
            .entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| B64.decode(b64).ok())
        else {
            continue;
        };
        let Some(parsed) = referendum_poc::protocol::voting::parse_wbb_data(&raw) else {
            continue;
        };
        if parsed.entry_type != "cast_intended_proof" {
            continue;
        }
        let Ok(value) = parsed.decode_payload::<serde_json::Value>() else {
            continue;
        };
        if value["digest"].as_str() != Some(digest) {
            continue;
        }
        let bb_id = value["bb_id"].as_u64().unwrap_or_default();
        out.entry(bb_id).or_insert(value);
    }
    out
}

/// Every published `cast_intended_proof` for `digest`, by ballot box.
async fn openings_on_board(
    cluster: &ElectionCluster,
    digest: &str,
) -> std::collections::BTreeMap<u64, Vec<serde_json::Value>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let entries = cluster.wbb.client.entries().await.expect("wbb entries");
    let mut out: std::collections::BTreeMap<u64, Vec<serde_json::Value>> = Default::default();
    for sequenced in &entries.entries {
        let Some(raw) = sequenced
            .entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| B64.decode(b64).ok())
        else {
            continue;
        };
        let Some(parsed) = referendum_poc::protocol::voting::parse_wbb_data(&raw) else {
            continue;
        };
        if parsed.entry_type != "cast_intended_proof" {
            continue;
        }
        let Ok(value) = parsed.decode_payload::<serde_json::Value>() else {
            continue;
        };
        if value["digest"].as_str() != Some(digest) {
            continue;
        }
        let bb_id = value["bb_id"].as_u64().unwrap_or_default();
        out.entry(bb_id).or_default().push(value["opened"].clone());
    }
    out
}

/// Sec. 3.5.2 on an append-only board (A3): the roll publishes its setup
/// artifacts once. A retry - an operator's, or a re-run after one of the five
/// submissions was cut off - must not leave two of them.
#[tokio::test(flavor = "multi_thread")]
async fn the_rolls_setup_publication_is_once_only() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let before = cluster.entry_type_count("tt_public_shares").await;
    assert_eq!(before, 1, "the harness published the setup once");

    let again = cluster
        .client
        .post(format!("{}/admin/setup", cluster.er_base()))
        .header("Authorization", format!("Bearer {}", cluster.admin_token()))
        .send()
        .await
        .expect("second setup");
    assert!(
        again.status().is_success(),
        "a retry is adopted, not refused"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cluster.entry_type_count("tt_public_shares").await,
        1,
        "a second setup call must not put a second copy on the board"
    );
}

/// Sec. 6.3.2 p. 131: "a ruse PIN is always displayed exactly as the valid
/// PIN, the attacker is not sure of the validity of the PIN learned", and
/// Sec. 3.7.3 puts no limit on ruse requests. So `/api/pin/ruse` must leave
/// the SAME state behind whatever it is given - a difference in the answer,
/// or in what the next screen says, is an oracle that can be run to
/// exhaustion. Arming another value puts the real PIN back.
#[tokio::test(flavor = "multi_thread")]
async fn the_decoy_choice_says_nothing_about_the_real_pin() {
    // Two voters: the verifiable mixes need at least two ballots.
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;
    // A ballot the voter cast in a surveillance gap: what a prober must not
    // be able to reach (Sec. 3.7.3, A1).
    cluster.vote_and_cast(0, "reject", pin).await;

    // Probe with a candidate that is NOT the real PIN, then with the real
    // one, and compare what each leaves behind. The PIN in force authorises
    // the request (Sec. 3.7.3 step 5), and it is the candidate just armed
    // that the next probe authorises with.
    let probe = |auth: u64, candidate: u64| {
        let client = cluster.client.clone();
        let base = cluster.voter_urls[0].clone();
        let passphrase = cluster.passphrases[0].clone();
        async move {
            let armed = client
                .post(format!("{base}/api/pin/ruse"))
                .json(&serde_json::json!({
                    "passphrase": passphrase, "pin": auth, "ruse_pin": candidate,
                }))
                .send()
                .await
                .expect("ruse probe");
            let arm_status = armed.status().as_u16();
            // What a prober holding the candidate can ask afterwards:
            // Sec. 3.7.1 lets them ask it as often as they like.
            let verify = client
                .post(format!("{base}/api/pin/verify"))
                .json(&serde_json::json!({ "passphrase": passphrase, "pin": candidate }))
                .send()
                .await
                .expect("verify probe");
            let verify_status = verify.status().as_u16();
            let valid = verify
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v["valid"].as_bool());
            (arm_status, verify_status, valid)
        }
    };

    let decoy = (pin + 1) % 100_000;
    let innocent = probe(pin, decoy).await;
    let guilty = probe(decoy, pin).await;
    assert_eq!(
        innocent, guilty,
        "arming the real PIN as a decoy must be indistinguishable from arming any other \
         value, in the answer AND in every screen that follows"
    );
    assert_eq!(innocent.0, 200, "a chosen decoy is always accepted");

    // And the voter is not stuck with it: arming another value restores the
    // real PIN, which builds real ballots again.
    let restored = cluster
        .voter_post(
            0,
            "/api/pin/ruse",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "ruse_pin": decoy,
            }),
        )
        .await;
    assert_eq!(restored["ruse_pin"].as_u64(), Some(decoy));
    cluster.vote_and_cast(0, "approve", pin).await;
    let other = cluster.pin(1).await;
    cluster.vote_and_cast(1, "blank", other).await;
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        outcome.counts.si, 1,
        "the voter's own PIN counts again once another decoy is armed"
    );
    assert_eq!(outcome.counts.no, 0, "and the superseded ballot does not");
}

/// Sec. 3.7.5 step 3: a revocation is a NEW registration "as in Section
/// 3.6.1", and the first retrieval of a new credential shows PIN^valid
/// (Sec. 3.6.3 footnote 9). No decoy is carried over: the screens show and
/// verify the new PIN, a ballot cast on it counts, and a voter who wants the
/// old decoy again arms it again by typing it.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_is_a_fresh_start() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    let decoy = cluster.ruse_pin(0, pin).await;

    let revoked = cluster
        .voter_post(
            0,
            "/api/revoke",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    assert!(revoked["vid"].as_u64().is_some(), "a spare identifier");
    helpers::wait_pin_ready(
        &cluster.client,
        &cluster.voter_urls[0],
        &cluster.passphrases[0],
    )
    .await;
    let shown = cluster
        .voter_post(
            0,
            "/api/pin/retrieve",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let new_pin = shown["pin"].as_u64().expect("new pin");
    assert_ne!(
        new_pin, decoy,
        "the retrieval shows the NEW PIN, not the old decoy"
    );
    assert_ne!(new_pin, pin);

    let verify = |candidate: u64| {
        let client = cluster.client.clone();
        let url = format!("{}/api/pin/verify", cluster.voter_urls[0]);
        let passphrase = cluster.passphrases[0].clone();
        async move {
            helpers::post_json(
                &client,
                &url,
                serde_json::json!({ "passphrase": passphrase, "pin": candidate }),
            )
            .await["valid"]
                .as_bool()
        }
    };
    assert_eq!(verify(new_pin).await, Some(true), "the new PIN verifies");
    assert_eq!(verify(decoy).await, Some(false), "the old decoy does not");

    // A ballot cast on what the screens call valid COUNTS.
    cluster.open_voting().await;
    cluster.vote_and_cast(0, "reject", new_pin).await;
    let other = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", other).await;

    // And the voter can arm the old decoy again, by typing it.
    let rearmed = cluster
        .voter_post(
            0,
            "/api/pin/ruse",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": new_pin, "ruse_pin": decoy,
            }),
        )
        .await;
    assert_eq!(rearmed["ruse_pin"].as_u64(), Some(decoy));
    assert_eq!(verify(decoy).await, Some(true));

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (1, 1),
        "the new PIN's ballot counts"
    );
}

/// Sec. 3.6.1 lists what the app stores encrypted and no ballot is among them;
/// Sec. 3.7.4 step 8 has a new device "proceed as in the PIN re-sending
/// procedure". So a device set up from the roll's blob holds the CREDENTIAL
/// and no ballots: it cannot confirm one another device cast, that ballot was
/// never confirmed and so is never counted (Sec. 3.9 step 2), and the voter
/// casts again.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovered_device_holds_the_credential_and_no_ballots() {
    // Two voters: the verifiable mixes need at least two ballots.
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;
    let cast = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = cast["digest"].as_str().expect("digest").to_string();
    let other = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", other).await;

    let second = cluster.spawn_voter_server_as("voter-1", "after-cast").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let recovered = helpers::post_json(
        &cluster.client,
        &format!("{second}/api/device/recover"),
        serde_json::json!({
            "fiscal_id": "VOTER-001", "passphrase": cluster.passphrases[0]
        }),
    )
    .await;
    assert_eq!(recovered["pin_set"], true, "the credential is restored");

    // It cannot finish the other device's ballot: it never held the
    // randomness that opens it.
    let refused = cluster
        .client
        .post(format!("{second}/api/confirm"))
        .json(&serde_json::json!({
            "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
            "l1": "code", "l2": "sum",
        }))
        .send()
        .await
        .expect("confirm on the recovered device");
    assert!(
        !refused.status().is_success(),
        "a recovered device must not be able to disclose a ballot it did not build"
    );

    // The voter votes again on the new device, and THAT ballot counts.
    let fresh = helpers::post_json(
        &cluster.client,
        &format!("{second}/api/vote"),
        serde_json::json!({ "passphrase": cluster.passphrases[0], "option": "blank", "pin": pin }),
    )
    .await;
    assert!(fresh["digest"].as_str().is_some());
    helpers::post_json(
        &cluster.client,
        &format!("{second}/api/cast"),
        serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
    )
    .await;
    let confirm = helpers::post_json(
        &cluster.client,
        &format!("{second}/api/confirm"),
        serde_json::json!({
            "passphrase": cluster.passphrases[0], "pin": pin, "digest": fresh["digest"],
            "l1": "code", "l2": "sum",
        }),
    )
    .await;
    assert!(confirm["confirmed_at_ms"].as_u64().unwrap_or_default() > 0);

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.no, outcome.counts.si),
        (1, 0, 1),
        "the unconfirmed ballot is not counted; the one the voter finished is"
    );
}

/// Sec. 2.8 Protocol 2 steps 4 and 6: the commitments are BROADCAST by their
/// dealer, and the sharings of ALL n dealers are combined. The tally driver
/// only relays them, so a teller must refuse a deal that is not the tellers'
/// own - otherwise a relay could seal a sharing of its own to the tellers'
/// PUBLISHED key shares, have every teller blind with it in good faith, and
/// know the joint exponent.
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_refuses_a_zeta_vss_deal_that_is_not_the_tellers_own() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let tt = |i: usize| format!("https://127.0.0.1:{}", cluster.ports.tt[i]);
    let token = |i: usize| {
        std::fs::read_to_string(
            cluster
                .ceremony_dir()
                .join(format!("tt-{}-service-token.txt", i + 1)),
        )
        .expect("tt service token")
        .trim()
        .to_string()
    };
    let round1 = |i: usize, session: &str| {
        let client = cluster.client.clone();
        let url = format!("{}/vss/zeta/round1", tt(i));
        let auth = format!("Bearer {}", token(i));
        let body = serde_json::json!({ "session": session });
        async move {
            let response = client
                .post(url)
                .header("Authorization", auth)
                .json(&body)
                .send()
                .await
                .expect("zeta round 1");
            assert!(response.status().is_success(), "zeta round 1");
            response.json::<serde_json::Value>().await.expect("json")
        }
    };
    let combine = |i: usize, session: &str, broadcasts: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{}/vss/zeta/combine", tt(i));
        let auth = format!("Bearer {}", token(i));
        let body = serde_json::json!({ "session": session, "broadcasts": broadcasts });
        async move {
            let response = client
                .post(url)
                .header("Authorization", auth)
                .json(&body)
                .send()
                .await
                .expect("zeta combine");
            let status = response.status().as_u16();
            let text = response.text().await.unwrap_or_default();
            (status, text)
        }
    };

    let dealt: Vec<serde_json::Value> = {
        let mut out = Vec::new();
        for i in 0..3 {
            out.push(round1(i, "probe").await);
        }
        out
    };

    // 1. A deal with this teller's own broadcast replaced by a re-deal of it
    //    - genuinely this teller's, genuinely signed, but dealt for another
    //    session. The signature binds the session, so it is refused there;
    //    the own-broadcast comparison stands behind it.
    let substitute = round1(0, "other-session").await;
    let mut swapped = dealt.clone();
    swapped[0] = substitute;
    let (status, body) = combine(0, "probe", serde_json::json!(swapped)).await;
    assert_eq!(status, 400, "a substituted own broadcast: {body}");
    assert!(
        body.contains("own broadcast") || body.contains("did not sign"),
        "{body}"
    );

    // 2. A deal with one dealer left out and another counted twice.
    let doubled = serde_json::json!([dealt[0], dealt[1], dealt[1]]);
    let (status, body) = combine(0, "probe", doubled).await;
    assert_eq!(status, 400, "a deal that is not one per teller: {body}");
    assert!(body.contains("one broadcast from each teller"), "{body}");

    // 3. A deal with a dealer's sealed shares tampered with.
    let mut tampered = dealt.clone();
    let masked = tampered[1]["broadcast"]["sealed_shares"][0]["masked"]
        .as_str()
        .expect("masked share")
        .to_string();
    let flipped: String = masked
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 0 && c == 'a' {
                'b'
            } else if i == 0 {
                'a'
            } else {
                c
            }
        })
        .collect();
    tampered[1]["broadcast"]["sealed_shares"][0]["masked"] = serde_json::json!(flipped);
    let (status, body) = combine(0, "probe", serde_json::json!(tampered)).await;
    assert_eq!(status, 400, "a tampered broadcast: {body}");
    assert!(body.contains("did not sign"), "{body}");
}

/// Sec. 6.3.1 A2 ("at least nRT - tRT + 1 RTs are trusted"): one registration
/// teller must not be able to deny a voter their credential - at ANY step of
/// Sec. 3.6.1-3.6.3, the two DVNIZKP rounds of Sec. 3.6.2 included.
#[tokio::test(flavor = "multi_thread")]
async fn one_teller_that_drops_out_of_the_credential_proof_denies_nobody() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;

    // A stand-in in front of rt-1 that forwards everything but the second
    // round of the credential proof.
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[0]))
        .expect("rt url");
    let stand_in = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _body: &[u8]| {
            path.contains("dvnizkp/round2").then(|| {
                (
                    reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::body::Bytes::from_static(b"{\"error\":\"nope\"}"),
                )
            })
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("rt-1", stand_in.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert!(
        pin["pin"].as_u64().is_some(),
        "the credential is rebuilt from the tellers that finished the proof: {pin}"
    );
}

/// Sec. 3.8.5 item 1: the app's screens must tell the voter ONE thing about a
/// ballot. A decoy cast between two casts of the same real ballot must not
/// leave two records of it, or confirmation marks one and the status screen
/// reads the other.
#[tokio::test(flavor = "multi_thread")]
async fn a_decoy_cast_between_two_casts_leaves_one_record() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;

    let real = cluster.vote(0, "reject", pin).await;
    cluster.cast(0, pin).await;

    // A decoy, cast in between (Sec. 3.7.3).
    let decoy = cluster.ruse_pin(0, pin).await;
    cluster.vote(0, "approve", decoy).await;
    cluster.cast(0, decoy).await;

    // The real ballot cast again - a lost answer, from the app's side.
    cluster.cast(0, pin).await;

    let confirm = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "digest": real["digest"],
                "l1": "code", "l2": "sum",
            }),
        )
        .await;
    assert_eq!(confirm["will_be_counted"], true);

    let status = cluster
        .voter_post(
            0,
            "/api/ballot/status",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    assert_eq!(
        status["will_be_counted"], true,
        "the status screen must answer about the ballot the voter just confirmed: {status}"
    );
    assert!(status["confirmed_at_ms"].as_u64().unwrap_or_default() > 0);
}

/// Sec. 3.9 step 22 decrypts `E^z`, never `E`; Sec. 3.8.3 footnote 18 says
/// why. The credential checks are a public function of two board entries, so
/// a teller that decrypted a list its caller simply handed it would let the
/// coordinator skip the threshold blinding altogether and read
/// `g3^(PIN_used - PIN_real)` off every discarded check - the coercion
/// resistance of Sec. 3.7 that the blinding exists to protect.
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_decrypts_only_what_its_own_blinding_produced() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let tt = format!("https://127.0.0.1:{}", cluster.ports.tt[0]);
    let token = std::fs::read_to_string(cluster.ceremony_dir().join("tt-1-service-token.txt"))
        .expect("tt service token")
        .trim()
        .to_string();

    // A caller-chosen list, with no blinding artifact behind it at all.
    for endpoint in ["decrypt/acc-checks", "decrypt/ox", "decrypt/fps"] {
        let bare = cluster
            .client
            .post(format!("{tt}/{endpoint}"))
            .header("Authorization", format!("Bearer {token}"))
            .json(&serde_json::json!({ "blinded": [], "fps": null, "originals": [] }))
            .send()
            .await
            .expect("bare decryption request");
        assert!(
            !bare.status().is_success(),
            "{endpoint} must refuse a list with no blinding behind it"
        );
    }

    // And a well-formed artifact that this teller had no part in: the
    // blinding of an EMPTY session, which no teller ever performed.
    let empty = cluster
        .client
        .post(format!("{tt}/decrypt/acc-checks"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "fps": { "commitments": [], "shares": [], "fp_lists": [[]] },
            "originals": [[]],
            "transcript": "acc",
        }))
        .send()
        .await
        .expect("empty artifact request");
    assert_eq!(
        empty.status().as_u16(),
        400,
        "a blinding this teller did not perform must be refused"
    );
}

/// Sec. 3.7.3 step 5 builds the ruse credential for
/// `x^ruse = x + PIN^ruse - PIN^valid`. So a voter who types their OWN PIN as
/// the decoy gets a credential that IS the valid one, and its ballots count:
/// the app must not tell them otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn a_decoy_equal_to_the_real_pin_still_casts_a_counted_ballot() {
    // Two voters: the verifiable mixes need at least two ballots.
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;

    let armed = cluster
        .voter_post(
            0,
            "/api/pin/ruse",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "ruse_pin": pin,
            }),
        )
        .await;
    assert_eq!(armed["ruse_pin"].as_u64(), Some(pin));

    cluster.open_voting().await;
    cluster.vote_and_cast(0, "reject", pin).await;
    let other = cluster.pin(1).await;
    cluster.vote_and_cast(1, "blank", other).await;
    cluster.close_voting().await;

    let outcome = cluster.tally().await;
    assert_eq!(
        outcome.counts.no, 1,
        "x^ruse = x + PIN^ruse - PIN^valid is x when the PINs are equal, so the ballot counts"
    );
    assert_eq!(outcome.counts.blank, 1);
}

/// Sec. 3.6.1 step 9 has each RT send its share with a proof, and step 11 has
/// the app check those proofs. A teller that delivers a share which does not
/// fit the dealers' published commitments is dropped BY NAME - the voter still
/// gets their credential, and the report says who was wrong rather than which
/// subset happened to work.
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_that_delivers_a_bad_share_is_named_and_dropped() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;

    // A stand-in in front of rt-1 that corrupts the scalar it delivers.
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[0]))
        .expect("rt url");
    let stand_in = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        std::sync::Arc::new(|path: &str, _req: &[u8], status, body| {
            if !path.contains("credentials/deliver") || !status.is_success() {
                return (status, body);
            }
            let Ok(mut share) = serde_json::from_slice::<serde_json::Value>(&body) else {
                return (status, body);
            };
            // Swap two of the scalars: each is still a perfectly well-formed
            // scalar, so nothing fails to parse - they are simply no longer
            // the points the dealers committed to.
            let x = share["share"]["x_share"].clone();
            share["share"]["x_share"] = share["share"]["r_share"].clone();
            share["share"]["r_share"] = x;
            let raw = serde_json::to_vec(&share).unwrap_or_else(|_| body.to_vec());
            (status, axum::body::Bytes::from(raw))
        }),
        None,
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("rt-1", stand_in.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert!(
        pin["pin"].as_u64().is_some(),
        "the credential is rebuilt without the teller that sent a bad share: {pin}"
    );

    // And the teller is NAMED - not merely one of a subset that was left out.
    let status = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/status"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(
        status["rebuilt_without_rts"],
        serde_json::json!(["rt-1"]),
        "the share that did not fit the commitments names its teller: {status}"
    );
}

/// Sec. 3.9 steps 28-29 decrypt the sum of the LEGITIMATE votes, and every
/// input to that sum is on the board by then. So a teller recomputes what it
/// decrypts and takes nothing from its caller: the credential checks are a
/// public function of two board entries, and a teller that decrypted a
/// caller-chosen list under the master tally key would hand out
/// `g3^(PIN_used - PIN_real)` for every discarded check - with nothing
/// published for universal verification to catch.
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_decrypts_only_the_tally_the_board_adds_up_to() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    let other = cluster.pin(1).await;
    cluster.open_voting().await;
    cluster.vote_and_cast(0, "approve", pin).await;
    cluster.vote_and_cast(1, "reject", other).await;
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!((outcome.counts.si, outcome.counts.no), (1, 1));

    let tt = format!("https://127.0.0.1:{}", cluster.ports.tt[0]);
    let token = std::fs::read_to_string(cluster.ceremony_dir().join("tt-1-service-token.txt"))
        .expect("tt service token")
        .trim()
        .to_string();

    // The published tally, which the teller will recompute for itself.
    let honest = cluster
        .client
        .post(format!("{tt}/decrypt/tally"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("tally decryption");
    assert!(
        honest.status().is_success(),
        "the teller decrypts the board's own tally"
    );
    let honest: serde_json::Value = honest.json().await.expect("json");

    // The same call carrying a ciphertext of the caller's choosing: it must
    // make NO difference, because the teller never looks at it.
    let planted = cluster
        .client
        .post(format!("{tt}/decrypt/tally"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "enc_tally": {"l1": [], "l2": []} }))
        .send()
        .await
        .expect("planted tally decryption");
    assert!(planted.status().is_success());
    let planted: serde_json::Value = planted.json().await.expect("json");
    // The proofs carry a fresh nonce per call, so compare what was actually
    // decrypted: the ciphertext it was taken from and the share of it.
    let decrypted = |answer: &serde_json::Value| -> Vec<(String, String)> {
        answer["l1"]
            .as_array()
            .expect("l1")
            .iter()
            .map(|partial| {
                (
                    partial["proof"]["ciphertext"].as_str().unwrap().to_string(),
                    partial["decryption_share"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    assert_eq!(
        decrypted(&honest),
        decrypted(&planted),
        "a ciphertext in the request must change nothing: the teller decrypts \
         what the board adds up to"
    );
    assert!(!decrypted(&honest).is_empty());
}

/// Sec. 3.6.1 lists what the app stores encrypted and no ballot is among
/// them; Sec. 3.7.4 step 8 has a new device "proceed as in the PIN re-sending
/// procedure", inheriting nothing else. So only the device that BUILT a
/// ballot holds the randomness that opens it, and it pinned one of each pair
/// before anything left (Sec. 3.8.4 steps 10-11). Two devices therefore
/// cannot open the two different slots of one ballot - which together are
/// `sum - code`, the vote, on a board that cannot take a leaf back.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovered_device_cannot_open_a_ballot_it_did_not_build() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;
    let vote = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = vote["digest"].as_str().expect("digest").to_string();

    // A second device, set up from the roll's blob while the ballot is cast
    // but not yet confirmed.
    let second = cluster.spawn_voter_server_as("voter-1", "racing").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let recovered = helpers::post_json(
        &cluster.client,
        &format!("{second}/api/device/recover"),
        serde_json::json!({
            "fiscal_id": "VOTER-001", "passphrase": cluster.passphrases[0]
        }),
    )
    .await;
    assert_eq!(recovered["pin_set"], true, "the credential is restored");

    // Both press Confirm at the same moment with OPPOSITE selections.
    let confirm = |base: String, l1: &'static str, l2: &'static str| {
        let client = cluster.client.clone();
        let passphrase = cluster.passphrases[0].clone();
        let digest = digest.clone();
        async move {
            client
                .post(format!("{base}/api/confirm"))
                .json(&serde_json::json!({
                    "passphrase": passphrase, "pin": pin, "digest": digest,
                    "l1": l1, "l2": l2
                }))
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0)
        }
    };
    let (a, b) = tokio::join!(
        confirm(cluster.voter_urls[0].clone(), "code", "sum"),
        confirm(second.clone(), "sum", "code"),
    );

    // The recovered device has no ballot to disclose, so the board carries
    // ONE selection whatever the timing.
    let opened = openings_on_board(&cluster, &digest).await;
    let slots: std::collections::BTreeSet<String> = opened
        .values()
        .flatten()
        .map(|o| {
            let pick = |v: &serde_json::Value| {
                v.as_object()
                    .and_then(|m| m.keys().next().cloned())
                    .unwrap_or_default()
            };
            format!("{}/{}", pick(&o["l1"]), pick(&o["l2"]))
        })
        .collect();
    assert!(
        slots.len() <= 1,
        "two openings of one ballot ({slots:?}); answers were {a} and {b}"
    );
}

/// Sec. 3.8.4 step 15 has the WBB PUBLISH divergent data, not suppress it, so
/// no authority may refuse another's confirmation - a board that did would
/// hand whoever wrote first a VETO over every honest box, and one dishonest
/// box (A9 allows one) could make any ballot disappear.
///
/// A BOX can tell the difference, because it holds the ballot: it opens every
/// disclosure already published for that ballot and refuses only one that
/// VALIDLY opens the other slots. A plant that does not open is ignored, and
/// vetoes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_planted_confirmation_cannot_veto_an_honest_one() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    let other = cluster.pin(1).await;
    cluster.open_voting().await;
    let vote = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = vote["digest"].as_str().expect("digest").to_string();

    // A compromised box plants a confirmation for that ballot, naming the
    // OTHER slots, before the voter confirms. It does not open the ballot.
    let planted = serde_json::json!({
        "digest": digest,
        "bb_id": 1,
        "disclosure": {"l1": "sum", "l2": "code", "rnd_l1": "A".repeat(43), "rnd_l2": "A".repeat(43)},
        "opened": {"l1": {"Sum": 7}, "l2": {"Code": 9}},
        "confirmed_at_ms": 1,
    });
    let data = format!(
        "voting,BB,cast_intended_proof,1,{}",
        B64.encode(serde_json::to_string(&planted).unwrap())
    );
    let entry = referendum_poc::clients::wbb::sign_entry(
        data.as_bytes(),
        "BB-1",
        cluster.base.clock.base_ms as i64 + 900,
        &cluster.signing_key("bb-1"),
    );
    let _ = cluster
        .wbb
        .client
        .submit_and_wait(&entry, std::time::Duration::from_secs(20))
        .await;

    // The voter confirms as usual, and their ballot is counted.
    let confirm = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
                "l1": "code", "l2": "sum",
            }),
        )
        .await;
    assert!(
        confirm["confirmed_at_ms"].as_u64().unwrap_or_default() > 0,
        "a plant must not stop an honest confirmation: {confirm}"
    );
    cluster.vote_and_cast(1, "approve", other).await;
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.no, outcome.counts.si),
        (1, 1),
        "the planted confirmation must not cost the voter their ballot"
    );
}

/// Sec. 5.2 fixes the PIN at five digits and says plainly what that costs:
/// "a short PIN may be brute-forced: a coercer briefly in control of a
/// voter's device could try multiple PINs, succeeding with non-negligible
/// probability, then deprive the voter of the device. A RATE-LIMITING MEASURE
/// ON BALLOT CASTING is therefore advisable."
///
/// So the thesis accepts that the local screens tell a coercer holding the
/// device and the passphrase which PIN is valid - Sec. 3.7.1 has the voter
/// check theirs "as many times as wanted" - and puts the limit where it can
/// be enforced against what the coercer can DO. This checks that limit bites,
/// and that local verification stays unlimited.
#[tokio::test(flavor = "multi_thread")]
async fn casting_is_rate_limited_and_local_checks_are_not() {
    let mut cluster = ElectionCluster::start(
        1,
        ElectionOpts {
            max_casts_per_voter: Some(2),
            ..ElectionOpts::default()
        },
    )
    .await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;

    // Sec. 3.7.1: the voter checks their PIN as often as they like.
    for _ in 0..120 {
        let checked = cluster
            .voter_post(
                0,
                "/api/pin/verify",
                serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
            )
            .await;
        assert_eq!(checked["valid"], true, "PIN verification is unlimited");
    }

    // Sec. 5.2: what the roll DOES limit is casting.
    cluster.open_voting().await;
    for _ in 0..2 {
        cluster.vote(0, "reject", pin).await;
        cluster.cast(0, pin).await;
    }
    cluster.vote(0, "approve", pin).await;
    let refused = cluster
        .client
        .post(format!("{}/api/cast", cluster.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }))
        .send()
        .await
        .expect("cast beyond the budget");
    assert_eq!(
        refused.status().as_u16(),
        403,
        "the roll limits how many different ballots a voter may cast"
    );
}

/// Sec. 3.9 steps 15-17: a registration teller's credential-control share is
/// held to the key share PUBLISHED for it, and the parties' shares must
/// interpolate to `pk_RT`. A teller that states a share it never held is
/// NAMED, and any t_RT good ones finish the step - one teller must not be
/// able to stop a tally an honest subset can complete (Sec. 6.3.1 A2).
#[tokio::test(flavor = "multi_thread")]
async fn one_teller_cannot_stop_the_credential_controls() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // rt-1 states another party's control key share: self-consistent, but not
    // the one published for it.
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[0]))
        .expect("rt url");
    let stand_in = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        std::sync::Arc::new(|path: &str, _req: &[u8], status, body| {
            if !path.contains("controls/round1") || !status.is_success() {
                return (status, body);
            }
            let Ok(mut broadcast) = serde_json::from_slice::<serde_json::Value>(&body) else {
                return (status, body);
            };
            // A point that is not this party's published share.
            broadcast["pk_rt_i"] = serde_json::json!("A".repeat(43));
            let raw = serde_json::to_vec(&broadcast).unwrap_or_else(|_| body.to_vec());
            (status, axum::body::Bytes::from(raw))
        }),
        None,
    )
    .await;

    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let outcome = cluster
        .try_tally_with_rts(vec![
            stand_in,
            url(&cluster.ports.rt[1]),
            url(&cluster.ports.rt[2]),
        ])
        .await
        .expect("the honest tellers finish the step without rt-1");
    assert_eq!((outcome.counts.si, outcome.counts.no), (1, 1));
}

/// Sec. 3.9 steps 15-17: the credential controls run in TWO rounds, and a
/// teller that answers the first and then drops out of the second must be set
/// aside like any other - the step is run again over those that remain. A
/// round-2 answer is a response over the nonces of the round 1 it was built
/// on, so the tellers that did answer start again from round 1 (Sec. 6.3.1
/// A2).
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_that_drops_out_of_the_second_control_round_denies_nobody() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // rt-1 answers the first round honestly and then goes silent on the
    // second - the round the earlier drop-out test never reaches.
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[0]))
        .expect("rt url");
    let stand_in = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _req: &[u8]| {
            path.contains("controls/round2").then(|| {
                (
                    reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::body::Bytes::from_static(b"{}"),
                )
            })
        })),
    )
    .await;

    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let outcome = cluster
        .try_tally_with_rts(vec![
            stand_in,
            url(&cluster.ports.rt[1]),
            url(&cluster.ports.rt[2]),
        ])
        .await
        .expect("the honest tellers finish the second round without rt-1");
    assert_eq!((outcome.counts.si, outcome.counts.no), (1, 1));
}

/// Sec. 3.7.1 step 3 recovers the credential only "after V has typed in PIN":
/// the passphrase unlocks the app, it does not answer for a ballot. Without
/// this the coercer of Sec. 6.3.2 - who by A1 may hold the passphrase - reads
/// `sum - code`, the vote, off a voter who armed no decoy, and confirms the
/// ballot in their place.
#[tokio::test(flavor = "multi_thread")]
async fn the_passphrase_alone_reaches_no_ballot() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;
    let cast = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = cast["digest"].as_str().expect("digest").to_string();

    // No decoy is armed: this is the voter who has not been coerced yet.
    for path in ["/api/cai/values", "/api/ballot/status"] {
        let response = cluster
            .client
            .post(format!("{}{path}", cluster.voter_urls[0]))
            .json(&serde_json::json!({ "passphrase": cluster.passphrases[0] }))
            .send()
            .await
            .expect("request");
        assert_eq!(
            response.status(),
            400,
            "{path} answered without a PIN: {}",
            response.text().await.unwrap_or_default()
        );
    }
    let response = cluster
        .client
        .post(format!("{}/api/confirm", cluster.voter_urls[0]))
        .json(&serde_json::json!({
            "passphrase": cluster.passphrases[0], "digest": digest,
            "l1": "code", "l2": "sum",
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        response.status(),
        400,
        "a ballot was confirmed without a PIN"
    );

    // And the voter's own PIN still reaches their ballot.
    let values = cluster
        .voter_post(
            0,
            "/api/cai/values",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    assert!(values["l1_code"].is_number());
}

/// Sec. 3.7.3 step 5 builds the decoy credential for `x^ruse = x + PIN^ruse -
/// PIN^valid`, and Sec. 3.7.1 step 3 recovers `x` only once the voter has
/// typed their PIN: arming a decoy is the VOTER's request. A coercer who
/// armed one with the passphrase alone would leave the voter's own PIN no
/// longer verifying - Sec. 3.7.3 says so - and every ballot they cast
/// afterwards discarded at tally, with nothing on any screen to show it.
#[tokio::test(flavor = "multi_thread")]
async fn arming_a_decoy_needs_the_pin_in_force() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;

    let ruse = |body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{}/api/pin/ruse", cluster.voter_urls[0]);
        async move { client.post(url).json(&body).send().await.expect("request") }
    };

    let no_pin = ruse(serde_json::json!({ "passphrase": cluster.passphrases[0] })).await;
    assert!(
        no_pin.status().is_client_error(),
        "a decoy was armed with the passphrase alone"
    );

    let wrong = (pin + 1) % 100_000;
    let bad = ruse(serde_json::json!({
        "passphrase": cluster.passphrases[0], "pin": wrong,
    }))
    .await;
    assert_eq!(bad.status(), 400, "a decoy was armed on a wrong PIN");

    // The voter's own PIN arms one, and the decoy they chose is the decoy.
    let armed = cluster
        .voter_post(
            0,
            "/api/pin/ruse",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "ruse_pin": 12345,
            }),
        )
        .await;
    assert_eq!(armed["ruse_pin"], 12345);
}

/// Sec. 3.8.4 steps 9-11: the voter checks the sums of ONE ballot and then
/// chooses which of its values is opened. A confirmation that names another
/// ballot opens a value of a ballot nobody checked.
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmation_names_the_ballot_whose_values_were_checked() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;

    let cast = cluster.vote_and_cast_unconfirmed(0, "approve", pin).await;
    let cast_digest = cast["digest"].as_str().expect("digest").to_string();
    // A second ballot is built and NOT cast: the screens are about the cast
    // one, and this one cannot be confirmed yet.
    let built = cluster.vote(0, "reject", pin).await;
    let built_digest = built["digest"].as_str().expect("digest").to_string();
    assert_ne!(built_digest, cast_digest);

    let confirm = |digest: String| {
        let client = cluster.client.clone();
        let url = format!("{}/api/confirm", cluster.voter_urls[0]);
        let passphrase = cluster.passphrases[0].clone();
        async move {
            client
                .post(url)
                .json(&serde_json::json!({
                    "passphrase": passphrase, "pin": pin, "digest": digest,
                    "l1": "code", "l2": "sum",
                }))
                .send()
                .await
                .expect("request")
        }
    };

    // The uncast ballot is refused, and the refusal names it.
    let uncast = confirm(built_digest.clone()).await;
    assert_eq!(uncast.status(), 409, "an uncast ballot was confirmed");
    let body = uncast.text().await.unwrap_or_default();
    assert!(
        body.contains(&built_digest),
        "the refusal must name the ballot: {body}"
    );
    // A ballot nobody has is refused.
    let nobody = confirm("A".repeat(43)).await;
    assert!(
        nobody.status().is_client_error(),
        "a ballot nobody has was confirmed"
    );
    // A confirmation that names no ballot is refused: the app does not guess
    // which ballot the voter checked.
    let unnamed = cluster
        .client
        .post(format!("{}/api/confirm", cluster.voter_urls[0]))
        .json(&serde_json::json!({
            "passphrase": cluster.passphrases[0], "pin": pin, "l1": "code", "l2": "sum",
        }))
        .send()
        .await
        .expect("request");
    assert!(
        unnamed.status().is_client_error(),
        "a confirmation without a ballot went through"
    );
    // Naming the cast ballot confirms it.
    let ok = confirm(cast_digest).await;
    assert_eq!(ok.status(), 200, "{}", ok.text().await.unwrap_or_default());
}

/// Sec. 3.8.4 steps 10-14: the two openings of one level are `sum - code`,
/// the vote, so a device opens ONE of each pair and the unused openings are
/// destroyed before anything is sent. A handler that read the device's state
/// before the confirmation and saved it back afterwards - a PIN re-send waits
/// seconds for the tellers - must not put the confirmed ballot, with both of
/// its openings, back within reach.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_screen_cannot_bring_back_a_confirmed_ballot() {
    let mut cluster = ElectionCluster::start(
        1,
        ElectionOpts {
            wall_clock_tau: Some((3, 4)),
            ..ElectionOpts::default()
        },
    )
    .await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;
    let vote = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = vote["digest"].as_str().expect("digest").to_string();

    // A PIN re-send reads the session, then waits for the tellers' waiting
    // period before writing it back.
    let resend = {
        let client = cluster.client.clone();
        let url = format!("{}/api/pin/resend", cluster.voter_urls[0]);
        let passphrase = cluster.passphrases[0].clone();
        tokio::spawn(async move {
            client
                .post(url)
                .json(&serde_json::json!({ "passphrase": passphrase }))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The voter confirms while it is in flight.
    let first = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
                "l1": "code", "l2": "code",
            }),
        )
        .await;
    assert_eq!(first["l1"], "code");
    let _ = resend.await;

    let again = cluster
        .client
        .post(format!("{}/api/confirm", cluster.voter_urls[0]))
        .json(&serde_json::json!({
            "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
            "l1": "sum", "l2": "sum",
        }))
        .send()
        .await
        .expect("second confirmation");
    let status = again.status();
    assert!(
        status.is_client_error(),
        "the other opening was still reachable: {status} {}",
        again.text().await.unwrap_or_default()
    );

    for (bb_id, values) in &openings_on_board(&cluster, &digest).await {
        assert_eq!(
            values.len(),
            1,
            "BB-{bb_id} published {} openings for one ballot",
            values.len()
        );
    }
}

/// Sec. 3.9 step 16: "the RTs consider only shares with valid NIZKPs" is a
/// judgement over what a party SENDS, not only over whether it answers. A
/// registration teller that answers the second control round with the wrong
/// scalars, and then refuses to co-sign the entry the step publishes, must be
/// named and set aside like any other - t_RT tellers are entitled to finish
/// the step, and one that lies must not deny the election (Sec. 6.3.1 A2).
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_that_lies_in_the_second_control_round_denies_nobody() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[0]))
        .expect("rt url");
    let stand_in = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        std::sync::Arc::new(|path: &str, _req: &[u8], status, body| {
            if !path.contains("controls/round2") || !status.is_success() {
                return (status, body);
            }
            // The same shape, the same encoding, the wrong scalars.
            let Ok(mut response) = serde_json::from_slice::<serde_json::Value>(&body) else {
                return (status, body);
            };
            if let Some(values) = response["z_values"].as_array().cloned() {
                response["z_values"] =
                    serde_json::Value::Array(values.into_iter().rev().collect::<Vec<_>>());
            }
            let raw = serde_json::to_vec(&response).unwrap_or_else(|_| body.to_vec());
            (status, axum::body::Bytes::from(raw))
        }),
        // ... and it will not co-sign what the step publishes either.
        Some(std::sync::Arc::new(|path: &str, _req: &[u8]| {
            path.ends_with("sign").then(|| {
                (
                    reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::body::Bytes::from_static(b"{}"),
                )
            })
        })),
    )
    .await;

    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let outcome = cluster
        .try_tally_with_rts(vec![
            stand_in,
            url(&cluster.ports.rt[1]),
            url(&cluster.ports.rt[2]),
        ])
        .await
        .expect("the honest tellers finish the step without rt-1");
    assert_eq!((outcome.counts.si, outcome.counts.no), (1, 1));
}

/// Sec. 3.8.4 steps 7-17 are a sequence the voter is in the middle of once a
/// ballot is cast: the board carries its digest, Sec. 3.8.5 has the voter look
/// it up, and Sec. 3.9 step 2 discards it unless a disclosure arrives. A
/// second `/api/vote` must therefore not take the screens away from it - a
/// stranded ballot looks on the board exactly like a voter who chose not to
/// confirm, so nothing would ever show the loss.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_vote_does_not_strand_the_ballot_already_cast() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;

    let cast = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = cast["digest"].as_str().expect("digest").to_string();

    // The voter changes their mind and builds another ballot.
    let again = cluster
        .voter_post(
            0,
            "/api/vote",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "option": "approve", "pin": pin,
            }),
        )
        .await;
    assert_ne!(again["digest"].as_str(), Some(digest.as_str()));
    assert_eq!(
        again["awaiting_confirmation"].as_str(),
        Some(digest.as_str()),
        "the app must say the cast ballot is still waiting: {again}"
    );

    // The confirmation screens still answer for the ballot that was CAST.
    let values = cluster
        .voter_post(
            0,
            "/api/cai/values",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    assert_eq!(values["digest"].as_str(), Some(digest.as_str()));
    let confirmed = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
                "l1": "code", "l2": "sum",
            }),
        )
        .await;
    assert_eq!(confirmed["digest"].as_str(), Some(digest.as_str()));
    assert_eq!(confirmed["will_be_counted"], true);

    let other = cluster.pin(1).await;
    cluster.vote_and_cast(1, "blank", other).await;
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (0, 1),
        "the cast ballot is the one that counts"
    );
}

/// Sec. 3.6.1 lists what the app saves, and a ballot is not among it: a
/// device recovery brings back the CREDENTIAL. Running one on a device that
/// is in the middle of casting must therefore take nothing away either - the
/// recovery needs only the passphrase, so a coercer who runs it must not be
/// able to destroy a ballot the voter has already cast.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovery_on_a_live_device_takes_no_ballot_away() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;
    let cast = cluster.vote_and_cast_unconfirmed(0, "reject", pin).await;
    let digest = cast["digest"].as_str().expect("digest").to_string();

    // The passphrase alone, on the device that is holding the ballot.
    let recovered = cluster
        .voter_post(
            0,
            "/api/device/recover",
            serde_json::json!({
                "fiscal_id": "VOTER-001", "passphrase": cluster.passphrases[0],
            }),
        )
        .await;
    assert_eq!(recovered["pin_set"], true);

    let confirmed = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin, "digest": digest,
                "l1": "sum", "l2": "sum",
            }),
        )
        .await;
    assert_eq!(confirmed["digest"].as_str(), Some(digest.as_str()));
    assert_eq!(confirmed["will_be_counted"], true);
}

/// Sec. 3.8.4 step 17: the app is the voter's account of what happened, and
/// the voter is the only party who can act in time (Sec. 3.9 step 10: the last
/// confirmed ballot counts). A box that REFUSES a confirmation publishes
/// nothing, and no retry changes that - so the refusal has to reach the voter
/// even when another box published (A9 allows one dishonest box).
#[tokio::test(flavor = "multi_thread")]
async fn a_box_that_refuses_a_confirmation_is_named_to_the_voter() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0]))
        .expect("bb url");
    let refusing = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _body: &[u8]| {
            path.ends_with("cai").then(|| {
                (
                    reqwest::StatusCode::BAD_REQUEST,
                    axum::body::Bytes::from_static(b"CAI disclosure does not verify"),
                )
            })
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", refusing.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let pin = pin["pin"].as_u64().expect("pin");
    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    let confirm = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/confirm"),
        serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": vote["digest"],
            "l1": "code", "l2": "sum",
        }),
    )
    .await;

    assert_eq!(
        confirm["will_be_counted"], true,
        "the honest box still counts the ballot: {confirm}"
    );
    let refused = confirm["refused_boxes"].as_array().expect("refused_boxes");
    assert_eq!(
        refused.len(),
        1,
        "the box that refused must be named: {confirm}"
    );
    assert_eq!(refused[0]["bb_id"], 1);
    assert!(
        refused[0]["reason"]
            .as_str()
            .is_some_and(|why| why.contains("does not verify")),
        "and what it said must be reported: {confirm}"
    );
}

/// Sec. 3.8.4 steps 10-14: the two openings of one level are the vote, so a
/// confirmation is one-way. A handler holds its copy of the device state
/// across a network round trip - `/api/cast` talks to the roll and to every
/// box - and what it writes back must not undo a confirmation that happened
/// meanwhile, or the device builds the OTHER opening and sends it.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_cast_cannot_undo_a_confirmation() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;
    cluster.open_voting().await;

    // bb-1 is reached through a stand-in that stalls the cast, so the cast
    // handler is still holding its copy when the confirmation lands.
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0]))
        .expect("bb url");
    let slow = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _body: &[u8]| {
            if !path.ends_with("ballots") {
                return None;
            }
            // Off the runtime's worker: a plain sleep would stall the test's own
            // timers and requests with it.
            tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(2500)));
            None
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", slow.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .unwrap_or(pin);

    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let digest = vote["digest"].as_str().expect("digest").to_string();
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;

    // A second cast of the same ballot is in flight, stalled at bb-1 ...
    let casting = {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/cast");
        let passphrase = passphrase.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;

    // ... while the voter confirms.
    let confirmed = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/confirm"),
        serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": digest,
            "l1": "code", "l2": "code",
        }),
    )
    .await;
    assert_eq!(confirmed["digest"].as_str(), Some(digest.as_str()));
    let _ = casting.await;

    // The confirmed ballot is gone from the device, with both openings.
    let again = cluster
        .client
        .post(format!("{voter}/api/cai/values"))
        .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
        .send()
        .await
        .expect("values");
    assert!(
        again.status().is_client_error(),
        "the confirmed ballot came back: {} {}",
        again.status(),
        again.text().await.unwrap_or_default()
    );
    let other = cluster
        .client
        .post(format!("{voter}/api/confirm"))
        .json(&serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": digest,
            "l1": "sum", "l2": "sum",
        }))
        .send()
        .await
        .expect("second confirmation");
    assert!(
        other.status().is_client_error(),
        "the other opening was still reachable: {} {}",
        other.status(),
        other.text().await.unwrap_or_default()
    );
    for (bb_id, values) in &openings_on_board(&cluster, &digest).await {
        assert_eq!(
            values.len(),
            1,
            "BB-{bb_id} published {} openings for one ballot",
            values.len()
        );
    }
}

/// Sec. 3.6.3 footnote 9: "PIN = PIN^ruse if this originates from a ruse PIN
/// request ..., or PIN = PIN^valid if this originates from a pin re-sending
/// request". A re-send delivers the voter's OWN PIN - otherwise a voter whose
/// decoy was armed by somebody else has no way back to it, and the ballot
/// they cast on what the app handed them is discarded at tally.
#[tokio::test(flavor = "multi_thread")]
async fn a_re_send_delivers_the_voters_own_pin() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;

    // Somebody else arms a decoy with the PIN in force.
    let decoy = cluster.ruse_pin(0, pin).await;
    assert_ne!(decoy, pin);

    let resent = cluster
        .voter_post(
            0,
            "/api/pin/resend",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    assert_eq!(
        resent["pin"].as_u64(),
        Some(pin),
        "a re-send must deliver the valid PIN, not the decoy: {resent}"
    );

    // And the PIN it delivered casts a ballot that counts.
    cluster.open_voting().await;
    cluster
        .vote_and_cast(0, "reject", resent["pin"].as_u64().expect("pin"))
        .await;
    let other = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", other).await;
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (1, 1),
        "the re-delivered PIN must still cast a counted ballot"
    );
}

/// Sec. 3.8.4 steps 7-17 are one sequence per ballot. A vote of the same PIN
/// while that ballot's cast is still IN FLIGHT must not take the ballot's
/// openings away: the cast finishes, the board carries the digest, and the
/// ballot must still be confirmable from this device.
#[tokio::test(flavor = "multi_thread")]
async fn a_vote_during_a_slow_cast_does_not_strand_the_ballot_being_cast() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0]))
        .expect("bb url");
    let slow = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _body: &[u8]| {
            if path.ends_with("ballots") {
                // Off the runtime's worker: a plain sleep would stall the test's own
                // timers and requests with it.
                tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(2500)));
            }
            None
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", slow.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    let post = |path: &str, body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{voter}{path}");
        async move { client.post(url).json(&body).send().await.expect("request") }
    };

    let x = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let x_digest = x["digest"].as_str().expect("digest").to_string();
    let casting = tokio::spawn(post(
        "/api/cast",
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    ));
    tokio::time::sleep(Duration::from_millis(400)).await;
    // A second ballot, while the first is still being cast.
    let y = post(
        "/api/vote",
        serde_json::json!({ "passphrase": passphrase, "option": "approve", "pin": pin }),
    )
    .await;
    assert_eq!(y.status(), 200, "{}", y.text().await.unwrap_or_default());
    let cast = casting.await.expect("join");
    assert_eq!(cast.status(), 200, "the cast of X finishes");

    // X is on the board and still confirmable from this device.
    let values = post(
        "/api/cai/values",
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": x_digest }),
    )
    .await;
    assert_eq!(
        values.status(),
        200,
        "the ballot being cast was stranded: {}",
        values.text().await.unwrap_or_default()
    );
    let confirmed = post(
        "/api/confirm",
        serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": x_digest,
            "l1": "code", "l2": "sum",
        }),
    )
    .await;
    assert_eq!(
        confirmed.status(),
        200,
        "{}",
        confirmed.text().await.unwrap_or_default()
    );
}

/// Sec. 3.7.5: a revoked identifier is finished. A cast still in flight when
/// the voter revokes must not write the revoked session back under the old
/// identifier - two state files under one passphrase would leave the file
/// system to decide which credential the voter is on.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_during_a_slow_cast_leaves_one_session() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0]))
        .expect("bb url");
    let slow = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _body: &[u8]| {
            if path.ends_with("ballots") {
                // Off the runtime's worker: a plain sleep would stall the test's own
                // timers and requests with it.
                tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(2500)));
            }
            None
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", slow.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    let post = |path: &str, body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{voter}{path}");
        async move { helpers::post_json(&client, &url, body).await }
    };
    let old_vid = post(
        "/api/status",
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["vid"]
        .as_u64()
        .expect("vid");

    post(
        "/api/vote",
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let casting = {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/cast");
        let passphrase = passphrase.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let revoked = post(
        "/api/revoke",
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let new_vid = revoked["vid"].as_u64().expect("new vid");
    assert_ne!(new_vid, old_vid);
    let _ = casting.await;

    // Every later read resolves to the NEW identifier, and the revoked
    // credential's PIN is gone from the device.
    for _ in 0..6 {
        let status = post(
            "/api/status",
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await;
        assert_eq!(status["vid"].as_u64(), Some(new_vid), "{status}");
    }
    let old_pin = cluster
        .client
        .post(format!("{voter}/api/pin"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await
        .expect("request");
    assert!(
        old_pin.status().is_client_error(),
        "the revoked credential's PIN came back: {}",
        old_pin.text().await.unwrap_or_default()
    );
}

/// Sec. 3.7.5: a revocation is one step at the roll and a new registration
/// after it, and the system can afford `n_ACC - n_V` of them. A service that
/// is briefly down during the PIN request that follows must not leave the
/// voter with a revoked credential, no device record on the new identifier
/// and a screen saying "revocation failed" - the one retry that suggests
/// spends a spare. The device is registered BEFORE the PIN request, and the
/// error says what happened and what to do.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_whose_pin_request_fails_leaves_the_device_registered() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    // The notification service fails registrations while the flag is up.
    let failing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.ns)).expect("ns url");
    let stand_in = {
        let failing = failing.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (path.ends_with("register") && failing.load(std::sync::atomic::Ordering::SeqCst))
                    .then(|| {
                        (
                            reqwest::StatusCode::SERVICE_UNAVAILABLE,
                            axum::body::Bytes::from_static(b"{}"),
                        )
                    })
            })),
        )
        .await
    };
    let voter = cluster.spawn_voter_with_ns(stand_in.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;

    failing.store(true, std::sync::atomic::Ordering::SeqCst);
    let revoke = cluster
        .client
        .post(format!("{voter}/api/revoke"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await
        .expect("request");
    let status = revoke.status();
    let body = revoke.text().await.unwrap_or_default();
    failing.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        !status.is_success() && body.contains("revoked") && body.contains("Re-send"),
        "the error must say the revocation took effect and what to do: {status} {body}"
    );

    // The voter follows the message: a re-send delivers the new PIN, and the
    // device - registered on the new identifier - casts a counted ballot.
    let resent = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/resend"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let new_pin = resent["pin"].as_u64().expect("new pin");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": new_pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": new_pin }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().map(|r| r.len()),
        Some(2),
        "the device on the new identifier must be able to cast: {cast}"
    );
}

/// Sec. 3.7.5 counts `n_ACC - n_V` revocations. The roll moves the device's
/// record onto the new identifier IN the revocation itself, so the second
/// request the device sends afterwards (re-stating its key, seeding the blob)
/// can be lost without leaving a voter who can retrieve a PIN and never cast.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_whose_device_registration_fails_still_casts() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    // The roll is reached through a stand-in that refuses device
    // registrations while the flag is up.
    let failing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let stand_in = {
        let failing = failing.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (path.ends_with("devices") && failing.load(std::sync::atomic::Ordering::SeqCst))
                    .then(|| {
                        (
                            reqwest::StatusCode::SERVICE_UNAVAILABLE,
                            axum::body::Bytes::from_static(b"{}"),
                        )
                    })
            })),
        )
        .await
    };
    let voter = cluster.spawn_voter_with_er(stand_in.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;

    failing.store(true, std::sync::atomic::Ordering::SeqCst);
    let revoked = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    failing.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        revoked["vid"].as_u64().is_some(),
        "the revocation itself succeeds: {revoked}"
    );

    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let new_pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("new pin");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": new_pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": new_pin }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().map(|r| r.len()),
        Some(2),
        "the device on the new identifier must be able to cast: {cast}"
    );
}

/// Sec. 3.6.1 steps 5-9 are one procedure, and once the roll holds the
/// device's app key only that device can ever sign a rebind of it (Sec. 3.7.4
/// step 7). A PIN request or a blob upload lost after that point must cost
/// the voter a retry, not the election: the passphrase is handed over, the
/// status screen says no request is open, and a re-send asks again.
#[tokio::test(flavor = "multi_thread")]
async fn an_enrollment_whose_last_requests_fail_still_hands_over_the_passphrase() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    let failing = std::sync::Arc::new(AtomicBool::new(true));
    let refuse = |suffix: &'static str, failing: std::sync::Arc<AtomicBool>| {
        std::sync::Arc::new(move |path: &str, _body: &[u8]| {
            (path.ends_with(suffix) && failing.load(Ordering::SeqCst)).then(|| {
                (
                    reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    axum::body::Bytes::from_static(b"{}"),
                )
            })
        })
    };
    let ns_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.ns)).expect("ns url");
    let ns = helpers::spawn_stand_in(
        &ns_real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(refuse("register", failing.clone())),
    )
    .await;
    let er_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = helpers::spawn_stand_in(
        &er_real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(refuse("devices/blob", failing.clone())),
    )
    .await;
    let voter = cluster
        .spawn_voter_with(Some(er.as_ref()), Some(ns.as_ref()), &[])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    let enrolled = cluster
        .client
        .post(format!("{voter}/api/enroll"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-001" }))
        .send()
        .await
        .expect("request");
    let status = enrolled.status();
    let enrolled: serde_json::Value = enrolled.json().await.expect("json");
    assert!(
        status.is_success(),
        "a lost PIN request must not keep the passphrase from the voter: {status} {enrolled}"
    );
    let passphrase = enrolled["passphrase"]
        .as_str()
        .expect("passphrase")
        .to_string();
    // The rest of the enrollment runs in the background: wait for it to
    // fail, with the services still failing, before they recover.
    helpers::wait_enrollment_settled(&cluster.client, &voter, &passphrase).await;
    failing.store(false, Ordering::SeqCst);

    let state = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/status"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(state["pin_request_open"], false, "{state}");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/resend"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().map(|r| r.len()),
        Some(2),
        "{cast}"
    );
}

/// Sec. 6.3.1 A9: one slow or dishonest ballot box costs only the voter whose
/// confirmation it stalls. Two voters on one app server: a confirmation held
/// at a box for one of them must not hold the other's.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_confirmation_holds_no_other_voter() {
    // Both voters enroll on ONE app server, and nowhere else.
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;

    let slow_digest: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let stalls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0]))
        .expect("bb url");
    let slow = {
        let slow_digest = slow_digest.clone();
        let stalls = stalls.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                let wanted = slow_digest.lock().unwrap().clone();
                if path.ends_with("cai") {
                    if let Some(digest) = wanted {
                        if String::from_utf8_lossy(body).contains(&digest) {
                            stalls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            // Off the runtime's worker: a plain sleep here
                            // would stall the test's own timers with it.
                            tokio::task::block_in_place(|| {
                                std::thread::sleep(Duration::from_millis(3000))
                            });
                        }
                    }
                }
                None
            })),
        )
        .await
    };
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", slow.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut passphrases = Vec::new();
    for fiscal_id in ["VOTER-001", "VOTER-002"] {
        passphrases.push(helpers::enroll_on(&cluster.client, &voter, fiscal_id).await);
    }
    cluster.open_voting().await;
    let mut ballots = Vec::new();
    for passphrase in passphrases {
        let pin = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/pin"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await["pin"]
            .as_u64()
            .expect("pin");
        let vote = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/vote"),
            serde_json::json!({ "passphrase": passphrase, "option": "approve", "pin": pin }),
        )
        .await;
        helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/cast"),
            serde_json::json!({ "passphrase": passphrase, "pin": pin }),
        )
        .await;
        let digest = vote["digest"].as_str().expect("digest").to_string();
        ballots.push((passphrase, pin, digest));
    }
    *slow_digest.lock().unwrap() = Some(ballots[0].2.clone());

    let confirm = |i: usize| {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/confirm");
        let (passphrase, pin, digest) = ballots[i].clone();
        async move {
            let started = tokio::time::Instant::now();
            let response = client
                .post(url)
                .json(&serde_json::json!({
                    "passphrase": passphrase, "pin": pin, "digest": digest,
                    "l1": "code", "l2": "sum",
                }))
                .send()
                .await
                .expect("request");
            (response.status(), started.elapsed())
        }
    };
    let stalled = tokio::spawn(confirm(0));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (status, took) = confirm(1).await;
    assert!(
        stalls.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the first confirmation was never stalled"
    );
    assert!(status.is_success(), "{status}");
    assert!(
        took < Duration::from_millis(1500),
        "the second voter waited {took:?} behind the first voter's stalled confirmation"
    );
    let (status, _) = stalled.await.expect("join");
    assert!(status.is_success(), "{status}");
}

/// Sec. 3.8.5 1(d): a box the app and the board page count among those that
/// accepted a ballot must hold it. Once the DIGEST is on the board over the
/// box's signature the ballot is accepted; a refused metadata entry after it
/// must not make the box drop the ballot.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_metadata_entry_does_not_drop_an_accepted_ballot() {
    use base64::Engine as _;
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin = cluster.pin(0).await;

    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, body: &[u8]| {
            if !path.ends_with("submit") {
                return None;
            }
            let entry: serde_json::Value = serde_json::from_slice(body).ok()?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(entry["data"].as_str()?)
                .ok()?;
            String::from_utf8_lossy(&data)
                .contains(",ballot_metadata,")
                .then(|| {
                    (
                        reqwest::StatusCode::FORBIDDEN,
                        axum::body::Bytes::from_static(b"refused"),
                    )
                })
        })),
    )
    .await;
    let bb1 = cluster
        .spawn_bb_with_board("bb-1", board.join("wbb/").unwrap().as_str())
        .await;
    let voter = cluster.spawn_voter_with_peers(&[("bb-1", bb1)]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .unwrap_or(pin);

    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(
        cast["refused_bb_ids"].as_array().map(|r| r.len()),
        Some(0),
        "the box whose digest is on the board accepted the ballot: {cast}"
    );
    let confirm = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/confirm"),
        serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": vote["digest"],
            "l1": "code", "l2": "sum",
        }),
    )
    .await;
    assert!(
        confirm["counting_bb_ids"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id == 1)),
        "the box that accepted the ballot holds it and opens it: {confirm}"
    );
}

/// Sec. 3.7.5: a revocation moves the device onto a NEW generation of its
/// session. A stale file of the revoked generation found beside it (a crash
/// between the two writes, a restored backup) never takes over and is
/// removed.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_session_file_never_takes_over_after_a_revocation() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let voter = cluster.spawn_voter_with_peers(&[]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let dir = cluster.voter_state_dir(&voter);
    let files = || {
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("state dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".dat"))
            .collect();
        names.sort();
        names
    };
    let before = files();
    assert_eq!(before.len(), 1, "{before:?}");
    let stale = std::fs::read(dir.join(&before[0])).expect("read session");

    let revoked = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let new_vid = revoked["vid"].as_u64().expect("vid");
    std::fs::write(dir.join(&before[0]), &stale).expect("plant the stale file");
    assert_eq!(files().len(), 2);

    let status = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/status"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(status["vid"].as_u64(), Some(new_vid), "{status}");
    let after = files();
    assert_eq!(
        after,
        vec![format!("voter-{new_vid}.dat")],
        "the stale file is removed"
    );
}

/// One writer per device (Sec. 3.7.2 step 4), keyed by what stays the same
/// across a revocation: a recovery in flight while the device revokes must
/// not write the revoked session back beside the new one.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovery_racing_a_revocation_writes_nothing_back() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let slow = std::sync::Arc::new(AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = {
        let slow = slow.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            // The roll ANSWERS late: the blob it returns was read before
            // the revocation, so only the lock and the generation rule keep
            // the recovery from writing the revoked session back. (Delaying
            // the REQUEST instead lets the roll read the new blob, and the
            // test passes whatever the device does.)
            std::sync::Arc::new(move |path: &str, _body: &[u8], status, body| {
                if path.ends_with("devices/recover") && slow.load(Ordering::SeqCst) {
                    tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(1500)));
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let voter = cluster.spawn_voter_with_er(er.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let dir = cluster.voter_state_dir(&voter);

    slow.store(true, Ordering::SeqCst);
    let recovering = {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/device/recover");
        let passphrase = passphrase.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .json(&serde_json::json!({ "fiscal_id": "VOTER-001", "passphrase": passphrase }))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    let revoked = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let new_vid = revoked["vid"].as_u64().expect("vid");
    let _ = recovering.await;
    slow.store(false, Ordering::SeqCst);

    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("state dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".dat"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![format!("voter-{new_vid}.dat")],
        "one session, the new one"
    );
}

/// Sec. 3.8.4 step 6: a box confirms a registration once it can confirm the
/// publication. A digest submission lost on the box-to-board channel leaves
/// the box holding the ballot and the voter told to cast again; casting
/// again must PUBLISH the digest, not replay a receipt for data the board
/// does not hold (Sec. 3.8.5 1(d): two boxes on the board).
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_digest_publication_is_published_by_the_cast_again() {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let drop_digest = std::sync::Arc::new(AtomicBool::new(false));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let drop_digest = drop_digest.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                if !path.ends_with("submit") || !drop_digest.load(Ordering::SeqCst) {
                    return None;
                }
                let entry: serde_json::Value = serde_json::from_slice(body).ok()?;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(entry["data"].as_str()?)
                    .ok()?;
                String::from_utf8_lossy(&data)
                    .contains(",ballot_digest,")
                    .then(|| {
                        (
                            reqwest::StatusCode::BAD_GATEWAY,
                            axum::body::Bytes::from_static(b"lost"),
                        )
                    })
            })),
        )
        .await
    };
    let bb1 = cluster
        .spawn_bb_with_board("bb-1", board.join("wbb/").unwrap().as_str())
        .await;
    let voter = cluster.spawn_voter_with_peers(&[("bb-1", bb1)]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    cluster.open_voting().await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let digest = vote["digest"].as_str().expect("digest").to_string();
    let cast = |label: &'static str| {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/cast");
        let passphrase = passphrase.clone();
        async move {
            let response = client
                .post(url)
                .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
                .send()
                .await
                .expect("request");
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            (label, body)
        }
    };
    drop_digest.store(true, Ordering::SeqCst);
    let first = cast("first").await;
    drop_digest.store(false, Ordering::SeqCst);
    let again = cast("again").await;
    let view = helpers::get_json(&cluster.client, &format!("{voter}/api/verify/{digest}")).await;
    let publishers: Vec<u64> = view["publications"]
        .as_array()
        .expect("publications")
        .iter()
        .filter_map(|p| p["bb_id"].as_u64())
        .collect();
    assert!(
        publishers.contains(&1),
        "casting again published nothing from BB-1: {publishers:?} ({first:?}, {again:?})"
    );
}

/// Sec. 3.9 step 5 / Sec. 3.10 1(e): invalid ballots are DISCARDED. A record
/// a dishonest box releases with a choice of another shape than the
/// election's - opened by a genuine disclosure it copied - must not stop the
/// tally.
#[tokio::test(flavor = "multi_thread")]
async fn a_released_record_of_another_shape_does_not_stop_the_tally() {
    use base64::Engine as _;
    fn shorten_l1(value: &mut serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                if map.contains_key("l2") {
                    if let Some(serde_json::Value::Array(items)) = map.get_mut("l1") {
                        if !items.is_empty() {
                            items.pop();
                            return true;
                        }
                    }
                }
                map.values_mut().any(shorten_l1)
            }
            serde_json::Value::Array(items) => items.iter_mut().any(shorten_l1),
            _ => false,
        }
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    let bb_token = std::fs::read_to_string(cluster.ceremony_dir().join("bb-1-service-token.txt"))
        .expect("token")
        .trim()
        .to_string();
    let released: serde_json::Value = cluster
        .client
        .get(format!("https://127.0.0.1:{}/ballots", cluster.ports.bb[0]))
        .header("Authorization", format!("Bearer {bb_token}"))
        .send()
        .await
        .expect("release")
        .json()
        .await
        .expect("json");
    let real = released[0].clone();
    let real_ballot: evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup> =
        serde_json::from_value(real["ballot"].clone()).expect("ballot");
    let real_digest = referendum_poc::protocol::voting::ballot_digest(&real_ballot).unwrap();
    let mut doctored = real.clone();
    assert!(shorten_l1(&mut doctored["ballot"]), "found l1");
    let doctored_ballot: evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup> =
        serde_json::from_value(doctored["ballot"].clone()).expect("still deserialises");
    let doctored_digest =
        referendum_poc::protocol::voting::ballot_digest(&doctored_ballot).unwrap();

    // BB-1's own entries for the real ballot, re-signed under the doctored digest.
    let entries = cluster.wbb.client.entries().await.expect("entries");
    let find = |kind: &str| {
        entries
            .entries
            .iter()
            .find_map(|sequenced| {
                let data = b64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
                let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
                if parsed.entry_type != kind {
                    return None;
                }
                let payload = parsed.decode_payload::<serde_json::Value>().ok()?;
                let mine = payload["digest"] == serde_json::json!(real_digest)
                    && (payload.get("bb_id").is_none() || payload["bb_id"] == 1)
                    && (payload.get("receipt").is_none() || payload["receipt"]["bb_id"] == 1);
                mine.then_some(payload)
            })
            .unwrap_or_else(|| panic!("BB-1's {kind}"))
    };
    let first_ts = entries.entries.last().expect("an entry").timestamp + 1;
    for (ts, kind) in (first_ts..).zip(["ballot_digest", "cast_intended_proof"]) {
        let mut payload = find(kind);
        payload["digest"] = serde_json::json!(doctored_digest);
        let data = format!(
            "voting,BB,{kind},1,{}",
            b64.encode(serde_json::to_string(&payload).unwrap())
        );
        let entry = referendum_poc::clients::wbb::sign_entry(
            data.as_bytes(),
            "BB-1",
            ts,
            &cluster.signing_key("bb-1"),
        );
        cluster
            .wbb
            .client
            .submit_and_wait(&entry, Duration::from_secs(20))
            .await
            .expect("published");
    }
    cluster.close_voting().await;

    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let extra = doctored.clone();
    let bb1 = helpers::spawn_stand_in(
        &bb1_real,
        cluster.client.clone(),
        std::sync::Arc::new(move |path: &str, _req: &[u8], status, body| {
            if path == "ballots" && status.is_success() {
                let mut list: serde_json::Value = serde_json::from_slice(&body).unwrap();
                list.as_array_mut().unwrap().push(extra.clone());
                return (
                    status,
                    axum::body::Bytes::from(serde_json::to_vec(&list).unwrap()),
                );
            }
            (status, body)
        }),
        None,
    )
    .await;
    let bb2 = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let outcome = cluster.try_tally_with_boxes(vec![bb1, bb2]).await;
    assert!(
        outcome.is_ok(),
        "one dishonest box stopped the tally: {:?}",
        outcome.err()
    );
}

/// Sec. 3.8.4 steps 11-15 and A9: a dishonest box that forwards the voter's
/// disclosure to the honest box, so the device's own request finds a
/// confirmation "in progress" there, must not make the confirmation read as
/// refused: the honest box's answer comes, and the board decides.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarded_disclosure_does_not_read_as_a_refusal() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2_cai = format!("https://127.0.0.1:{}/cai", cluster.ports.bb[1]);
    let client = cluster.client.clone();
    let dishonest = helpers::spawn_stand_in(
        &bb1_real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
            if !path.ends_with("cai") {
                return None;
            }
            let client = client.clone();
            let url = bb2_cai.clone();
            let body = body.to_vec();
            tokio::spawn(async move {
                let _ = client
                    .post(url)
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await;
            });
            tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(20)));
            Some((
                reqwest::StatusCode::FORBIDDEN,
                axum::body::Bytes::from_static(b"{\"error\":\"refused\"}"),
            ))
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", dishonest.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    cluster.open_voting().await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "approve", "pin": pin }),
    )
    .await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    let response = cluster
        .client
        .post(format!("{voter}/api/confirm"))
        .json(&serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": vote["digest"],
            "l1": "code", "l2": "sum",
        }))
        .send()
        .await
        .expect("request");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "the honest box published the confirmation, yet the app said: {status} {body}"
    );
}

/// One writer per device (Sec. 3.7.2 step 4), keyed by what stays the same
/// across a revocation. A second revocation sent while the first is still
/// waiting on the tellers - after the first has already switched the device
/// onto the new identifier - waits for it, and the device ends on ONE
/// session.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_writer_during_a_revocation_waits_for_it() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let voter = cluster.spawn_voter_with_peers(&[]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    cluster.open_voting().await;
    let dir = cluster.voter_state_dir(&voter);
    let files = || {
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("state dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".dat"))
            .collect();
        names.sort();
        names
    };
    let before = files();
    assert_eq!(before.len(), 1, "{before:?}");
    let revoke = || {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/revoke");
        let passphrase = passphrase.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .json(&serde_json::json!({ "passphrase": passphrase }))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    let first = revoke();
    // The first revocation has switched the file (the old one is gone) but
    // is still waiting on the tellers for the new PIN request.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let now = files();
        if now.len() == 1 && now != before {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the file never switched"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let second = revoke();
    let first = first.await.expect("join").expect("request");
    let second = second.await.expect("join").expect("request");
    assert!(
        first.is_success() && second.is_success(),
        "{first} {second}"
    );
    let after = files();
    assert_eq!(after.len(), 1, "two writers on one device left {after:?}");
}

/// Sec. 3.6.1 steps 5-9 and Sec. 3.7.4 step 7: a lost ANSWER to the device
/// registration (the roll registered the key, the device never heard so)
/// must not leave a key at the roll that no device holds. The session is
/// saved before the registration is sent, the passphrase is handed over, and
/// a re-send registers the same key and completes the enrollment.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_answer_to_the_device_registration_does_not_lock_the_voter_out() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let lose = std::sync::Arc::new(AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = {
        let lose = lose.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, _body: &[u8], status, body| {
                if path == "devices" && lose.load(Ordering::SeqCst) {
                    return (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{}"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let voter = cluster.spawn_voter_with_er(er.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    lose.store(true, Ordering::SeqCst);
    let enrolled = cluster
        .client
        .post(format!("{voter}/api/enroll"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-001" }))
        .send()
        .await
        .expect("request");
    let status = enrolled.status();
    let enrolled: serde_json::Value = enrolled.json().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "a lost answer from the roll kept the passphrase from the voter: {status} {enrolled}"
    );
    let passphrase = enrolled["passphrase"]
        .as_str()
        .expect("passphrase")
        .to_string();
    helpers::wait_enrollment_settled(&cluster.client, &voter, &passphrase).await;
    lose.store(false, Ordering::SeqCst);
    cluster.open_voting().await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/resend"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().map(|r| r.len()),
        Some(2),
        "{cast}"
    );
}

/// Sec. 3.7.5: one revocation, one spare ("up to n_ACC - n_V revocations can
/// be handled"). A revocation whose ANSWER is lost is retried by the device;
/// the retry gets the spare the first one issued, spends no other, and the
/// device ends on the identifier the roll has - able to cast.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_answer_to_a_revocation_spends_one_spare() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let lose = std::sync::Arc::new(AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = {
        let lose = lose.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, _body: &[u8], status, body| {
                if path == "revocations" && lose.load(Ordering::SeqCst) {
                    return (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{}"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let voter = cluster.spawn_voter_with_er(er.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-003").await;
    let before = cluster.entry_type_count("revocation_commitment").await;

    lose.store(true, Ordering::SeqCst);
    let lost = cluster
        .client
        .post(format!("{voter}/api/revoke"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await
        .expect("request")
        .status();
    lose.store(false, Ordering::SeqCst);
    assert!(!lost.is_success(), "the answer was lost: {lost}");
    let retried = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let after = cluster.entry_type_count("revocation_commitment").await;
    assert_eq!(
        after - before,
        1,
        "one revocation spent {} spares",
        after - before
    );
    let roll = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-003" }),
    )
    .await;
    assert_eq!(retried["vid"], roll["vid"], "device and roll agree");

    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "approve", "pin": pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().map(|r| r.len()),
        Some(2),
        "{cast}"
    );
}

/// Whether a board submission carries a `ballot_digest` entry.
fn is_digest_submission(path: &str, body: &[u8]) -> bool {
    use base64::Engine as _;
    if !path.ends_with("submit") {
        return false;
    }
    let Ok(entry) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    entry["data"]
        .as_str()
        .and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok())
        .is_some_and(|data| String::from_utf8_lossy(&data).contains(",ballot_digest,"))
}

/// Sec. 3.9 step 3 and A9: a box releases every ballot whose digest the
/// board shows under its key. A network attacker that drops a box's board
/// ANSWERS during voting (the digest IS published) must not make that box
/// withhold the ballot at release - the board, now in the tallying phase,
/// refuses a resubmission, and the box asks the board instead. With the
/// other box withholding the ballot, the honest box's copy is the one
/// counted.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_board_answer_does_not_keep_a_published_ballot_from_the_release() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, req: &[u8], status, body| {
                if lossy.load(Ordering::SeqCst)
                    && (is_digest_submission(path, req) || path.ends_with("entries"))
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"answer lost"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let bb1 = cluster
        .spawn_bb_with_board("bb-1", board.join("wbb/").unwrap().as_str())
        .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.clone())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut passphrases = Vec::new();
    for fiscal_id in ["VOTER-001", "VOTER-002", "VOTER-003"] {
        passphrases.push(helpers::enroll_on(&cluster.client, &voter, fiscal_id).await);
    }
    cluster.open_voting().await;
    let vote = |passphrase: String, option: &'static str| {
        let client = cluster.client.clone();
        let voter = voter.clone();
        async move {
            let pin = helpers::post_json(
                &client,
                &format!("{voter}/api/pin"),
                serde_json::json!({ "passphrase": passphrase }),
            )
            .await["pin"]
                .as_u64()
                .expect("pin");
            let ballot = helpers::post_json(
                &client,
                &format!("{voter}/api/vote"),
                serde_json::json!({ "passphrase": passphrase, "option": option, "pin": pin }),
            )
            .await;
            (pin, ballot["digest"].as_str().expect("digest").to_string())
        }
    };
    for passphrase in &passphrases[1..] {
        let (pin, digest) = vote(passphrase.clone(), "approve").await;
        helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/cast"),
            serde_json::json!({ "passphrase": passphrase, "pin": pin }),
        )
        .await;
        helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/confirm"),
            serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": digest,
                                "l1": "code", "l2": "sum" }),
        )
        .await;
    }
    let victim = passphrases[0].clone();
    let (pin, digest) = vote(victim.clone(), "reject").await;
    lossy.store(true, Ordering::SeqCst);
    let _ = cluster
        .client
        .post(format!("{voter}/api/cast"))
        .json(&serde_json::json!({ "passphrase": victim, "pin": pin }))
        .send()
        .await;
    let _ = cluster
        .client
        .post(format!("{voter}/api/confirm"))
        .json(
            &serde_json::json!({ "passphrase": victim, "pin": pin, "digest": digest,
                                   "l1": "code", "l2": "sum" }),
        )
        .send()
        .await;
    lossy.store(false, Ordering::SeqCst);
    cluster.close_voting().await;

    let token = std::fs::read_to_string(cluster.ceremony_dir().join("bb-1-service-token.txt"))
        .expect("token")
        .trim()
        .to_string();
    let released: serde_json::Value = cluster
        .client
        .get(format!("{bb1}/ballots"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("release")
        .json()
        .await
        .unwrap_or_default();
    assert_eq!(
        released.as_array().map(|a| a.len()),
        Some(3),
        "BB-1 holds three ballots whose digests the board shows under its key: {released}"
    );

    // The other box withholds the victim's ballot: BB-1's copy must count.
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let withheld = digest.clone();
    let bb2 = helpers::spawn_stand_in(
        &bb2_real,
        cluster.client.clone(),
        std::sync::Arc::new(move |path: &str, _req: &[u8], status, body| {
            if path == "ballots" && status.is_success() {
                let list: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
                let kept: Vec<serde_json::Value> = list
                    .into_iter()
                    .filter(|r| {
                        let b: evoting::api::prelude::Ballot<
                            dlog_group::ristretto::RistrettoGroup,
                        > = serde_json::from_value(r["ballot"].clone()).unwrap();
                        referendum_poc::protocol::voting::ballot_digest(&b)
                            .unwrap()
                            .to_string()
                            != withheld
                    })
                    .collect();
                return (
                    status,
                    axum::body::Bytes::from(serde_json::to_vec(&kept).unwrap()),
                );
            }
            (status, body)
        }),
        None,
    )
    .await;
    let bb1_url = reqwest::Url::parse(&format!("{bb1}/")).unwrap();
    let outcome = cluster
        .try_tally_with_boxes(vec![bb1_url, bb2])
        .await
        .expect("tally");
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (2, 1),
        "the confirmed ballot BB-2 withheld is counted from BB-1's copy"
    );
}

/// Sec. 3.8.4 steps 11-14 and A9: a box's confirmation slot is taken only by
/// a disclosure that opens the ballot. A flood of disclosures copied from the
/// board - another voter's, valid for another ballot - must not keep the
/// slot busy and turn the voter's own confirmation away.
#[tokio::test(flavor = "multi_thread")]
async fn copied_disclosures_do_not_keep_the_voter_from_confirming() {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    // BB-1 accepts casts and refuses every confirmation.
    let dishonest = helpers::spawn_stand_in(
        &bb1_real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(|path: &str, _body: &[u8]| {
            path.ends_with("cai").then(|| {
                (
                    reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    axum::body::Bytes::from_static(b"{\"error\":\"busy\"}"),
                )
            })
        })),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", dishonest.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let victim = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let other = helpers::enroll_on(&cluster.client, &voter, "VOTER-002").await;
    cluster.open_voting().await;
    let pin_of = |passphrase: &str| {
        let client = cluster.client.clone();
        let url = format!("{voter}/api/pin");
        let body = serde_json::json!({ "passphrase": passphrase });
        async move {
            helpers::post_json(&client, &url, body).await["pin"]
                .as_u64()
                .expect("pin")
        }
    };
    // Another voter confirms: a genuine disclosure lands on the board.
    let pin2 = pin_of(&other).await;
    let v2 = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": other, "option": "approve", "pin": pin2 }),
    )
    .await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": other, "pin": pin2 }),
    )
    .await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/confirm"),
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": v2["digest"],
                            "l1": "code", "l2": "sum" }),
    )
    .await;
    let entries = cluster.wbb.client.entries().await.expect("entries");
    let copied = entries
        .entries
        .iter()
        .find_map(|s| {
            let data = base64::engine::general_purpose::STANDARD
                .decode(s.entry.get("data")?.as_str()?)
                .ok()?;
            let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
            (parsed.entry_type == "cast_intended_proof")
                .then(|| parsed.decode_payload::<serde_json::Value>().ok())?
        })
        .expect("a disclosure on the board")["disclosure"]
        .clone();

    let pin = pin_of(&victim).await;
    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": victim, "option": "reject", "pin": pin }),
    )
    .await;
    let digest = vote["digest"].as_str().expect("digest").to_string();
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": victim, "pin": pin }),
    )
    .await;

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let bb2_cai = format!("https://127.0.0.1:{}/cai", cluster.ports.bb[1]);
    let mut flood = Vec::new();
    for _ in 0..32 {
        let client = cluster.client.clone();
        let url = bb2_cai.clone();
        let body = serde_json::json!({ "digest": digest, "disclosure": copied });
        let stop = stop.clone();
        flood.push(tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                let _ = client.post(&url).json(&body).send().await;
            }
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let confirmed = cluster
        .client
        .post(format!("{voter}/api/confirm"))
        .json(
            &serde_json::json!({ "passphrase": victim, "pin": pin, "digest": digest,
                                   "l1": "code", "l2": "sum" }),
        )
        .send()
        .await
        .expect("request");
    let status = confirmed.status();
    let body = confirmed.text().await.unwrap_or_default();
    stop.store(true, Ordering::SeqCst);
    for task in flood {
        let _ = task.await;
    }
    assert!(
        status.is_success(),
        "a flood of copied disclosures turned the voter's confirmation away: {status} {body}"
    );
}

/// One ballot, one metadata entry per box: concurrent re-casts of a ballot
/// whose digest a box has not yet seen on the board publish the digest once
/// and sign ONE metadata entry, not one per request.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_re_casts_publish_one_metadata_entry() {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let drop_digest = std::sync::Arc::new(AtomicBool::new(false));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let drop_digest = drop_digest.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                (drop_digest.load(Ordering::SeqCst) && is_digest_submission(path, body)).then(
                    || {
                        (
                            reqwest::StatusCode::BAD_GATEWAY,
                            axum::body::Bytes::from_static(b"lost"),
                        )
                    },
                )
            })),
        )
        .await
    };
    let bb1 = cluster
        .spawn_bb_with_board("bb-1", board.join("wbb/").unwrap().as_str())
        .await;
    // Record what the app sends the other box, to replay it at BB-1.
    let recorded: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>> = Default::default();
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let bb2 = {
        let recorded = recorded.clone();
        helpers::spawn_stand_in(
            &bb2_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                if path == "ballots" {
                    *recorded.lock().unwrap() = Some(body.to_vec());
                }
                None
            })),
        )
        .await
    };
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.clone()), ("bb-2", bb2.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    cluster.open_voting().await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    let vote = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let digest = vote["digest"].as_str().expect("digest").to_string();
    drop_digest.store(true, Ordering::SeqCst);
    let _ = cluster
        .client
        .post(format!("{voter}/api/cast"))
        .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
        .send()
        .await;
    drop_digest.store(false, Ordering::SeqCst);
    let body = recorded
        .lock()
        .unwrap()
        .clone()
        .expect("the cast reached BB-2");
    let mut replays = Vec::new();
    for _ in 0..6 {
        let client = cluster.client.clone();
        let url = format!("{bb1}/ballots");
        let body = body.clone();
        replays.push(tokio::spawn(async move {
            client
                .post(url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map(|r| r.status())
        }));
    }
    for replay in replays {
        let _ = replay.await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let entries = cluster.wbb.client.entries().await.expect("entries");
    let metadata = entries
        .entries
        .iter()
        .filter_map(|s| {
            let data = base64::engine::general_purpose::STANDARD
                .decode(s.entry.get("data")?.as_str()?)
                .ok()?;
            let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
            let payload = parsed.decode_payload::<serde_json::Value>().ok()?;
            (parsed.entry_type == "ballot_metadata"
                && payload["digest"] == serde_json::json!(digest)
                && payload["bb_id"] == 1)
                .then_some(())
        })
        .count();
    assert_eq!(
        metadata, 1,
        "one ballot, {metadata} metadata entries from BB-1"
    );
}

/// Sec. 3.7.5: a revocation revokes the credential the voter holds NOW. A
/// second device of the voter that is out of date (it still holds a session
/// on an identifier the first device already revoked) is not retrying a lost
/// answer: its revocation is a real one, and the credential the first
/// revocation issued - which a coercer may have watched - is revoked too.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_from_an_out_of_date_second_device_revokes() {
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.open_voting().await;
    let first = cluster.spawn_voter_with_peers(&[]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &first, "VOTER-001").await;
    let second = cluster
        .spawn_voter_server_as("voter-1", "second-device")
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    helpers::post_json(
        &cluster.client,
        &format!("{second}/api/device/recover"),
        serde_json::json!({ "fiscal_id": "VOTER-001", "passphrase": passphrase }),
    )
    .await;
    let revoked = helpers::post_json(
        &cluster.client,
        &format!("{first}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let watched = revoked["vid"].as_u64().expect("vid");
    let before = cluster.entry_type_count("revocation_commitment").await;
    helpers::post_json(
        &cluster.client,
        &format!("{second}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let after = cluster.entry_type_count("revocation_commitment").await;
    let roll = helpers::post_json(
        &cluster.client,
        &format!("{second}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    assert_eq!(
        after - before,
        1,
        "the second device's revocation revoked nothing"
    );
    assert_ne!(
        roll["vid"].as_u64(),
        Some(watched),
        "credential {watched} is still the voter's"
    );
}

/// Sec. 3.6.1 steps 5-9: the passphrase is handed over before the enrollment
/// goes on the network. A notification service that is slow to answer (a
/// network attacker can delay any channel) must not make a voter who stops
/// waiting lose the passphrase to a session already saved under it.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_enrollment_hands_over_the_passphrase_at_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.open_voting().await;
    let slow = std::sync::Arc::new(AtomicBool::new(true));
    let ns_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.ns)).expect("ns url");
    let ns = {
        let slow = slow.clone();
        helpers::spawn_stand_in(
            &ns_real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, _body: &[u8], status, body| {
                if path.ends_with("register") && slow.load(Ordering::SeqCst) {
                    tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(4000)));
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let voter = cluster.spawn_voter_with_ns(ns.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    // The voter stops waiting after 1.5 s.
    let enrolled = cluster
        .client
        .post(format!("{voter}/api/enroll"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-001" }))
        .timeout(Duration::from_millis(1500))
        .send()
        .await
        .expect("the passphrase arrives before the voter gives up");
    let enrolled: serde_json::Value = enrolled.json().await.expect("json");
    let passphrase = enrolled["passphrase"]
        .as_str()
        .expect("passphrase")
        .to_string();
    slow.store(false, Ordering::SeqCst);
    helpers::wait_pin_ready(&cluster.client, &voter, &passphrase).await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let cast = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().map(|r| r.len()),
        Some(2),
        "{cast}"
    );
}

/// Sec. 3.7.4: the roll keeps the voter's recovery blob. A device that
/// re-registers its SAME key to repair a registration it could not confirm
/// sends no blob, and that must not erase the one the roll holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_repair_keeps_the_recovery_blob() {
    use std::sync::atomic::{AtomicU8, Ordering};
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.open_voting().await;
    // 1: the roll's answer to POST /devices is lost; 2: PIN request tokens refused.
    let mode = std::sync::Arc::new(AtomicU8::new(0));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = {
        let answers = mode.clone();
        let requests = mode.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, _body: &[u8], status, body| {
                if path == "devices" && answers.load(Ordering::SeqCst) == 1 {
                    return (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{}"),
                    );
                }
                (status, body)
            }),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (path == "tokens/pin-request" && requests.load(Ordering::SeqCst) == 2).then(|| {
                    (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{}"),
                    )
                })
            })),
        )
        .await
    };
    let voter = cluster.spawn_voter_with_er(er.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    mode.store(1, Ordering::SeqCst);
    let enrolled = helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/enroll"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    let passphrase = enrolled["passphrase"]
        .as_str()
        .expect("passphrase")
        .to_string();
    helpers::wait_enrollment_settled(&cluster.client, &voter, &passphrase).await;
    mode.store(0, Ordering::SeqCst);
    // The device saved its blob after the failed request; a recovery works.
    let recover_on = |label: &'static str| {
        let cluster = &cluster;
        let passphrase = passphrase.clone();
        async move {
            let device = cluster.spawn_voter_server_as("voter-2", label).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            cluster
                .client
                .post(format!("{device}/api/device/recover"))
                .json(&serde_json::json!({ "fiscal_id": "VOTER-001", "passphrase": passphrase }))
                .send()
                .await
                .expect("request")
                .status()
        }
    };
    assert!(recover_on("before-repair").await.is_success(), "control");
    mode.store(2, Ordering::SeqCst);
    let _ = cluster
        .client
        .post(format!("{voter}/api/pin/resend"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await;
    mode.store(0, Ordering::SeqCst);
    let after = recover_on("after-repair").await;
    assert!(
        after.is_success(),
        "the registration repair erased the recovery blob: {after}"
    );
}

/// Sec. 3.8.4 steps 6-8 and Sec. 3.9 step 10: the app sends a disclosure
/// only for a ballot the board already shows. A dishonest box that holds a
/// ballot without publishing it (while a network attacker keeps the honest
/// box from receiving it) never gets the voter's disclosure, so it cannot
/// publish that ballot after the voter's re-vote and have it counted instead.
#[tokio::test(flavor = "multi_thread")]
async fn a_ballot_published_after_the_re_vote_does_not_replace_it() {
    use std::sync::atomic::{AtomicBool, Ordering};
    type Ballot = evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup>;
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let hold = std::sync::Arc::new(AtomicBool::new(false));
    let recorded_cast: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>> = Default::default();
    let recorded_cai: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>> = Default::default();
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    // BB-1, dishonest: while `hold`, it records the cast and the disclosure,
    // answers the cast with a receipt and publishes nothing.
    let bb1 = {
        let hold = hold.clone();
        let recorded_cast = recorded_cast.clone();
        let recorded_cai = recorded_cai.clone();
        helpers::spawn_stand_in(
            &bb1_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                if !hold.load(Ordering::SeqCst) {
                    return None;
                }
                if path == "ballots" {
                    *recorded_cast.lock().unwrap() = Some(body.to_vec());
                    let request: serde_json::Value = serde_json::from_slice(body).ok()?;
                    let ballot: Ballot = serde_json::from_value(request["ballot"].clone()).ok()?;
                    let digest = referendum_poc::protocol::voting::ballot_digest(&ballot).ok()?;
                    let answer = serde_json::json!({
                        "digest": digest,
                        "receipt": {"seq_no": 7, "received_at_unix_ms": 1, "bb_id": 1},
                        "emoji": ballot.to_emoji(),
                    });
                    return Some((
                        reqwest::StatusCode::OK,
                        axum::body::Bytes::from(serde_json::to_vec(&answer).unwrap()),
                    ));
                }
                if path == "cai" {
                    *recorded_cai.lock().unwrap() = Some(body.to_vec());
                    return Some((
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{\"error\":\"busy\"}"),
                    ));
                }
                None
            })),
        )
        .await
    };
    // The network attacker drops the app's traffic to BB-2 while `hold`.
    let bb2 = {
        let hold = hold.clone();
        helpers::spawn_stand_in(
            &bb2_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (hold.load(Ordering::SeqCst) && (path == "ballots" || path == "cai")).then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.to_string()), ("bb-2", bb2.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let victim = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let other = helpers::enroll_on(&cluster.client, &voter, "VOTER-002").await;
    cluster.open_voting().await;
    let post = |path: &'static str, body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{voter}{path}");
        async move { helpers::post_json(&client, &url, body).await }
    };
    // Another voter approves, normally.
    let pin2 = post("/api/pin", serde_json::json!({ "passphrase": other })).await["pin"]
        .as_u64()
        .expect("pin");
    let v2 = post(
        "/api/vote",
        serde_json::json!({ "passphrase": other, "option": "approve", "pin": pin2 }),
    )
    .await;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": other, "pin": pin2 }),
    )
    .await;
    post(
        "/api/confirm",
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": v2["digest"],
                            "l1": "code", "l2": "sum" }),
    )
    .await;

    // The victim's first ballot (approve), under attack.
    let pin = post("/api/pin", serde_json::json!({ "passphrase": victim })).await["pin"]
        .as_u64()
        .expect("pin");
    let first = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "approve", "pin": pin }),
    )
    .await;
    hold.store(true, Ordering::SeqCst);
    let _ = cluster
        .client
        .post(format!("{voter}/api/cast"))
        .json(&serde_json::json!({ "passphrase": victim, "pin": pin }))
        .send()
        .await;
    let _ = cluster
        .client
        .post(format!("{voter}/api/confirm"))
        .json(
            &serde_json::json!({ "passphrase": victim, "pin": pin, "digest": first["digest"],
                                   "l1": "sum", "l2": "sum" }),
        )
        .send()
        .await;
    hold.store(false, Ordering::SeqCst);
    assert!(
        recorded_cai.lock().unwrap().is_none(),
        "the app sent a disclosure for a ballot no box had published"
    );

    // The victim re-votes privately (reject), on both boxes.
    let second = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "reject", "pin": pin }),
    )
    .await;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": victim, "pin": pin }),
    )
    .await;
    post(
        "/api/confirm",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": second["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;

    // BB-1 publishes the first ballot late, with whatever it recorded.
    let late_cast = recorded_cast.lock().unwrap().clone();
    if let Some(body) = late_cast {
        let _ = cluster
            .client
            .post(format!("{bb1_real}ballots"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await;
    }
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (1, 1),
        "the victim's last confirmed ballot (reject) must be the one counted"
    );
}

/// Sec. 3.9 step 3 and A9: at release a box decides from ONE board read
/// which of its ballots are published, and a read that fails fails the
/// release. A network attacker dropping that read must not turn the
/// release into a shorter list that looks honest.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_board_read_does_not_shorten_a_release() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let drop_reads = std::sync::Arc::new(AtomicUsize::new(0));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        let drop_reads = drop_reads.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, req: &[u8], status, body| {
                if lossy.load(Ordering::SeqCst)
                    && (is_digest_submission(path, req) || path.ends_with("entries"))
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"answer lost"),
                    );
                }
                if path.ends_with("entries")
                    && drop_reads
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"read dropped"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let bb1 = cluster
        .spawn_bb_with_board("bb-1", board.join("wbb/").unwrap().as_str())
        .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.clone())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut passphrases = Vec::new();
    for fiscal_id in ["VOTER-001", "VOTER-002", "VOTER-003"] {
        passphrases.push(helpers::enroll_on(&cluster.client, &voter, fiscal_id).await);
    }
    cluster.open_voting().await;
    for (i, passphrase) in passphrases.iter().enumerate() {
        let pin = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/pin"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await["pin"]
            .as_u64()
            .expect("pin");
        let vote = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/vote"),
            serde_json::json!({ "passphrase": passphrase, "option": "approve", "pin": pin }),
        )
        .await;
        // The last voter's cast reaches the board, but BB-1 never hears so.
        lossy.store(i == 2, Ordering::SeqCst);
        let _ = cluster
            .client
            .post(format!("{voter}/api/cast"))
            .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
            .send()
            .await;
        let _ = cluster
            .client
            .post(format!("{voter}/api/confirm"))
            .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin,
                                       "digest": vote["digest"], "l1": "code", "l2": "sum" }))
            .send()
            .await;
        lossy.store(false, Ordering::SeqCst);
    }
    cluster.close_voting().await;
    let token = std::fs::read_to_string(cluster.ceremony_dir().join("bb-1-service-token.txt"))
        .expect("token")
        .trim()
        .to_string();
    let release = || async {
        let response = cluster
            .client
            .get(format!("{bb1}/ballots"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("request");
        let status = response.status();
        let records: serde_json::Value = response.json().await.unwrap_or_default();
        (status, records.as_array().map(|a| a.len()))
    };
    drop_reads.store(1, Ordering::SeqCst);
    let (status, released) = release().await;
    assert!(
        !status.is_success() || released == Some(3),
        "a dropped board read shortened the release: {status} {released:?}"
    );
    let (status, released) = release().await;
    assert!(status.is_success(), "{status}");
    assert_eq!(
        released,
        Some(3),
        "every ballot whose digest the board shows is released"
    );
}

/// Sec. 3.7.4 and 3.7.5: a device recovered from the recovery blob does not
/// inherit the other device's pending revocation request. Its own later
/// revocation is a real one - not taken for a retry of the other device's -
/// and the credential a coercer watched being issued is revoked.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovered_device_does_not_inherit_a_pending_revocation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.open_voting().await;
    let drop_revocation = std::sync::Arc::new(AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = {
        let drop_revocation = drop_revocation.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (path == "revocations" && drop_revocation.load(Ordering::SeqCst)).then(|| {
                    (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{}"),
                    )
                })
            })),
        )
        .await
    };
    let first = cluster.spawn_voter_with_er(er.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &first, "VOTER-001").await;
    let pin = helpers::post_json(
        &cluster.client,
        &format!("{first}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .expect("pin");
    // A revocation whose request never reaches the roll leaves an id pending.
    drop_revocation.store(true, Ordering::SeqCst);
    let _ = cluster
        .client
        .post(format!("{first}/api/revoke"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await;
    drop_revocation.store(false, Ordering::SeqCst);
    // A cast refreshes the recovery blob.
    helpers::post_json(
        &cluster.client,
        &format!("{first}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": "approve", "pin": pin }),
    )
    .await;
    helpers::post_json(
        &cluster.client,
        &format!("{first}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    let second = cluster
        .spawn_voter_server_as("voter-1", "second-device")
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    helpers::post_json(
        &cluster.client,
        &format!("{second}/api/device/recover"),
        serde_json::json!({ "fiscal_id": "VOTER-001", "passphrase": passphrase }),
    )
    .await;
    // The first device revokes for real, watched by the coercer.
    let watched = helpers::post_json(
        &cluster.client,
        &format!("{first}/api/revoke"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["vid"]
        .as_u64()
        .expect("vid");
    let before = cluster.entry_type_count("revocation_commitment").await;
    // Alone, the voter revokes from the recovered device.
    let _ = cluster
        .client
        .post(format!("{second}/api/revoke"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await;
    let after = cluster.entry_type_count("revocation_commitment").await;
    let roll = helpers::post_json(
        &cluster.client,
        &format!("{second}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    assert_eq!(
        after - before,
        1,
        "the recovered device's revocation revoked nothing"
    );
    assert_ne!(
        roll["vid"].as_u64(),
        Some(watched),
        "credential {watched} is still the voter's"
    );
}

/// Sec. 3.7.5: a revocation is possible until the end of voting. A retry of
/// a revocation whose answer was lost is refused like any other once voting
/// has closed - the phase is checked before the retry is recognised.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_retry_after_voting_closed_is_refused() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let lose = std::sync::Arc::new(AtomicBool::new(false));
    let real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.er)).expect("er url");
    let er = {
        let lose = lose.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, _body: &[u8], status, body| {
                if path == "revocations" && lose.load(Ordering::SeqCst) {
                    return (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        axum::body::Bytes::from_static(b"{}"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let voter = cluster.spawn_voter_with_er(er.as_ref()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let passphrase = helpers::enroll_on(&cluster.client, &voter, "VOTER-003").await;
    lose.store(true, Ordering::SeqCst);
    let _ = cluster
        .client
        .post(format!("{voter}/api/revoke"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await;
    lose.store(false, Ordering::SeqCst);
    cluster.close_voting().await;
    let retried = cluster
        .client
        .post(format!("{voter}/api/revoke"))
        .json(&serde_json::json!({ "passphrase": passphrase }))
        .send()
        .await
        .expect("request");
    let status = retried.status();
    let body = retried.text().await.unwrap_or_default();
    assert!(
        !status.is_success() && body.contains("NOT revoked"),
        "a retry after voting closed was answered as a revocation: {status} {body}"
    );
}

/// Sec. 3.9 step 10 counts a voter's most recent ballot. An older ballot of
/// the same PIN that one box held back (and the board never showed) is
/// superseded by the voter's confirmed re-vote: tapping Cast again must not
/// send it, and it can never be confirmed in the re-vote's place.
#[tokio::test(flavor = "multi_thread")]
async fn a_superseded_ballot_is_not_revived_after_the_re_vote() {
    use std::sync::atomic::{AtomicBool, Ordering};
    type Ballot = evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup>;
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let hold = std::sync::Arc::new(AtomicBool::new(false));
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    // BB-1, dishonest while `hold`: a receipt for the cast, nothing published.
    let bb1 = {
        let hold = hold.clone();
        helpers::spawn_stand_in(
            &bb1_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                if !hold.load(Ordering::SeqCst) || path != "ballots" {
                    return None;
                }
                let request: serde_json::Value = serde_json::from_slice(body).ok()?;
                let ballot: Ballot = serde_json::from_value(request["ballot"].clone()).ok()?;
                let digest = referendum_poc::protocol::voting::ballot_digest(&ballot).ok()?;
                let answer = serde_json::json!({
                    "digest": digest,
                    "receipt": {"seq_no": 7, "received_at_unix_ms": 1, "bb_id": 1},
                    "emoji": ballot.to_emoji(),
                });
                Some((
                    reqwest::StatusCode::OK,
                    axum::body::Bytes::from(serde_json::to_vec(&answer).unwrap()),
                ))
            })),
        )
        .await
    };
    // The network attacker drops the app's cast to BB-2 while `hold`.
    let bb2 = {
        let hold = hold.clone();
        helpers::spawn_stand_in(
            &bb2_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (hold.load(Ordering::SeqCst) && path == "ballots").then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.to_string()), ("bb-2", bb2.to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let victim = helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let other = helpers::enroll_on(&cluster.client, &voter, "VOTER-002").await;
    cluster.open_voting().await;
    let post = |path: &'static str, body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{voter}{path}");
        async move { helpers::post_json(&client, &url, body).await }
    };
    let attempt = |path: &'static str, body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{voter}{path}");
        async move {
            let _ = client.post(url).json(&body).send().await;
        }
    };
    // Another voter rejects, normally.
    let pin2 = post("/api/pin", serde_json::json!({ "passphrase": other })).await["pin"]
        .as_u64()
        .expect("pin");
    let v2 = post(
        "/api/vote",
        serde_json::json!({ "passphrase": other, "option": "reject", "pin": pin2 }),
    )
    .await;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": other, "pin": pin2 }),
    )
    .await;
    post(
        "/api/confirm",
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": v2["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;

    // The victim's first ballot (approve) reaches only the dishonest box.
    let pin = post("/api/pin", serde_json::json!({ "passphrase": victim })).await["pin"]
        .as_u64()
        .expect("pin");
    let first = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "approve", "pin": pin }),
    )
    .await;
    hold.store(true, Ordering::SeqCst);
    attempt(
        "/api/cast",
        serde_json::json!({ "passphrase": victim, "pin": pin }),
    )
    .await;
    attempt(
        "/api/confirm",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": first["digest"],
                            "l1": "sum", "l2": "code" }),
    )
    .await;
    hold.store(false, Ordering::SeqCst);

    // The re-vote (reject), cast and confirmed on both boxes.
    let second = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "reject", "pin": pin }),
    )
    .await;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": victim, "pin": pin }),
    )
    .await;
    post(
        "/api/confirm",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": second["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;

    // Cast tapped again, then a confirmation of the first ballot.
    attempt(
        "/api/cast",
        serde_json::json!({ "passphrase": victim, "pin": pin }),
    )
    .await;
    attempt(
        "/api/confirm",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": first["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (0, 2),
        "the victim's confirmed re-vote (reject) must be the one counted"
    );
}

/// A stand-in for BB-2 that releases everything except the ballot `withheld`.
async fn withholding_box(cluster: &ElectionCluster, withheld: String) -> reqwest::Url {
    let real = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    helpers::spawn_stand_in(
        &real,
        cluster.client.clone(),
        std::sync::Arc::new(move |path: &str, _req: &[u8], status, body| {
            if path == "ballots" && status.is_success() {
                let list: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
                let kept: Vec<serde_json::Value> = list
                    .into_iter()
                    .filter(|r| {
                        let b: evoting::api::prelude::Ballot<
                            dlog_group::ristretto::RistrettoGroup,
                        > = serde_json::from_value(r["ballot"].clone()).unwrap();
                        referendum_poc::protocol::voting::ballot_digest(&b)
                            .unwrap()
                            .to_string()
                            != withheld
                    })
                    .collect();
                return (
                    status,
                    axum::body::Bytes::from(serde_json::to_vec(&kept).unwrap()),
                );
            }
            (status, body)
        }),
        None,
    )
    .await
}

/// Three voters on one app server whose BB-1 talks to the board through
/// `board`; the third casts while `lossy` is up. Returns the third ballot's
/// digest and BB-1's URL.
async fn three_ballots_one_lossy(
    cluster: &ElectionCluster,
    board: reqwest::Url,
    lossy: &std::sync::atomic::AtomicBool,
) -> (String, String) {
    use std::sync::atomic::Ordering;
    let bb1 = cluster
        .spawn_bb_with_board("bb-1", board.join("wbb/").unwrap().as_str())
        .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.clone())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut passphrases = Vec::new();
    for fiscal_id in ["VOTER-001", "VOTER-002", "VOTER-003"] {
        passphrases.push(helpers::enroll_on(&cluster.client, &voter, fiscal_id).await);
    }
    cluster.open_voting().await;
    let mut last = String::new();
    for (i, passphrase) in passphrases.iter().enumerate() {
        let option = if i == 2 { "reject" } else { "approve" };
        let pin = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/pin"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await["pin"]
            .as_u64()
            .expect("pin");
        let vote = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/vote"),
            serde_json::json!({ "passphrase": passphrase, "option": option, "pin": pin }),
        )
        .await;
        lossy.store(i == 2, Ordering::SeqCst);
        let _ = cluster
            .client
            .post(format!("{voter}/api/cast"))
            .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
            .send()
            .await;
        let _ = cluster
            .client
            .post(format!("{voter}/api/confirm"))
            .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin,
                                       "digest": vote["digest"], "l1": "code", "l2": "sum" }))
            .send()
            .await;
        lossy.store(false, Ordering::SeqCst);
        last = vote["digest"].as_str().expect("digest").to_string();
    }
    cluster.close_voting().await;
    (last, bb1)
}

/// Sec. 3.9 steps 2-3 and A9: a release an honest box could not complete
/// (its board read was dropped) is asked for again by the tally; it is never
/// taken for an empty one, which would drop every ballot only that box holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_release_is_asked_again_not_tallied_as_empty() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let drop_reads = std::sync::Arc::new(AtomicUsize::new(0));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        let drop_reads = drop_reads.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, req: &[u8], status, body| {
                if lossy.load(Ordering::SeqCst)
                    && (is_digest_submission(path, req) || path.ends_with("entries"))
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"answer lost"),
                    );
                }
                if path.ends_with("entries")
                    && drop_reads
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"read dropped"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let (victim, bb1) = three_ballots_one_lossy(&cluster, board, &lossy).await;
    let bb2 = withholding_box(&cluster, victim).await;
    drop_reads.store(1, Ordering::SeqCst);
    let outcome = cluster
        .try_tally_with_boxes(vec![reqwest::Url::parse(&format!("{bb1}/")).unwrap(), bb2])
        .await
        .expect("tally");
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (2, 1),
        "the confirmed ballot only the honest box released is counted"
    );
}

/// Sec. 3.9 step 3: "each ballot B for which a digest H(B) has been published
/// during the election period" - by whichever box. An honest box whose own
/// digest submission was lost still releases a confirmed ballot whose digest
/// another box published.
#[tokio::test(flavor = "multi_thread")]
async fn a_digest_published_by_another_box_releases_the_ballot() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                (lossy.load(Ordering::SeqCst) && is_digest_submission(path, body)).then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    let (victim, bb1) = three_ballots_one_lossy(&cluster, board, &lossy).await;
    let bb2 = withholding_box(&cluster, victim).await;
    let outcome = cluster
        .try_tally_with_boxes(vec![reqwest::Url::parse(&format!("{bb1}/")).unwrap(), bb2])
        .await
        .expect("tally");
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (2, 1),
        "the confirmed ballot whose digest another box published is counted"
    );
}

/// The answer to a request, kept even when it is an error.
async fn answer(
    client: &reqwest::Client,
    url: String,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let response = client.post(url).json(&body).send().await.expect("request");
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    )
}

/// Sec. 3.9 step 10: the ballot counted is the voter's most recent. Two
/// ballots of one PIN cast and unconfirmed: confirming the OLDER one is
/// refused (a newer one is on the board), and the newer one - never dropped -
/// is confirmed and counted.
#[tokio::test(flavor = "multi_thread")]
async fn confirming_an_older_ballot_neither_counts_it_nor_strands_the_newer() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let passphrase = cluster.enroll(0).await;
    cluster.enroll(1).await;
    cluster.open_voting().await;
    let pin = cluster.pin(0).await;
    let other_pin = cluster.pin(1).await;
    cluster.vote_and_cast(1, "reject", other_pin).await;
    let voter = cluster.voter_urls[0].clone();
    let client = cluster.client.clone();
    let older = cluster.vote(0, "approve", pin).await;
    answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": older["digest"] }),
    )
    .await;
    let newer = cluster.vote(0, "reject", pin).await;
    answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": newer["digest"] }),
    )
    .await;
    let (status, _) = answer(
        &client,
        format!("{voter}/api/confirm"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": older["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;
    assert_eq!(
        status, 409,
        "the older ballot is superseded by the newer one on the board"
    );
    let (status, body) = answer(
        &client,
        format!("{voter}/api/confirm"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": newer["digest"],
                            "l1": "sum", "l2": "code" }),
    )
    .await;
    assert_eq!(status, 200, "the newer ballot is still confirmable: {body}");
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (0, 2),
        "the newer ballot counts"
    );
}

/// Confirming a ballot forgets the ballots of the PIN built BEFORE it, never
/// the ones built after: the ballot the Cast screen shows can still be cast.
#[tokio::test(flavor = "multi_thread")]
async fn confirming_a_ballot_keeps_a_newer_one_not_yet_cast() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    let passphrase = cluster.enroll(0).await;
    cluster.open_voting().await;
    let pin = cluster.pin(0).await;
    let voter = cluster.voter_urls[0].clone();
    let client = cluster.client.clone();
    let first = cluster.vote(0, "approve", pin).await;
    answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": first["digest"] }),
    )
    .await;
    let second = cluster.vote(0, "reject", pin).await;
    let (status, _) = answer(
        &client,
        format!("{voter}/api/confirm"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": first["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;
    assert_eq!(status, 200, "the second ballot is not on the board yet");
    let (status, body) = answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin, "digest": second["digest"] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "the newer ballot was dropped by the older one's confirmation: {body}"
    );
}

/// Sec. 3.9 step 10 reads "most recent" from the board. An older ballot that
/// a dishonest box held back and that was published only after the voter's
/// re-vote can no longer be confirmed: the re-vote is on the board before it.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_published_older_ballot_cannot_be_confirmed_over_the_re_vote() {
    use std::sync::atomic::{AtomicBool, Ordering};
    type Ballot = evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup>;
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let hold = std::sync::Arc::new(AtomicBool::new(false));
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let bb1 = {
        let hold = hold.clone();
        helpers::spawn_stand_in(
            &bb1_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                if !hold.load(Ordering::SeqCst) || path != "ballots" {
                    return None;
                }
                let request: serde_json::Value = serde_json::from_slice(body).ok()?;
                let ballot: Ballot = serde_json::from_value(request["ballot"].clone()).ok()?;
                let digest = referendum_poc::protocol::voting::ballot_digest(&ballot).ok()?;
                let receipt = serde_json::json!({
                    "digest": digest,
                    "receipt": {"seq_no": 7, "received_at_unix_ms": 1, "bb_id": 1},
                    "emoji": ballot.to_emoji(),
                });
                Some((
                    reqwest::StatusCode::OK,
                    axum::body::Bytes::from(serde_json::to_vec(&receipt).unwrap()),
                ))
            })),
        )
        .await
    };
    let bb2 = {
        let hold = hold.clone();
        helpers::spawn_stand_in(
            &bb2_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
                (hold.load(Ordering::SeqCst) && path == "ballots").then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1.to_string()), ("bb-2", bb2.to_string())])
        .await;
    let client = cluster.client.clone();
    let victim = helpers::enroll_on(&client, &voter, "VOTER-001").await;
    let other = helpers::enroll_on(&client, &voter, "VOTER-002").await;
    cluster.open_voting().await;
    let post = |path: &'static str, body: serde_json::Value| {
        let client = client.clone();
        let url = format!("{voter}{path}");
        async move { helpers::post_json(&client, &url, body).await }
    };
    let pin2 = post("/api/pin", serde_json::json!({ "passphrase": other })).await["pin"]
        .as_u64()
        .expect("pin");
    let o = post(
        "/api/vote",
        serde_json::json!({ "passphrase": other, "option": "reject", "pin": pin2 }),
    )
    .await;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": o["digest"] }),
    )
    .await;
    post(
        "/api/confirm",
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": o["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;

    let pin = post("/api/pin", serde_json::json!({ "passphrase": victim })).await["pin"]
        .as_u64()
        .expect("pin");
    let first = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "approve", "pin": pin }),
    )
    .await;
    hold.store(true, Ordering::SeqCst);
    answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": first["digest"] }),
    )
    .await;
    hold.store(false, Ordering::SeqCst);
    let second = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "reject", "pin": pin }),
    )
    .await;
    answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": second["digest"] }),
    )
    .await;
    // The first ballot cast again: now published, AFTER the re-vote.
    answer(
        &client,
        format!("{voter}/api/cast"),
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": first["digest"] }),
    )
    .await;
    let (status, _) = answer(
        &client,
        format!("{voter}/api/confirm"),
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": first["digest"],
                            "l1": "sum", "l2": "code" }),
    )
    .await;
    assert_eq!(
        status, 409,
        "the older ballot is superseded by the re-vote on the board"
    );
    answer(
        &client,
        format!("{voter}/api/confirm"),
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": second["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (0, 2),
        "the re-vote is the ballot counted"
    );
}

/// Sec. 3.9 steps 2-3: a box that published a counted ballot and does not
/// answer at release - however many times it is asked - never has its
/// release taken for an empty one. The tally stops, naming it, rather than
/// publish a result without the ballot.
#[tokio::test(flavor = "multi_thread")]
async fn a_box_that_stays_silent_at_release_stops_the_tally_rather_than_lose_a_ballot() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let drop_reads = std::sync::Arc::new(AtomicUsize::new(0));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        let drop_reads = drop_reads.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, req: &[u8], status, body| {
                if lossy.load(Ordering::SeqCst)
                    && (is_digest_submission(path, req) || path.ends_with("entries"))
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"answer lost"),
                    );
                }
                if path.ends_with("entries")
                    && drop_reads
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"read dropped"),
                    );
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let (victim, bb1) = three_ballots_one_lossy(&cluster, board, &lossy).await;
    let bb2 = withholding_box(&cluster, victim).await;
    // More dropped reads than the tally asks.
    drop_reads.store(100, Ordering::SeqCst);
    let outcome = cluster
        .try_tally_with_boxes(vec![reqwest::Url::parse(&format!("{bb1}/")).unwrap(), bb2])
        .await;
    match outcome {
        Err(e) => assert!(e.to_string().contains("release is incomplete"), "{e}"),
        Ok(o) => panic!(
            "a result was published without the ballot only the silent box holds: {:?}",
            o.counts
        ),
    }
}

/// Sec. 3.9 steps 2-3: a box holds every ballot it was cast, published or
/// not. A silent box that holds a counted ballot without having published
/// its digest (its submission was lost) stops the tally just like a silent
/// publisher would; once it answers, the ballot is counted.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_box_that_holds_a_ballot_it_did_not_publish_stops_the_tally() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let drop_reads = std::sync::Arc::new(AtomicUsize::new(0));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        let drop_reads = drop_reads.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            std::sync::Arc::new(move |path: &str, _req: &[u8], status, body| {
                if path.ends_with("entries")
                    && drop_reads
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                {
                    return (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"read dropped"),
                    );
                }
                (status, body)
            }),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                (lossy.load(Ordering::SeqCst) && is_digest_submission(path, body)).then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    // BB-1 never publishes the victim's digest; BB-2 publishes it and
    // withholds the ballot at release.
    let (victim, bb1) = three_ballots_one_lossy(&cluster, board, &lossy).await;
    let bb2 = withholding_box(&cluster, victim).await;
    let boxes = vec![reqwest::Url::parse(&format!("{bb1}/")).unwrap(), bb2];
    // BB-1's board reads are dropped: it gives no release.
    drop_reads.store(100, Ordering::SeqCst);
    match cluster.try_tally_with_boxes(boxes.clone()).await {
        // The stop names, per missing ballot, the silent box that may hold
        // it (BB-1 published nothing) and the box that answered without
        // releasing it (Sec. 3.9 step 4).
        Err(e) => {
            let e = e.to_string();
            assert!(e.contains("release is incomplete"), "{e}");
            assert!(e.contains("may be held by the silent BB-1"), "{e}");
            assert!(
                e.contains("not released by BB-2 although it answered"),
                "{e}"
            );
        }
        Ok(o) => panic!(
            "a result was published without the ballot only the silent box holds: {:?}",
            o.counts
        ),
    }
    // Once BB-1 answers, the run again counts the victim's ballot.
    drop_reads.store(0, Ordering::SeqCst);
    let outcome = cluster
        .try_tally_with_boxes(boxes)
        .await
        .expect("the tally completes once every box answers");
    assert_eq!((outcome.counts.si, outcome.counts.no), (2, 1));
}

/// Sec. 3.9 step 4: one box cannot stop the tally for good by publishing a
/// digest and a confirmation for a ballot that does not exist and then
/// staying silent. The tally stops (the box may only be unreachable) until
/// the operator names it to proceed without; then the tally completes.
#[tokio::test(flavor = "multi_thread")]
async fn the_operator_can_tally_without_a_box_that_stays_silent() {
    use base64::Engine as _;
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in [(0usize, "approve"), (1, "approve"), (2, "reject")] {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    // BB-2 publishes, under its own key, a digest entry and a confirmation
    // for a ballot nobody cast: the board counts it.
    let entries = cluster.wbb.client.entries().await.expect("entries");
    let (mut digest_entry, mut confirmation) = (None, None);
    for signed in &entries.entries {
        if !referendum_poc::protocol::voting::signed_by_ballot_box(&signed.entry, 2) {
            continue;
        }
        let Some(parsed) = signed
            .entry
            .get("data")
            .and_then(|d| d.as_str())
            .and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok())
            .and_then(|d| referendum_poc::protocol::voting::parse_wbb_data(&d))
        else {
            continue;
        };
        if parsed.entry_type == "ballot_digest" && digest_entry.is_none() {
            digest_entry = parsed.decode_payload::<serde_json::Value>().ok();
        }
        if parsed.entry_type == "cast_intended_proof" && confirmation.is_none() {
            confirmation = parsed.decode_payload::<serde_json::Value>().ok();
        }
    }
    let mut digest_entry = digest_entry.expect("a BB-2 digest entry");
    let mut confirmation = confirmation.expect("a BB-2 confirmation");
    let made_up = referendum_poc::domain::BallotDigest::from_bytes([0x5a; 32]);
    digest_entry["digest"] = serde_json::to_value(made_up).unwrap();
    confirmation["digest"] = serde_json::to_value(made_up).unwrap();
    let key = {
        let bytes = std::fs::read(cluster.ceremony_dir().join("bb-2-signing-key.bin")).unwrap();
        ed25519_dalek::SigningKey::from_bytes(&bytes.try_into().unwrap())
    };
    let before = entries.entries.len();
    for (n, (entry_type, payload)) in [
        ("ballot_digest", &digest_entry),
        ("cast_intended_proof", &confirmation),
    ]
    .into_iter()
    .enumerate()
    {
        let data = format!(
            "voting,BB,{entry_type},1,{}",
            base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_string(payload).unwrap())
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let entry =
            referendum_poc::clients::wbb::sign_entry(data.as_bytes(), "BB-2", now + n as i64, &key);
        cluster
            .wbb
            .client
            .submit(&entry)
            .await
            .expect("the board takes BB-2's entry");
    }
    while cluster
        .wbb
        .client
        .entries()
        .await
        .expect("entries")
        .entries
        .len()
        < before + 2
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    cluster.close_voting().await;
    // At release BB-2 does not answer.
    let bb1 = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let bb2 = helpers::spawn_stand_in(
        &bb2_real,
        cluster.client.clone(),
        helpers::passthrough(),
        Some(std::sync::Arc::new(move |path: &str, _body: &[u8]| {
            (path == "ballots").then(|| {
                (
                    reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    axum::body::Bytes::from_static(b"busy"),
                )
            })
        })),
    )
    .await;
    let boxes = vec![bb1, bb2];
    // An id that is no ballot box is refused, not ignored.
    match cluster
        .try_tally_with_boxes_without(boxes.clone(), vec![7])
        .await
    {
        Err(e) => assert!(e.to_string().contains("not a ballot box"), "{e}"),
        Ok(o) => panic!("an unknown box id was accepted: {:?}", o.counts),
    }
    match cluster.try_tally_with_boxes(boxes.clone()).await {
        Err(e) => assert!(e.to_string().contains("BB-2"), "{e}"),
        Ok(o) => panic!("the tally went on past a silent box: {:?}", o.counts),
    }
    let outcome = cluster
        .try_tally_with_boxes_without(boxes, vec![2])
        .await
        .expect("the tally completes without the box the operator named");
    assert_eq!((outcome.counts.si, outcome.counts.no), (2, 1));
}

/// Sec. 3.9 step 3: an honest box whose own digest submission was lost
/// releases the ballot on another box's digest - the release rule - and the
/// audit does not accuse it for that.
#[tokio::test(flavor = "multi_thread")]
async fn releasing_on_another_boxs_digest_is_not_misconduct() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let lossy = lossy.clone();
        helpers::spawn_stand_in(
            &real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                (lossy.load(Ordering::SeqCst) && is_digest_submission(path, body)).then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    let (_victim, bb1) = three_ballots_one_lossy(&cluster, board, &lossy).await;
    let bb2 = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let outcome = cluster
        .try_tally_with_boxes(vec![reqwest::Url::parse(&format!("{bb1}/")).unwrap(), bb2])
        .await
        .expect("tally");
    assert_eq!((outcome.counts.si, outcome.counts.no), (2, 1));
    let audit = cluster.audit().await;
    let accusing: Vec<String> = audit
        .steps
        .iter()
        .filter(|s| (!s.ok || s.warning) && s.detail.contains("BB-1"))
        .map(|s| format!("{}: {}", s.name, s.detail))
        .collect();
    assert!(
        accusing.is_empty(),
        "the honest box was accused: {accusing:?}"
    );
}

/// Sec. 3.9 step 10 and Sec. 3.8.4 steps 6-8: the check that no newer
/// ballot is on the board and the check that THIS ballot is published come
/// from one reading. Read apart, a box holding an older ballot X and the
/// re-vote Y could publish Y and then X in between, and X - the older
/// choice - would be confirmed as the most recent and counted.
#[tokio::test(flavor = "multi_thread")]
async fn one_board_reading_decides_both_superseded_and_published() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    type Ballot = evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup>;
    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    let hold = Arc::new(AtomicBool::new(false));
    let arm = Arc::new(AtomicBool::new(false));
    let saved: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    // BB-1: while `hold`, gives a receipt, keeps the request, publishes nothing.
    let bb1 = {
        let hold = hold.clone();
        let saved = saved.clone();
        helpers::spawn_stand_in(
            &bb1_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(Arc::new(move |path: &str, body: &[u8]| {
                if !hold.load(Ordering::SeqCst) || path != "ballots" {
                    return None;
                }
                let request: serde_json::Value = serde_json::from_slice(body).ok()?;
                let ballot: Ballot = serde_json::from_value(request["ballot"].clone()).ok()?;
                let digest = referendum_poc::protocol::voting::ballot_digest(&ballot).ok()?;
                saved.lock().unwrap().push(body.to_vec());
                let receipt = serde_json::json!({
                    "digest": digest,
                    "receipt": {"seq_no": 7, "received_at_unix_ms": 1, "bb_id": 1},
                    "emoji": ballot.to_emoji(),
                });
                Some((
                    reqwest::StatusCode::OK,
                    axum::body::Bytes::from(serde_json::to_vec(&receipt).unwrap()),
                ))
            })),
        )
        .await
    };
    // BB-2 (honest): the casts to it are lost while `hold`.
    let bb2 = {
        let hold = hold.clone();
        helpers::spawn_stand_in(
            &bb2_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(Arc::new(move |path: &str, _body: &[u8]| {
                (hold.load(Ordering::SeqCst) && path == "ballots").then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"dropped"),
                    )
                })
            })),
        )
        .await
    };
    // The board: once armed, the ANSWER to the next full read is held back
    // while BB-1 publishes Y, then X (the snapshot was already taken).
    let real_board =
        reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let board = {
        let arm = arm.clone();
        let saved = saved.clone();
        let client = cluster.client.clone();
        let bb1_real = bb1_real.clone();
        helpers::spawn_stand_in(
            &real_board,
            cluster.client.clone(),
            Arc::new(move |path: &str, _req: &[u8], status, body| {
                if path == "wbb/entries" && arm.swap(false, Ordering::SeqCst) {
                    let bodies = saved.lock().unwrap().clone();
                    let client = client.clone();
                    let url = bb1_real.join("ballots").unwrap();
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async move {
                            // Y (cast second) first, then X.
                            for body in bodies.iter().rev() {
                                client
                                    .post(url.clone())
                                    .header("content-type", "application/json")
                                    .body(body.clone())
                                    .send()
                                    .await
                                    .expect("late publication");
                            }
                        })
                    });
                }
                (status, body)
            }),
            None,
        )
        .await
    };
    let voter = cluster
        .spawn_voter_on_board(
            Some(board.join("wbb/").unwrap().as_str()),
            None,
            None,
            &[("bb-1", bb1.to_string()), ("bb-2", bb2.to_string())],
        )
        .await;
    let client = cluster.client.clone();
    let victim = helpers::enroll_on(&client, &voter, "VOTER-001").await;
    let other = helpers::enroll_on(&client, &voter, "VOTER-002").await;
    cluster.open_voting().await;
    let post = |path: &'static str, body: serde_json::Value| {
        let client = client.clone();
        let url = format!("{voter}{path}");
        async move { answer(&client, url, body).await }
    };
    let pin2 = post("/api/pin", serde_json::json!({ "passphrase": other }))
        .await
        .1["pin"]
        .as_u64()
        .expect("pin");
    let o = post(
        "/api/vote",
        serde_json::json!({ "passphrase": other, "option": "reject", "pin": pin2 }),
    )
    .await
    .1;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": o["digest"] }),
    )
    .await;
    let confirmed = post(
        "/api/confirm",
        serde_json::json!({ "passphrase": other, "pin": pin2, "digest": o["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;
    assert_eq!(confirmed.0, 200, "{}", confirmed.1);

    let pin = post("/api/pin", serde_json::json!({ "passphrase": victim }))
        .await
        .1["pin"]
        .as_u64()
        .expect("pin");
    hold.store(true, Ordering::SeqCst);
    let x = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "approve", "pin": pin }),
    )
    .await
    .1;
    let cast = post(
        "/api/cast",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": x["digest"] }),
    )
    .await;
    assert_eq!(cast.0, 200, "{}", cast.1);
    let y = post(
        "/api/vote",
        serde_json::json!({ "passphrase": victim, "option": "reject", "pin": pin }),
    )
    .await
    .1;
    let cast = post(
        "/api/cast",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": y["digest"] }),
    )
    .await;
    assert_eq!(cast.0, 200, "{}", cast.1);
    hold.store(false, Ordering::SeqCst);
    assert_eq!(saved.lock().unwrap().len(), 2, "BB-1 holds X and Y");

    arm.store(true, Ordering::SeqCst);
    // The first reading of the confirm shows neither X nor Y; Y and then X
    // are published while its answer is held back.
    let cx = post(
        "/api/confirm",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": x["digest"],
                            "l1": "code", "l2": "code" }),
    )
    .await;
    let cy = post(
        "/api/confirm",
        serde_json::json!({ "passphrase": victim, "pin": pin, "digest": y["digest"],
                            "l1": "sum", "l2": "code" }),
    )
    .await;
    assert_eq!(
        cx.0, 409,
        "X was confirmed on a reading that did not show it: {}",
        cx.1
    );
    assert!(
        cx.1.to_string().contains("not on the bulletin board"),
        "X must be refused as not yet published: {}",
        cx.1
    );
    assert_eq!(cy.0, 200, "{}", cy.1);
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (0, 2),
        "the voter's re-vote (Y, reject) must be the ballot counted"
    );
}

/// Three voters on one app server whose BB-1 CAST channel goes through a
/// stand-in that drops the third voter's cast (network attacker): only BB-2
/// holds the third ballot. Returns the third ballot's digest.
async fn three_ballots_one_only_bb2_holds(cluster: &ElectionCluster) -> String {
    use std::sync::atomic::{AtomicBool, Ordering};
    let lossy = std::sync::Arc::new(AtomicBool::new(false));
    let bb1_real =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb1_front = {
        let lossy = lossy.clone();
        helpers::spawn_stand_in(
            &bb1_real,
            cluster.client.clone(),
            helpers::passthrough(),
            Some(std::sync::Arc::new(move |path: &str, body: &[u8]| {
                (lossy.load(Ordering::SeqCst) && path == "ballots" && !body.is_empty()).then(|| {
                    (
                        reqwest::StatusCode::BAD_GATEWAY,
                        axum::body::Bytes::from_static(b"cast dropped"),
                    )
                })
            })),
        )
        .await
    };
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", bb1_front.as_str().trim_end_matches('/').to_string())])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut passphrases = Vec::new();
    for fiscal_id in ["VOTER-001", "VOTER-002", "VOTER-003"] {
        passphrases.push(helpers::enroll_on(&cluster.client, &voter, fiscal_id).await);
    }
    cluster.open_voting().await;
    let mut last = String::new();
    for (i, passphrase) in passphrases.iter().enumerate() {
        let option = if i == 2 { "reject" } else { "approve" };
        let pin = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/pin"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await["pin"]
            .as_u64()
            .expect("pin");
        let vote = helpers::post_json(
            &cluster.client,
            &format!("{voter}/api/vote"),
            serde_json::json!({ "passphrase": passphrase, "option": option, "pin": pin }),
        )
        .await;
        lossy.store(i == 2, Ordering::SeqCst);
        let _cast = cluster
            .client
            .post(format!("{voter}/api/cast"))
            .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin }))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let _confirm = cluster
            .client
            .post(format!("{voter}/api/confirm"))
            .json(&serde_json::json!({ "passphrase": passphrase, "pin": pin,
                                       "digest": vote["digest"], "l1": "code", "l2": "sum" }))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        lossy.store(false, Ordering::SeqCst);
        last = vote["digest"].as_str().expect("digest").to_string();
    }
    cluster.close_voting().await;
    last
}

/// BB-2 writes, under its own key, a well-formed `encrypted_ballot` entry for
/// the ballot with digest `digest`, taken from its own release.
async fn bb2_writes_its_release_of(cluster: &ElectionCluster, digest: &str) {
    use base64::Engine as _;
    let token = std::fs::read_to_string(cluster.ceremony_dir().join("bb-2-service-token.txt"))
        .unwrap()
        .trim()
        .to_string();
    let list: Vec<serde_json::Value> = loop {
        let resp = cluster
            .client
            .get(format!("https://127.0.0.1:{}/ballots", cluster.ports.bb[1]))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::OK {
            break resp.json().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let record = list
        .into_iter()
        .find(|r| {
            let b: evoting::api::prelude::Ballot<dlog_group::ristretto::RistrettoGroup> =
                serde_json::from_value(r["ballot"].clone()).unwrap();
            referendum_poc::protocol::voting::ballot_digest(&b)
                .unwrap()
                .to_string()
                == digest
        })
        .expect("BB-2 holds the ballot");
    let payload = serde_json::json!({ "record": record });
    let data = format!(
        "tallying,BB,encrypted_ballot,1,{}",
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&payload).unwrap())
    );
    let entries = cluster.wbb.client.entries().await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let entry = referendum_poc::clients::wbb::sign_entry(
        data.as_bytes(),
        "BB-2",
        now.max(entries.entries.last().unwrap().timestamp + 1),
        &cluster.signing_key("bb-2"),
    );
    cluster
        .wbb
        .client
        .submit_and_wait(&entry, Duration::from_secs(20))
        .await
        .expect("the board accepts what a box may write");
}

/// Sec. 3.9 step 2: a box sends its released ballots to the board itself.
/// A ballot a box withheld from the driver but wrote to the board before the
/// tally is taken in and counted, and the audit agrees.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_a_box_writes_to_the_board_is_tallied() {
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let victim = three_ballots_one_only_bb2_holds(&cluster).await;
    bb2_writes_its_release_of(&cluster, &victim).await;
    let bb1 = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2 = withholding_box(&cluster, victim).await;
    let outcome = cluster
        .try_tally_with_boxes(vec![bb1, bb2])
        .await
        .expect("tally");
    assert_eq!((outcome.counts.si, outcome.counts.no), (2, 1));
    let audit = cluster.audit().await;
    assert!(audit.ok(), "{:?}", audit.steps);
}

/// A box that writes a release after the tally started changes nothing the
/// tally used: the audit names it and still passes.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_written_after_the_tally_started_is_named_not_counted() {
    let cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    let victim = three_ballots_one_only_bb2_holds(&cluster).await;
    let bb1 = reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let bb2 = withholding_box(&cluster, victim.clone()).await;
    let outcome = cluster
        .try_tally_with_boxes(vec![bb1, bb2])
        .await
        .expect("tally");
    assert_eq!((outcome.counts.si, outcome.counts.no), (2, 0));
    bb2_writes_its_release_of(&cluster, &victim).await;
    let audit = cluster.audit().await;
    assert!(audit.ok(), "{:?}", audit.steps);
    assert!(
        audit
            .steps
            .iter()
            .any(|s| s.detail.contains("after the tally had started")),
        "{:?}",
        audit.steps
    );
}
