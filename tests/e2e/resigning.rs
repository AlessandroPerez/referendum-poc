//! The tally driver signs every artifact again as it sends it (`Resigner`):
//! each re-signed co-signature must be checked against the key pinned for
//! its teller at the ceremony before it is sent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use referendum_poc::protocol::voting::entry_signer_ids;

use super::helpers::{spawn_stand_in, ElectionCluster, ElectionOpts, Rewrite};

fn data_of(entry: &serde_json::Value) -> String {
    entry
        .get("data")
        .and_then(|d| d.as_str())
        .and_then(|d| BASE64.decode(d).ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn url_of(port: &u16) -> reqwest::Url {
    reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap()
}

/// A stand-in rewrite: the `nth` `/sign` answer for the SAME data (data
/// containing `needle`) carries a signature with one bit flipped. The first
/// answer is honest - the co-signature checked when the pipeline queues the
/// artifact - and the second is the one the flush asks for when it signs the
/// artifact again (`Resigner`).
fn corrupt_nth_signature(needle: &'static str, nth: usize) -> Rewrite {
    let seen: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    Arc::new(move |path, request, status, body| {
        if path != "sign" || !status.is_success() {
            return (status, body);
        }
        let Ok(req) = serde_json::from_slice::<serde_json::Value>(request) else {
            return (status, body);
        };
        let Some(data) = req.get("data").and_then(|d| d.as_str()) else {
            return (status, body);
        };
        if !data.contains(needle) {
            return (status, body);
        }
        let n = {
            let mut seen = seen.lock().unwrap();
            let count = seen.entry(data.to_string()).or_insert(0);
            *count += 1;
            *count
        };
        if n != nth {
            return (status, body);
        }
        let mut answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut signature = BASE64
            .decode(answer["signature"].as_str().unwrap())
            .unwrap();
        signature[0] ^= 0x01;
        answer["signature"] = serde_json::Value::String(BASE64.encode(signature));
        (
            status,
            axum::body::Bytes::from(serde_json::to_vec(&answer).unwrap()),
        )
    })
}

/// The tally driver signs every artifact AGAIN as it sends it (`Resigner`,
/// src/actors/admin.rs). Each re-signed co-signature must be held to the key
/// pinned for its teller at the ceremony BEFORE it is sent, over the driver's
/// own data. Here RT-3 and TT-3 co-sign honestly when the pipeline produces
/// the artifacts and return a co-signature that does not verify when the
/// flush re-signs them. Expected: RT-3 is set aside and the control elements
/// go out under RT-1 and RT-2 (t_RT = 2); TT-3 is NAMED and the result is not
/// published; the next run finishes the saved submission and the audit passes.
#[tokio::test]
async fn a_re_signed_co_signature_is_checked_before_it_is_sent() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    let rt3 = spawn_stand_in(
        &url_of(&cluster.ports.rt[2]),
        cluster.client.clone(),
        corrupt_nth_signature(",credential_control,", 2),
        None,
    )
    .await;
    let tt3 = spawn_stand_in(
        &url_of(&cluster.ports.tt[2]),
        cluster.client.clone(),
        corrupt_nth_signature(",tally_result,", 2),
        None,
    )
    .await;
    let rts = vec![
        url_of(&cluster.ports.rt[0]),
        url_of(&cluster.ports.rt[1]),
        rt3,
    ];
    let tts = vec![
        url_of(&cluster.ports.tt[0]),
        url_of(&cluster.ports.tt[1]),
        tt3,
    ];

    let mut problems: Vec<String> = Vec::new();
    match cluster.try_tally_with_rts_and_tellers(rts, tts).await {
        Ok(outcome) => problems.push(format!(
            "the tally finished although TT-3's re-signed co-signature of the result does not \
             verify: {:?}",
            outcome.counts
        )),
        Err(failed) => {
            if !failed
                .to_string()
                .contains("TT-3 returned an invalid co-signature")
            {
                problems.push(format!(
                    "TT-3's re-signed co-signature was not checked against its pinned key \
                     before it was sent (the driver's error: {failed})"
                ));
            }
        }
    }
    let entries = cluster.wbb.client.entries().await.unwrap();
    let controls: Vec<&serde_json::Value> = entries
        .entries
        .iter()
        .map(|e| &e.entry)
        .filter(|e| data_of(e).contains(",credential_control,"))
        .collect();
    match controls.as_slice() {
        [one] => {
            let signers = entry_signer_ids(one);
            if signers.iter().any(|s| s == "RT-3") {
                problems.push(format!(
                    "the control elements were published with RT-3's re-signature: {signers:?}"
                ));
            }
        }
        other => problems.push(format!("{} credential_control entries", other.len())),
    }
    if cluster.entry_type_count("tally_result").await != 0 {
        problems.push("a result was published under a co-signature that does not verify".into());
    }
    // The real tellers finish the saved submission.
    let outcome = cluster.tally().await;
    if (outcome.counts.blank, outcome.counts.si, outcome.counts.no) != (0, 2, 1) {
        problems.push(format!("resumed result {:?}", outcome.counts));
    }
    let report = cluster.audit().await;
    if !report.ok() {
        problems.push(format!("audit after the resume:\n{}", report.render()));
    }
    assert!(problems.is_empty(), "{problems:#?}");
}
