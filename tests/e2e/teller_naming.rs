//! Sec. 3.9 step 16: a party whose contribution cannot be used is set aside
//! and NAMED by the tally driver - whatever way it fails, and without letting
//! its own answer put another teller's name in the operator's report.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::helpers::{self, ElectionCluster, ElectionOpts};

fn url_of(port: &u16) -> reqwest::Url {
    reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap()
}

/// Two voters, one approve and one reject, and the board closed for tally.
async fn closed_election() -> ElectionCluster {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pins = [cluster.pin(0).await, cluster.pin(1).await];
    cluster.open_voting().await;
    cluster.vote_and_cast(0, "approve", pins[0]).await;
    cluster.vote_and_cast(1, "reject", pins[1]).await;
    cluster.close_voting().await;
    cluster
}

/// The tally with TT-3 behind a stand-in whose `intercept` answers for it.
async fn tally_with_tt3(
    cluster: &ElectionCluster,
    intercept: helpers::Intercept,
) -> Result<referendum_poc::actors::admin::TallyOutcome, referendum_poc::actors::admin::AdminError>
{
    let tt3 = helpers::spawn_stand_in(
        &url_of(&cluster.ports.tt[2]),
        cluster.client.clone(),
        helpers::passthrough(),
        Some(intercept),
    )
    .await;
    cluster
        .try_tally_with_tellers(vec![
            url_of(&cluster.ports.tt[0]),
            url_of(&cluster.ports.tt[1]),
            tt3,
        ])
        .await
}

/// TT-3's answer to the SECOND request to co-sign the same re-encryption
/// proof (the flush-time re-sign, `Resigner`): the first, made while the
/// pipeline runs, is forwarded.
fn at_the_resign(answer: (reqwest::StatusCode, &'static str)) -> helpers::Intercept {
    let seen: Arc<Mutex<HashSet<String>>> = Arc::default();
    let fired = Arc::new(AtomicBool::new(false));
    Arc::new(move |path: &str, body: &[u8]| {
        if path != "sign" {
            return None;
        }
        let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let data = request["data"].as_str().unwrap_or_default().to_string();
        if !data.starts_with("tallying,TT,re_encryption_proof,")
            || seen.lock().unwrap().insert(data)
            || fired.swap(true, Ordering::SeqCst)
        {
            return None;
        }
        let body = answer
            .1
            .replace("{timestamp}", &request["timestamp"].to_string());
        Some((answer.0, axum::body::Bytes::from(body)))
    })
}

/// A teller that answers the co-signature request with something that is no
/// signature (200, three bytes) is named, as one that refuses is.
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_returning_an_unusable_co_signature_is_named() {
    let cluster = closed_election().await;
    let failed = tally_with_tt3(
        &cluster,
        at_the_resign((
            reqwest::StatusCode::OK,
            r#"{"signature":"AAAA","timestamp":{timestamp},"entity_id":"TT-3"}"#,
        )),
    )
    .await
    .expect_err("an unusable co-signature stops the run");
    assert!(
        failed
            .to_string()
            .contains("TT-3 returned an unusable co-signature"),
        "{failed}"
    );
    // With TT-3 honest again the tally finishes.
    let outcome = cluster.tally().await;
    assert_eq!((outcome.counts.si, outcome.counts.no), (1, 1));
}

/// A refusal is the teller's own text: it is quoted escaped, so control
/// characters in it cannot erase the driver's line and print another in an
/// honest teller's name on the operator's terminal.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_cannot_rewrite_the_operators_report() {
    let cluster = closed_election().await;
    let forged = "\r\x1b[2K\x1b[1A\x1b[2K\rError: admin driver error: \
                  TT-1 refused to co-sign a tally artifact (its answer: busy";
    let failed = tally_with_tt3(
        &cluster,
        at_the_resign((reqwest::StatusCode::SERVICE_UNAVAILABLE, forged)),
    )
    .await
    .expect_err("a refusal stops the run");
    let report = format!("{:?}", anyhow::Error::from(failed));
    assert!(
        !report.chars().any(|c| c.is_control() && c != '\n'),
        "the teller's answer reaches the report raw: {report:?}"
    );
    assert!(
        report.contains("TT-3 refused to co-sign a tally artifact"),
        "{report}"
    );
}

/// A teller that refuses its zeta VSS round 1 is named, whatever its refusal
/// says about another teller.
#[tokio::test(flavor = "multi_thread")]
async fn a_teller_refusing_its_zeta_round_is_named() {
    let cluster = closed_election().await;
    let fired = Arc::new(AtomicBool::new(false));
    let failed = tally_with_tt3(
        &cluster,
        Arc::new(move |path: &str, _body: &[u8]| {
            (path == "vss/zeta/round1" && !fired.swap(true, Ordering::SeqCst)).then(|| {
                (
                    reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    axum::body::Bytes::from_static(b"TT-1 sent a bad commitment"),
                )
            })
        }),
    )
    .await
    .expect_err("a refused VSS round stops the run");
    assert!(
        failed
            .to_string()
            .contains("TT-3 refused to deal its zeta VSS round 1"),
        "{failed}"
    );
}
