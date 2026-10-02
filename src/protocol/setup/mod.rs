//! Deterministic election setup ceremony .
//!
//! Runs the TT and RT distributed key generations, assembles the election
//! public key, and builds the `ElectionContext`. All randomness is drawn from
//! a seeded RNG so the same master seed always yields the same context hash.

pub mod artifacts;

use dlog_group::ristretto::RistrettoGroup;
use dlog_sigma_primitives::elgamal::keys::{ElGamalParams, PublicKey as ElGamalPublicKey};
use evoting::api::prelude::*;
use evoting::api::server::bb::{ElectionContext, ElectionManifest};
use evoting::api::server::rt::ThresholdRegistrationTeller;
use evoting::api::server::tt::ThresholdTabulationTeller;
use rand_core::{CryptoRng, RngCore};

use crate::configuration::ElectionSettings;

/// Output of the one-time setup ceremony.
pub struct CeremonyOutput {
    /// Public election context (contains the context hash).
    pub election_context: ElectionContext<RistrettoGroup>,
    /// One RT party per configured RT.
    pub rt_tellers: Vec<ThresholdRegistrationTeller<RistrettoGroup>>,
    /// One TT party per configured TT.
    pub tt_tellers: Vec<ThresholdTabulationTeller<RistrettoGroup>>,
    /// Master RT public key.
    pub rt_pk: RTPublicKey<RistrettoGroup>,
    /// Master TT public key embedded in `ElectionParams`.
    pub master_tt_pk: ElGamalPublicKey<RistrettoGroup>,
    /// ElGamal parameters.
    pub elgamal: ElGamalParams<RistrettoGroup>,
}

/// Errors that can occur during setup.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("invalid referendum choice parameters: {0}")]
    InvalidChoice(String),
}

/// Run the deterministic setup ceremony.
///
/// `rng` must be reproducible from the master seed (see `protocol::rng`).
/// `settings` carries the thresholds and electorate sizes.
pub fn run_ceremony<R: RngCore + CryptoRng>(
    settings: &ElectionSettings,
    rng: &mut R,
) -> Result<CeremonyOutput, SetupError> {
    // 1. TT DKG produces the tally decryption key shares and master public key.
    let elgamal = ElGamalParams::<RistrettoGroup>::new(rng);
    let (tt_tellers, master_tt_pk, teller_set) = ThresholdTabulationTeller::<RistrettoGroup>::setup(
        settings.n_tt,
        settings.t_tt,
        &elgamal,
        rng,
    );

    // 2. ElectionParams binds the ElGamal params to the master TT public key
    //    and to the tellers' public shares (every threshold decryption and
    //    blinding is held to them, teller by teller).
    let params = ElectionParams::<RistrettoGroup>::new(&elgamal, &master_tt_pk, teller_set, rng);

    // 3. RT DKG produces the credential-issuance key shares and master public key.
    let (rt_tellers, rt_pk) = ThresholdRegistrationTeller::<RistrettoGroup>::setup(
        settings.n_rt,
        settings.t_rt,
        params,
        rng,
    );

    // 4. Build the public election context.
    let manifest = ElectionManifest {
        election_id: "referendum-poc".to_string(),
        title: "Referendum Proof-of-Concept".to_string(),
        authority: "referendum-poc-authority".to_string(),
        version: 1,
    };

    // Referendum: 3 first-level options (blank / approve / reject), each with
    // a single candidate slot.
    let choice = ChoiceParameters::new(3, vec![1, 1, 1], false)
        .map_err(|e| SetupError::InvalidChoice(format!("{e:?}")))?;

    let election_context = rt_tellers[0].election_context(manifest, choice);

    Ok(CeremonyOutput {
        election_context,
        rt_tellers,
        tt_tellers,
        rt_pk,
        master_tt_pk,
        elgamal,
    })
}

/// Pseudonymous identifiers (Sec. 3.5.3): a RANDOM assignment of the integers
/// `1..=n_acc`, derived from the electoral roll's private seed so that only
/// the ER can link a voter to an identifier. Entry `i < n_voters` is the
/// identifier of the i-th registry voter; the rest are the spare identifiers
/// handed out on revocation, in this order. An identifier doubles as the
/// index of its credential, which is why the values stay within `1..=n_acc`.
pub fn assign_vids(er_seed: &crate::protocol::rng::ActorSeed, n_acc: usize) -> Vec<u64> {
    use rand::seq::SliceRandom;
    let mut vids: Vec<u64> = (1..=n_acc as u64).collect();
    let mut rng = crate::protocol::rng::operation_rng(er_seed, "vid-assignment", 0);
    vids.shuffle(&mut rng);
    vids
}

/// The "extra random strings" that stand for the holders of the spare
/// identifiers in the identifier Merkle tree (Sec. 3.5.3).
pub fn spare_holder_ids(er_seed: &crate::protocol::rng::ActorSeed, n_spares: usize) -> Vec<String> {
    use rand::RngCore;
    (0..n_spares)
        .map(|k| {
            let mut rng = crate::protocol::rng::operation_rng(er_seed, "spare-holder", k as u64);
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes);
            format!("spare-{}", hex::encode(bytes))
        })
        .collect()
}

/// Build the leaves of the identifier tree: the first `n_voters` holders are
/// the registry's voters, the rest hold spares (Sec. 3.5.3).
pub fn voter_pairs(
    holder_ids: &[String],
    vids: &[u64],
    n_voters: usize,
) -> Vec<(crate::protocol::merkle::LeafKind, String, u64)> {
    use crate::protocol::merkle::LeafKind;
    holder_ids
        .iter()
        .zip(vids.iter())
        .enumerate()
        .map(|(i, (id, vid))| {
            let kind = if i < n_voters {
                LeafKind::Voter
            } else {
                LeafKind::Spare
            };
            (kind, id.clone(), *vid)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::ElectionSettings;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_settings() -> ElectionSettings {
        ElectionSettings {
            n_rt: 3,
            t_rt: 2,
            n_tt: 3,
            t_tt: 2,
            n_bb: 2,
            n_voters: 8,
            n_acc: 10,
            t_prime: 2,
            max_casts_per_voter: 10,
            casting_token_ttl_s: 600,
            min_cast_interval_s: 0,
            tau_min_s: 2,
            tau_max_s: 5,
        }
    }

    #[test]
    fn ceremony_is_deterministic() {
        let settings = test_settings();

        let mut rng1 = ChaCha20Rng::from_seed([0u8; 32]);
        let out1 = run_ceremony(&settings, &mut rng1).unwrap();

        let mut rng2 = ChaCha20Rng::from_seed([0u8; 32]);
        let out2 = run_ceremony(&settings, &mut rng2).unwrap();

        assert_eq!(
            out1.election_context.context_hash,
            out2.election_context.context_hash
        );
    }

    #[test]
    fn context_hash_is_nonzero() {
        let settings = test_settings();
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let out = run_ceremony(&settings, &mut rng).unwrap();
        assert_ne!(out.election_context.context_hash, [0u8; 32]);
    }

    #[test]
    fn referendum_choice_has_three_options() {
        let settings = test_settings();
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let out = run_ceremony(&settings, &mut rng).unwrap();
        let choice_json = serde_json::to_value(&out.election_context.choice).unwrap();
        assert_eq!(choice_json["n1"], 3, "expected 3 first-level options");
        assert_eq!(
            choice_json["ln2"],
            serde_json::json!([1, 1, 1]),
            "expected one slot per option"
        );
    }
}

#[cfg(test)]
mod vid_assignment_tests {
    use super::*;
    use crate::protocol::rng::ActorSeed;

    #[test]
    fn identifiers_are_a_private_random_permutation() {
        let seed = ActorSeed::from_bytes([3u8; 32]);
        let vids = assign_vids(&seed, 10);
        // Every credential index is used exactly once...
        let mut sorted = vids.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (1..=10).collect::<Vec<u64>>());
        // ...not in registry order...
        assert_ne!(
            vids, sorted,
            "sequential ids would de-pseudonymise the registry"
        );
        // ...reproducibly for the ER, and differently for another seed.
        assert_eq!(vids, assign_vids(&seed, 10));
        assert_ne!(vids, assign_vids(&ActorSeed::from_bytes([4u8; 32]), 10));
    }

    #[test]
    fn spare_holders_are_distinct_random_strings() {
        let seed = ActorSeed::from_bytes([3u8; 32]);
        let holders = spare_holder_ids(&seed, 3);
        assert_eq!(holders.len(), 3);
        assert!(holders
            .iter()
            .all(|h| h.starts_with("spare-") && h.len() == 6 + 32));
        let unique: std::collections::HashSet<_> = holders.iter().collect();
        assert_eq!(unique.len(), 3);
        assert_eq!(holders, spare_holder_ids(&seed, 3));
    }
}
