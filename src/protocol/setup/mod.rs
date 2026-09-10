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
    let (tt_tellers, master_tt_pk) = ThresholdTabulationTeller::<RistrettoGroup>::setup(
        settings.n_tt,
        settings.t_tt,
        &elgamal,
        rng,
    );

    // 2. ElectionParams binds the ElGamal params to the master TT public key.
    let params = ElectionParams::<RistrettoGroup>::new(&elgamal, &master_tt_pk, rng);

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

/// Deterministic VID assignment: assign `1..=n_voters` to the registry order.
pub fn assign_vids(n_voters: usize) -> Vec<u64> {
    (1..=n_voters as u64).collect()
}

/// Build the (id, vid) pairs used for the Merkle root from the DIP registry.
pub fn voter_pairs(voter_ids: &[String], vids: &[u64]) -> Vec<(String, u64)> {
    voter_ids
        .iter()
        .zip(vids.iter())
        .map(|(id, vid)| (id.clone(), *vid))
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
