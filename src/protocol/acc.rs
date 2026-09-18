//! Anonymous credential (ACC) generation for the registration tellers (Sec. 3.5.4).
//!
//! This module drives the distributed ACC protocol from Sec. 3.5.4 of the
//! manuscript.  It is framework-free: all crypto runs synchronously and the
//! caller decides whether to wrap it in `spawn_blocking`.

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::{GroupPoint, GroupScalar};
use dlog_group::ristretto::RistrettoGroup;
use dlog_group::serde::{PointHelper, ScalarHelper};
use dlog_sigma_primitives::elgamal::ciphertext::{Ciphertext, ExtendedCiphertext};
use evoting::api::prelude::{voter_build_acc, RTPublicKey, ShortPublicACC};
use evoting::api::server::bb::ElectionContext;
use evoting::api::server::rt::{AccShareBroadcast, RTSecretKeyShare, ThresholdRegistrationTeller};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// Convenience alias for the concrete group used throughout the PoC.
type G = RistrettoGroup;

/// Errors that can occur during ACC generation or share loading.
#[derive(Debug, thiserror::Error)]
pub enum AccError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid scalar bytes in share file")]
    InvalidScalar,
    #[error("credential share file {0}")]
    ShareFile(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("share index mismatch: expected {expected}, got {got}")]
    ShareIndexMismatch { expected: usize, got: usize },
}

impl From<evoting::error::Error> for AccError {
    fn from(e: evoting::error::Error) -> Self {
        Self::Crypto(format!("{e:?}"))
    }
}

/// On-disk representation of an RT key share (matches the ceremony output).
#[derive(Debug, serde::Deserialize)]
struct RtShareFile {
    id: usize,
    secret_scalar_share: String,
    local_y_contrib: String,
    meg_sk1_share: String,
    meg_sk2_share: String,
}

/// A serializable wrapper around `ExtendedCiphertext` so enrollment packages
/// can be persisted as JSON while keeping the randomness needed to rebuild
/// the extended ciphertext later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableExtendedCiphertext {
    pub inner: Ciphertext<G>,
    #[serde(with = "ScalarHelper::<G>")]
    pub random_scalar: <G as GroupScalar>::Scalar,
}

impl From<ExtendedCiphertext<G>> for SerializableExtendedCiphertext {
    fn from(ext: ExtendedCiphertext<G>) -> Self {
        Self {
            inner: ext.inner,
            random_scalar: *ext.random_scalar.expose(),
        }
    }
}

impl From<SerializableExtendedCiphertext> for ExtendedCiphertext<G> {
    fn from(ext: SerializableExtendedCiphertext) -> Self {
        use dlog_sigma_primitives::elgamal::keys::SecretScalar;
        Self {
            inner: ext.inner,
            random_scalar: SecretScalar(ext.random_scalar),
        }
    }
}

/// Per-credential enrollment material stored by the ER for the voter
/// enrollment phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentPackage {
    /// The credential point `A` recovered by threshold decryption.
    #[serde(with = "PointHelper::<G>")]
    pub a: <G as GroupPoint>::Point,
    /// `E_pkTT[A]` produced by the RTs, including the effective randomness.
    pub enc_a_ext: SerializableExtendedCiphertext,
    /// One `AccShareBroadcast` per RT.  Any `t_RT` of them suffice for the
    /// voter to rebuild the credential.
    pub share_broadcasts: Vec<AccShareBroadcast<G>>,
}

impl EnrollmentPackage {
    fn new(
        a: <G as GroupPoint>::Point,
        enc_a_ext: ExtendedCiphertext<G>,
        shares: Vec<AccShareBroadcast<G>>,
    ) -> Self {
        Self {
            a,
            enc_a_ext: enc_a_ext.into(),
            share_broadcasts: shares,
        }
    }

    /// The subset of the package the ER hands to the voter at login.
    pub fn credential_package(&self) -> CredentialPackage {
        CredentialPackage {
            a: self.a,
            enc_a_ext: self.enc_a_ext.clone(),
        }
    }
}

/// What ONE registration teller stores for one credential: the public
/// credential point `A` and that teller's OWN share - never another teller's
/// (Sec. 3.5.4: each RT_i privately stores its tuple). With fewer than t_RT of
/// these files nobody can rebuild a credential or a PIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtCredentialShare {
    /// The credential point `A` (public: it is part of the published ACC).
    #[serde(with = "PointHelper::<G>")]
    pub a: <G as GroupPoint>::Point,
    /// This teller's share broadcast for the credential.
    pub share: AccShareBroadcast<G>,
}

/// File (under the ceremony's `output/`) with the ER's view of every
/// credential: `A` and `E[A]` only, no teller share.
pub const ER_CREDENTIALS_FILE: &str = "er_credential_packages.json";

/// File (under the ceremony's `output/`) with teller `rt_id`'s own shares.
pub fn rt_shares_file(rt_id: usize) -> String {
    format!("rt-{rt_id}-credential_shares.json")
}

/// Parse and police a teller's share file: every share must be the teller's
/// own and there must be exactly one per credential.
pub fn parse_rt_credential_shares(
    bytes: &[u8],
    rt_id: usize,
    n_acc: usize,
) -> Result<Vec<RtCredentialShare>, AccError> {
    let shares: Vec<RtCredentialShare> = serde_json::from_slice(bytes)
        .map_err(|e| AccError::ShareFile(format!("cannot parse credential shares: {e}")))?;
    if let Some(foreign) = shares.iter().find(|c| c.share.from_id != rt_id) {
        return Err(AccError::ShareFile(format!(
            "holds a share of RT-{}: refusing to load another teller's share",
            foreign.share.from_id
        )));
    }
    if shares.len() != n_acc {
        return Err(AccError::ShareFile(format!(
            "holds {} shares, the election has {n_acc} credentials",
            shares.len()
        )));
    }
    Ok(shares)
}

impl EnrollmentPackage {
    /// Teller `rt_id`'s view of this credential, if it holds a share of it.
    pub fn rt_share(&self, rt_id: usize) -> Option<RtCredentialShare> {
        self.share_broadcasts
            .iter()
            .find(|s| s.from_id == rt_id)
            .map(|share| RtCredentialShare {
                a: self.a,
                share: share.clone(),
            })
    }

    /// Ids of the tellers that hold a share of this credential.
    pub fn rt_ids(&self) -> Vec<usize> {
        self.share_broadcasts.iter().map(|s| s.from_id).collect()
    }
}

/// The part of an enrollment package the voter receives from the ER at login.
///
/// The per-RT `AccShareBroadcast`s are deliberately absent: the voter fetches
/// those over HTTPS from >= t_RT registration tellers (`/credentials/deliver`),
/// per README deviation 5 and Sec. 3.6.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPackage {
    /// The credential point `A` recovered by threshold decryption.
    #[serde(with = "PointHelper::<G>")]
    pub a: <G as GroupPoint>::Point,
    /// `E_pkTT[A]` produced by the RTs, including the effective randomness.
    pub enc_a_ext: SerializableExtendedCiphertext,
}

/// Load a single RT share from the JSON file written by the setup ceremony.
pub fn load_rt_share(path: &Path) -> Result<RTSecretKeyShare<G>, AccError> {
    let bytes = std::fs::read(path)?;
    let file: RtShareFile = serde_json::from_slice(&bytes)?;

    let decode_scalar = |s: &str| -> Result<<G as GroupScalar>::Scalar, AccError> {
        let bytes = BASE64.decode(s)?;
        G::scalar_from_bytes(&bytes).ok_or(AccError::InvalidScalar)
    };

    Ok(RTSecretKeyShare {
        id: file.id,
        secret_scalar_share: decode_scalar(&file.secret_scalar_share)?,
        local_y_contrib: decode_scalar(&file.local_y_contrib)?,
        meg_sk1_share: decode_scalar(&file.meg_sk1_share)?,
        meg_sk2_share: decode_scalar(&file.meg_sk2_share)?,
    })
}

/// Reconstruct an in-process `ThresholdRegistrationTeller` from a saved share.
///
/// This keeps the RT secret distributed: no single party reconstructs the
/// master secret, and the teller is only rebuilt inside the process that owns
/// the share.
pub fn reconstruct_rt_teller(
    share: RTSecretKeyShare<G>,
    election_context: &ElectionContext<G>,
    rt_pk: &RTPublicKey<G>,
) -> ThresholdRegistrationTeller<G> {
    ThresholdRegistrationTeller::from_share(share, election_context.pk.clone(), rt_pk)
}

/// Generate `n_acc` credentials and the public ACC list.
///
/// `tellers` must contain the reconstructed tellers for all `n_rt` parties.
/// `t` is the outer reconstruction threshold (`t_rt`); `t_prime` is the inner
/// threshold for the `a`/`b` polynomials (`t'_rt`).  The caller supplies the
/// RNG; for reproducible ceremonies the RNG must itself be seeded
/// deterministically.
pub fn generate_credentials(
    n_acc: usize,
    t: usize,
    t_prime: usize,
    tellers: &mut [ThresholdRegistrationTeller<G>],
    election_context: &ElectionContext<G>,
    rt_pk: &RTPublicKey<G>,
    rng: &mut ChaCha20Rng,
) -> Result<(Vec<EnrollmentPackage>, Vec<ShortPublicACC<G>>), AccError> {
    let n = tellers.len();

    let mut packages = Vec::with_capacity(n_acc);
    let mut short_accs = Vec::with_capacity(n_acc);

    for _ in 0..n_acc {
        // Round 1: each RT generates its VSS broadcast.
        let mut generators = Vec::with_capacity(n);
        let mut vss_broadcasts = Vec::with_capacity(n);
        for teller in tellers.iter_mut() {
            let (gen, bcast) = teller.acc_gen_round1(n, t, t_prime, rng);
            generators.push(gen);
            vss_broadcasts.push(bcast);
        }

        // Round 2: process VSS broadcasts and compute delta_i / share broadcasts.
        let mut delta_broadcasts = Vec::with_capacity(n);
        let mut share_broadcasts = Vec::with_capacity(n);
        for (teller, gen) in tellers.iter_mut().zip(generators.iter_mut()) {
            let (delta, share) = teller.acc_gen_round2(gen, &vss_broadcasts, rng)?;
            delta_broadcasts.push(delta);
            share_broadcasts.push(share);
        }

        // Threshold-combine E[g3^{x_i}] shares from at least t_RT tellers.
        // Each party proves its ciphertext encodes the correct g3^{x_i} share.
        let x_shares: Vec<_> = share_broadcasts.iter().map(|s| s.x_share).collect();
        let mut enc_gx3_broadcasts = Vec::with_capacity(t);
        for (teller, x_share) in tellers.iter().zip(x_shares.iter()).take(t) {
            enc_gx3_broadcasts.push(teller.gen_enc_gx3_share(*x_share, rng));
        }
        let enc_gx3 = ThresholdRegistrationTeller::<G>::combine_enc_gx3_shares(
            &election_context.pk,
            rt_pk,
            &vss_broadcasts,
            &enc_gx3_broadcasts,
        )?;

        // Round 3: each RT outputs a partial ciphertext.
        let mut ct_shares = Vec::with_capacity(n);
        for (teller, gen) in tellers.iter_mut().zip(generators.iter_mut()) {
            let ct = teller.acc_gen_round3(gen, &vss_broadcasts, &delta_broadcasts, &enc_gx3)?;
            ct_shares.push((teller.id, ct));
        }

        // Combine partial ciphertexts and threshold-decrypt to recover A.
        let enc_a = ThresholdRegistrationTeller::<G>::combine_acc_ciphertexts(&ct_shares)?;
        let partials: Vec<_> = tellers
            .iter()
            .map(|t| t.partial_decrypt_acc_ciphertext(&enc_a))
            .collect();
        let a = ThresholdRegistrationTeller::<G>::combine_acc_decryptions(&enc_a, &partials);

        // Re-encrypt A under the TT public key.
        let mut enc_a_broadcasts = Vec::with_capacity(n);
        for teller in tellers.iter_mut() {
            enc_a_broadcasts.push(teller.gen_enc_a_share(a, rng));
        }
        let enc_a_ext = ThresholdRegistrationTeller::<G>::combine_enc_a_shares(
            &election_context.pk,
            a,
            &enc_a_broadcasts,
        )?;

        // Build the public ACC so we can publish the short form.  The voter
        // will rerun `voter_build_acc` during enrollment with the same
        // material; the public list only needs the encrypted credential.
        let (_builder, _pin, public_acc) = voter_build_acc(
            &election_context.pk,
            rt_pk,
            a,
            enc_a_ext.clone(),
            &share_broadcasts,
            rng,
        );
        let short = tellers[0].short_public_acc(&public_acc)?;

        packages.push(EnrollmentPackage::new(a, enc_a_ext, share_broadcasts));
        short_accs.push(short);
    }

    Ok((packages, short_accs))
}

/// WBB staging threshold for RT-role entries (matches the fork's
/// hardcoded `setup,RT,acc_pub_key,t>=2` policy row).  Distinct from the
/// crypto thresholds `t_rt`/`t'`, which they merely happen to equal.
pub const WBB_RT_STAGING_THRESHOLD: usize = 2;

/// Build the WBB data string for the `setup,RT,acc_pub_key,2,...` entry.
///
/// The content (the JSON-encoded `ShortPublicACC` list) is base64-encoded so
/// the CSV payload does not contain commas.
pub fn build_acc_pub_key_data_string(short_accs: &[ShortPublicACC<G>]) -> Result<String, AccError> {
    let json = serde_json::to_string(short_accs)?;
    Ok(format!(
        "setup,RT,acc_pub_key,{},{}",
        WBB_RT_STAGING_THRESHOLD,
        BASE64.encode(json.as_bytes())
    ))
}

/// Derive a deterministic ACC-generation RNG from the RT operation seeds
/// (`rt-{i}-seed.bin`).
///
/// Hashing the three dedicated operation seeds together yields a seed that is
/// available to the admin driver without requiring the master seed, and keeps
/// credential randomness decoupled from the WBB entry-signing keys.
pub fn acc_rng_from_seeds(seeds: &[[u8; 32]]) -> ChaCha20Rng {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(b"acc-generation");
    ChaCha20Rng::from_seed(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::ElectionSettings;
    use crate::protocol::setup::run_ceremony;
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
    fn acc_generation_produces_n_acc_packages_and_short_accs() {
        let settings = test_settings();
        let mut rng = ChaCha20Rng::from_seed([0xabu8; 32]);
        let ceremony = run_ceremony(&settings, &mut rng).unwrap();

        let mut tellers: Vec<_> = ceremony.rt_tellers;

        let mut acc_rng = ChaCha20Rng::from_seed([0xcdu8; 32]);
        let (packages, short_accs) = generate_credentials(
            settings.n_acc,
            settings.t_rt,
            settings.t_prime,
            &mut tellers,
            &ceremony.election_context,
            &ceremony.rt_pk,
            &mut acc_rng,
        )
        .unwrap();

        assert_eq!(packages.len(), settings.n_acc);
        assert_eq!(short_accs.len(), settings.n_acc);
        // Every package has one share broadcast per RT.
        for pkg in &packages {
            assert_eq!(pkg.share_broadcasts.len(), settings.n_rt);
        }
    }
}
