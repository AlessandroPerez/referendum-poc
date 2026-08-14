//! Deterministic randomness for reproducible tests and ceremonies (roadmap §9).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, Secret};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// A 32-byte master seed.
#[derive(Clone, Debug)]
pub struct MasterSeed(Secret<[u8; 32]>);

impl MasterSeed {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Secret::new(seed))
    }

    pub fn from_hex(hex: &str) -> Result<Self, RngError> {
        if hex.len() != 64 {
            return Err(RngError::InvalidHexLength(hex.len()));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes).map_err(RngError::InvalidHex)?;
        Ok(Self::new(bytes))
    }

    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        f(self.0.expose_secret())
    }

    pub fn actor_seed(&self, actor_id: &str) -> ActorSeed {
        self.expose(|master| derive_actor_seed(master, actor_id))
    }
}

/// Per-actor deterministic RNG source.
#[derive(Clone, Debug)]
pub struct ActorSeed {
    seed: [u8; 32],
}

impl ActorSeed {
    pub fn into_rng(self) -> ActorRng {
        ActorRng {
            seed: self.seed,
            counter: 0,
        }
    }
}

/// A per-actor RNG registry.
#[derive(Clone, Debug)]
pub struct ActorRng {
    seed: [u8; 32],
    counter: u64,
}

impl ActorRng {
    pub fn next(&mut self, purpose: &str) -> ChaCha20Rng {
        let seed = derive_operation_seed(&self.seed, purpose, self.counter);
        self.counter += 1;
        ChaCha20Rng::from_seed(seed)
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

fn derive_actor_seed(master: &[u8; 32], actor_id: &str) -> ActorSeed {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, master);
    Update::update(&mut hasher, b"actor");
    Update::update(&mut hasher, actor_id.as_bytes());
    ActorSeed {
        seed: shake256_to_array(hasher),
    }
}

fn derive_operation_seed(actor_seed: &[u8; 32], purpose: &str, counter: u64) -> [u8; 32] {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, actor_seed);
    Update::update(&mut hasher, purpose.as_bytes());
    Update::update(&mut hasher, &counter.to_le_bytes());
    shake256_to_array(hasher)
}

fn shake256_to_array(hasher: Shake256) -> [u8; 32] {
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    XofReader::read(&mut reader, &mut out);
    out
}

#[derive(Debug, thiserror::Error)]
pub enum RngError {
    #[error("master seed hex must be 64 characters, got {0}")]
    InvalidHexLength(usize),
    #[error("invalid hex in master seed: {0}")]
    InvalidHex(#[from] hex::FromHexError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn master_seed_from_hex_roundtrips() {
        let seed = MasterSeed::new([42u8; 32]);
        let hex = "2a".repeat(32);
        let parsed = MasterSeed::from_hex(&hex).unwrap();
        seed.expose(|a| parsed.expose(|b| assert_eq!(a, b)));
    }

    #[test]
    fn same_inputs_yield_same_rng_stream() {
        let master = MasterSeed::new([1u8; 32]);
        let mut rng_a_1 = master.actor_seed("ER-1").into_rng();
        let mut rng_a_2 = master.actor_seed("ER-1").into_rng();
        let mut rng_b = master.actor_seed("RT-1").into_rng();

        let a_first = rng_a_1.next("ceremony").gen::<u64>();
        let a_first_copy = rng_a_2.next("ceremony").gen::<u64>();
        assert_eq!(a_first, a_first_copy);

        let b_first = rng_b.next("ceremony").gen::<u64>();
        assert_ne!(a_first, b_first);

        let a_second = rng_a_1.next("ceremony").gen::<u64>();
        assert_ne!(a_first, a_second);
        assert_eq!(rng_a_1.counter(), 2);
    }
}
