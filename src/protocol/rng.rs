//! Deterministic randomness for reproducible tests and ceremonies .

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
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
#[derive(Clone)]
pub struct ActorSeed {
    seed: [u8; 32],
}

impl ActorSeed {
    /// Rebuild an actor seed from provisioned bytes (e.g. a ceremony-written
    /// `voter-{i}-seed.bin` file).
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Expose the raw seed bytes for ceremony provisioning only.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// A key derived from this seed, for authenticating an actor's own
    /// on-disk records. Never the seed itself.
    pub fn mac_key(&self) -> [u8; 32] {
        use sha3::Digest as _;
        let mut hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"referendum-poc/actor-mac-key/v1");
        sha3::Digest::update(&mut hasher, self.seed);
        hasher.finalize().into()
    }

    pub fn into_rng(self) -> ActorRng {
        ActorRng {
            seed: self.seed,
            counter: 0,
        }
    }
}

impl std::fmt::Debug for ActorSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorSeed")
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// A per-actor RNG registry.
#[derive(Clone)]
pub struct ActorRng {
    seed: [u8; 32],
    counter: u64,
}

impl std::fmt::Debug for ActorRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorRng")
            .field("seed", &"<redacted>")
            .field("counter", &self.counter)
            .finish()
    }
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

/// Derive a one-off operation RNG from an actor seed without going through the
/// stateful [`ActorRng`] counter (for services that keep their own per-purpose
/// counters, e.g. RT DVNIZKP/tau generation).
pub fn operation_rng(actor_seed: &ActorSeed, purpose: &str, counter: u64) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(derive_operation_seed(&actor_seed.seed, purpose, counter))
}

/// A DURABLE per-purpose counter for the nonces an authority draws.
///
/// A Schnorr nonce answers one challenge and one only: two responses over one
/// commitment, under two different challenges, give the secret as
/// `s = (r1 - r2)/(c1 - c2)`. An in-memory counter makes that a restart away,
/// because the stream is derived from the actor seed on disk and starts again
/// from zero, and the party that is handed both transcripts here is a PEER
/// authority (Sec. 3.9 step 15 gives every registration teller every other's
/// round-1 broadcast), which the threat model tolerates (A2).
///
/// So the counter is written to disk BEFORE the nonces are drawn: a crash
/// between the write and the proof burns a counter value, which costs
/// nothing, where the reverse order would repeat one.
#[derive(Debug)]
pub struct NonceLedger {
    path: std::path::PathBuf,
    seed: ActorSeed,
    counters: tokio::sync::Mutex<std::collections::BTreeMap<String, u64>>,
    /// Per-process salt from the operating system, mixed into every nonce
    /// when the ledger is opened for a REAL run. The counter stops a restart
    /// from repeating a nonce, but a ledger RESTORED FROM AN OLDER BACKUP
    /// carries a valid seal over stale counters and nothing on this device can
    /// tell; with fresh entropy in the stream, two processes never share a
    /// nonce whatever the counters say. `None` only under the reproducible
    /// logical clock of the test harness, where the fixtures depend on the
    /// stream (and where no board is anyone's to attack).
    salt: Option<[u8; 32]>,
}

/// The ledger as it sits on disk: the counters under this actor's MAC, so a
/// ledger written by anyone else - or for another seed - is refused.
#[derive(Serialize, Deserialize)]
struct SealedCounters {
    mac: String,
    counters: std::collections::BTreeMap<String, u64>,
}

fn counters_mac(seed: &ActorSeed, counters: &std::collections::BTreeMap<String, u64>) -> String {
    use sha3::Digest as _;
    let body = serde_json::to_vec(counters).unwrap_or_default();
    let mut hasher = sha3::Sha3_256::new();
    sha3::Digest::update(&mut hasher, b"referendum-poc/nonce-ledger/v1");
    sha3::Digest::update(&mut hasher, seed.mac_key());
    sha3::Digest::update(&mut hasher, (body.len() as u64).to_le_bytes());
    sha3::Digest::update(&mut hasher, &body);
    hex::encode(hasher.finalize())
}

impl NonceLedger {
    /// Write a fresh, empty ledger for a seed that has never drawn a nonce.
    /// Only the ceremony that mints the seed may do this: after that, a
    /// ledger that is not there means LOST, not new.
    pub async fn create(path: std::path::PathBuf, seed: ActorSeed) -> std::io::Result<Self> {
        let ledger = Self {
            path,
            seed,
            counters: tokio::sync::Mutex::new(Default::default()),
            salt: None,
        };
        ledger.persist(&Default::default()).await?;
        Ok(ledger)
    }

    /// The ceremony's synchronous form of [`NonceLedger::create`]: the empty,
    /// sealed ledger written beside the seed it belongs to, so that a teller
    /// finding no ledger knows the counters were lost rather than never used.
    pub fn create_blocking(path: &std::path::Path, seed: &ActorSeed) -> std::io::Result<()> {
        let counters = std::collections::BTreeMap::new();
        let sealed = SealedCounters {
            mac: counters_mac(seed, &counters),
            counters,
        };
        let bytes = serde_json::to_vec(&sealed).map_err(std::io::Error::other)?;
        // Never over an existing one: a ceremony re-run over a used directory
        // would zero the counters beside the very seed they pace.
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(&bytes)
    }

    /// Open the ledger at `path`. A ledger that is missing, unreadable or not
    /// sealed by this seed is an error, never an empty one: starting from zero
    /// over a seed that has already been used is exactly the failure this
    /// type exists to prevent.
    pub async fn open(
        path: std::path::PathBuf,
        seed: ActorSeed,
        fresh_entropy: bool,
    ) -> std::io::Result<Self> {
        let bytes = tokio::fs::read(&path).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "nonce ledger {} cannot be read ({e}): a missing ledger means the counters \
                     are LOST, and this seed must not draw from zero again",
                    path.display()
                ),
            )
        })?;
        let sealed: SealedCounters =
            serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        let expected = counters_mac(&seed, &sealed.counters);
        if !constant_time_eq::constant_time_eq(expected.as_bytes(), sealed.mac.as_bytes()) {
            return Err(std::io::Error::other(format!(
                "nonce ledger {} does not carry this actor's own MAC",
                path.display()
            )));
        }
        let salt = fresh_entropy.then(|| {
            use rand::RngCore as _;
            let mut salt = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            salt
        });
        Ok(Self {
            path,
            seed,
            counters: tokio::sync::Mutex::new(sealed.counters),
            salt,
        })
    }

    /// The next RNG for `purpose`, with the counter persisted FIRST.
    pub async fn next(&self, purpose: &str) -> std::io::Result<ChaCha20Rng> {
        let mut counters = self.counters.lock().await;
        let counter = counters.entry(purpose.to_string()).or_insert(0);
        let drawn = *counter;
        *counter += 1;
        self.persist(&counters).await?;
        let mut seed = derive_operation_seed(&self.seed.seed, purpose, drawn);
        if let Some(salt) = &self.salt {
            for (byte, s) in seed.iter_mut().zip(salt) {
                *byte ^= s;
            }
        }
        Ok(ChaCha20Rng::from_seed(seed))
    }

    /// Write the counters to a temporary file, flush it to disk, and rename
    /// it over the ledger: a process killed part-way leaves either the old
    /// ledger or the new one, never a torn file that nobody can read and
    /// whose only repair would put the counters back to zero.
    async fn persist(
        &self,
        counters: &std::collections::BTreeMap<String, u64>,
    ) -> std::io::Result<()> {
        let sealed = SealedCounters {
            mac: counters_mac(&self.seed, counters),
            counters: counters.clone(),
        };
        let bytes = serde_json::to_vec(&sealed).map_err(std::io::Error::other)?;
        if let Some(dir) = self.path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = tokio::fs::File::create(&tmp).await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
            file.sync_all().await?;
        }
        tokio::fs::rename(&tmp, &self.path).await
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

    /// A Schnorr nonce answers ONE challenge (A7). The seed is on disk and
    /// survives a restart, so the counter that paces it has to as well - a
    /// teller that started again from zero would answer a second challenge
    /// over the same nonce, and a peer teller, who is handed both round-1
    /// broadcasts by Sec. 3.9 step 15, could then solve for its key share.
    #[tokio::test]
    async fn a_restart_does_not_repeat_a_nonce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonce-ledger.json");
        let seed = MasterSeed::new([7u8; 32]).actor_seed("RT-1");

        assert!(
            NonceLedger::open(path.clone(), seed.clone(), false)
                .await
                .is_err(),
            "a ledger that is not there means LOST, not new"
        );
        let ledger = NonceLedger::create(path.clone(), seed.clone())
            .await
            .expect("create");
        let first = ledger.next("controls").await.expect("draw").gen::<u64>();
        let second = ledger.next("controls").await.expect("draw").gen::<u64>();
        assert_ne!(first, second);
        drop(ledger);

        // The process restarts over the same seed and the same file.
        let restarted = NonceLedger::open(path, seed, false).await.expect("reopen");
        let third = restarted.next("controls").await.expect("draw").gen::<u64>();
        assert_ne!(third, first, "a restart replayed the first nonce");
        assert_ne!(third, second);
        // Purposes are paced independently.
        let other = restarted.next("dvnizkp").await.expect("draw").gen::<u64>();
        assert_ne!(other, third);

        // A ledger sealed for another seed is refused, and a torn write never
        // happens: the file is always a whole ledger, old or new.
        let stranger = MasterSeed::new([9u8; 32]).actor_seed("RT-2");
        assert!(
            NonceLedger::open(restarted.path.clone(), stranger, false)
                .await
                .is_err(),
            "another actor's seed must not open this ledger"
        );
        assert!(!restarted.path.with_extension("json.tmp").exists());
    }

    /// A ledger restored from an older backup carries a valid seal over stale
    /// counters and nothing on the device can tell. On a real run the nonce
    /// stream therefore also carries fresh entropy from the operating system:
    /// two processes opening the SAME ledger state never draw the same nonce.
    #[tokio::test]
    async fn fresh_entropy_makes_a_rolled_back_ledger_harmless() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonce-ledger.json");
        let seed = MasterSeed::new([3u8; 32]).actor_seed("RT-1");
        NonceLedger::create(path.clone(), seed.clone())
            .await
            .expect("create");
        let backup = std::fs::read(&path).expect("backup");

        let first = NonceLedger::open(path.clone(), seed.clone(), true)
            .await
            .expect("open")
            .next("controls")
            .await
            .expect("draw")
            .gen::<u64>();
        // The operator restores the backup: the counters go back.
        std::fs::write(&path, &backup).expect("restore");
        let replayed = NonceLedger::open(path.clone(), seed.clone(), true)
            .await
            .expect("open")
            .next("controls")
            .await
            .expect("draw")
            .gen::<u64>();
        assert_ne!(first, replayed, "a rolled-back ledger replayed a nonce");

        // Without fresh entropy (the harness's reproducible mode) the same
        // rollback WOULD replay - which is why that mode never runs a real
        // election.
        std::fs::write(&path, &backup).expect("restore");
        let a = NonceLedger::open(path.clone(), seed.clone(), false)
            .await
            .expect("open")
            .next("controls")
            .await
            .expect("draw")
            .gen::<u64>();
        std::fs::write(&path, &backup).expect("restore");
        let b = NonceLedger::open(path.clone(), seed.clone(), false)
            .await
            .expect("open")
            .next("controls")
            .await
            .expect("draw")
            .gen::<u64>();
        assert_eq!(a, b);
    }

    /// The ceremony creates a ledger once. A second creation over an existing
    /// one - a setup re-run into a used directory - must fail rather than zero
    /// the counters beside the seed they pace.
    #[test]
    fn a_ledger_is_never_created_over_an_existing_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonce-ledger.json");
        let seed = MasterSeed::new([4u8; 32]).actor_seed("RT-1");
        NonceLedger::create_blocking(&path, &seed).expect("first");
        assert!(
            NonceLedger::create_blocking(&path, &seed).is_err(),
            "a re-run over an existing ledger must be refused"
        );
    }

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
