//! Trusted setup ceremony (M3.5).
//!
//! Generates entity keys, RT/TT DKG share files, election context, seed.bin,
//! sunlight.yaml, checkpoints.db, cluster CA + per-service TLS certs, and
//! per-service configuration files.

use std::path::PathBuf;

use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use referendum_poc::actors::load_settings;
use referendum_poc::protocol::rng::MasterSeed;
use referendum_poc::protocol::setup::artifacts::write_artifacts;
use referendum_poc::protocol::setup::run_ceremony;
use secrecy::ExposeSecret;

#[derive(Parser, Debug)]
#[command(name = "setup-ceremony")]
struct Args {
    /// Directory containing configuration/base.yaml.
    #[arg(short, long, default_value = ".")]
    config: PathBuf,

    /// Output directory for all ceremony artifacts.
    #[arg(short, long, default_value = "./ceremony")]
    output: PathBuf,

    /// Optional 64-hex-character master seed. Overrides any seed in config.
    #[arg(short, long)]
    master_seed: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let settings = load_settings(&args.config)?;

    let master_seed_hex = args
        .master_seed
        .as_deref()
        .unwrap_or_else(|| settings.seeds.master_seed.expose_secret());
    let master_seed = MasterSeed::from_hex(master_seed_hex)?;

    // Deterministic RNG seeded from the master seed.
    let mut rng = {
        let mut seed = [0u8; 32];
        master_seed.expose(|s| seed.copy_from_slice(s));
        ChaCha20Rng::from_seed(seed)
    };

    let ceremony = run_ceremony(&settings.election, &mut rng)?;
    let paths = write_artifacts(
        &args.output,
        &settings,
        &ceremony,
        &master_seed,
        &settings.dip,
    )?;

    println!(
        "Ceremony artifacts written to {}",
        paths.output_dir.display()
    );
    println!(
        "  context hash: {}",
        hex::encode(ceremony.election_context.context_hash)
    );
    println!(
        "  election_context: {}",
        paths.election_context_json.display()
    );
    println!("  seed.bin: {}", paths.seed_bin.display());
    println!("  sunlight.yaml: {}", paths.sunlight_yaml.display());

    Ok(())
}
