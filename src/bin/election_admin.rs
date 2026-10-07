//! Election administration CLI: phase transitions (PM), ACC generation, tally .

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use referendum_poc::actors::admin::{
    gen_credentials, run_tally, transition_phase, GenCredentialsConfig, PhaseTransitionConfig,
    TallyConfig,
};
use referendum_poc::actors::load_settings;
use referendum_poc::protocol::clock::Clock;
use reqwest::Url;
use secrecy::SecretString;

#[derive(Parser)]
#[command(name = "election-admin")]
#[command(about = "Election administration coordinator")]
struct Cli {
    /// Directory containing `configuration/base.yaml` and ceremony artifacts.
    #[arg(short, long, default_value = ".")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate anonymous credentials and publish the signed acc_pub_key WBB entry.
    GenCredentials {
        /// Directory where the ER credential file and the per-RT share files are written.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// WBB log base URL (overrides configuration).
        #[arg(long)]
        wbb_url: Option<Url>,

        /// Comma-separated RT `/sign` endpoint URLs. If omitted, the admin
        /// signs the entry locally using the RT signing key files.
        #[arg(long, value_delimiter = ',')]
        rt_urls: Vec<Url>,
    },

    /// Publish the PM phase transition `setup -> voting` (Sec. 3.4.2, A4).
    OpenVoting {
        /// WBB log base URL (overrides configuration).
        #[arg(long)]
        wbb_url: Option<Url>,
    },

    /// Publish the PM phase transition `voting -> tallying` (Sec. 3.4.2, A4).
    CloseVoting {
        /// WBB log base URL (overrides configuration).
        #[arg(long)]
        wbb_url: Option<Url>,
    },

    /// Run the full Sec. 3.9 tally pipeline over HTTP and publish all artifacts (A5).
    Tally {
        /// WBB log base URL (overrides configuration).
        #[arg(long)]
        wbb_url: Option<Url>,
        /// Ballot box ids to tally without when they give no release
        /// (Sec. 3.9 step 4); comma separated, e.g. `--proceed-without 2,3`.
        #[arg(long, value_delimiter = ',')]
        proceed_without: Vec<u64>,
    },

    /// Print the final counts from the WBB `tally_result` entry (V15 support).
    Results {
        /// WBB log base URL (overrides configuration).
        #[arg(long)]
        wbb_url: Option<Url>,
    },
}

/// Collect the `base_url`s of peers named `{prefix}-1..n`, in index order.
fn peer_urls(
    settings: &referendum_poc::configuration::Settings,
    prefix: &str,
) -> anyhow::Result<Vec<Url>> {
    let mut peers: Vec<_> = settings
        .peers
        .iter()
        .filter(|p| p.name.starts_with(&format!("{prefix}-")))
        .collect();
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    if peers.is_empty() {
        anyhow::bail!("no {prefix}-* peers configured");
    }
    peers
        .iter()
        .map(|p| {
            Url::parse(&p.base_url)
                .map_err(|e| anyhow::anyhow!("invalid base_url for {}: {e}", p.name))
        })
        .collect()
}

/// Shared plumbing for the PM phase-transition subcommands.
async fn run_transition(
    settings: &referendum_poc::configuration::Settings,
    config_dir: &std::path::Path,
    wbb_url: Option<Url>,
    from: &str,
    to: &str,
) -> anyhow::Result<()> {
    let ceremony_dir = std::path::PathBuf::from(&settings._ceremony.election_context)
        .parent()
        .unwrap_or(config_dir)
        .to_path_buf();
    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let wbb_url = match wbb_url {
        Some(url) => url,
        None => Url::parse(&settings.wbb.base_url)
            .map_err(|e| anyhow::anyhow!("invalid wbb.base_url: {e}"))?,
    };
    transition_phase(
        PhaseTransitionConfig {
            ceremony_dir,
            wbb_url,
            ca_pem,
            clock: Clock::from_settings(&settings.clock),
        },
        from,
        to,
    )
    .await?;
    println!("phase transition {from} -> {to} published");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    referendum_poc::telemetry::init_subscriber(referendum_poc::telemetry::get_subscriber(
        "election-admin".into(),
        "info".into(),
        std::io::stdout,
    ));

    let cli = Cli::parse();
    let settings = load_settings(&cli.config)?;

    match cli.command {
        Command::GenCredentials {
            output,
            wbb_url,
            rt_urls,
        } => {
            let ceremony_dir = std::path::PathBuf::from(&settings._ceremony.election_context)
                .parent()
                .unwrap_or(&cli.config)
                .to_path_buf();
            let output_dir = output.unwrap_or_else(|| ceremony_dir.join("output"));

            let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
                .await
                .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;

            let wbb_url = wbb_url.unwrap_or_else(|| {
                Url::parse(&settings.wbb.base_url)
                    .expect("configuration wbb.base_url must be a valid URL")
            });

            let rt_urls = if rt_urls.is_empty() {
                None
            } else {
                Some(rt_urls)
            };
            let rt_tokens = if let Some(urls) = rt_urls.as_ref() {
                let mut tokens = Vec::with_capacity(urls.len());
                for (i, _url) in urls.iter().enumerate() {
                    let path = ceremony_dir.join(format!("rt-{}-service-token.txt", i + 1));
                    let token = tokio::fs::read_to_string(&path)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("failed to read service token {}: {e}", path.display())
                        })?
                        .trim()
                        .to_string();
                    tokens.push(SecretString::new(token));
                }
                Some(tokens)
            } else {
                None
            };

            let clock = Clock::from_settings(&settings.clock);

            gen_credentials(GenCredentialsConfig {
                ceremony_dir,
                output_dir,
                n_acc: settings.election.n_acc,
                t_rt: settings.election.t_rt,
                t_prime: settings.election.t_prime,
                wbb_url,
                rt_urls,
                rt_tokens,
                ca_pem,
                clock,
            })
            .await?;
        }
        Command::OpenVoting { wbb_url } => {
            run_transition(&settings, &cli.config, wbb_url, "setup", "voting").await?;
        }
        Command::CloseVoting { wbb_url } => {
            run_transition(&settings, &cli.config, wbb_url, "voting", "tallying").await?;
        }
        Command::Tally {
            wbb_url,
            proceed_without,
        } => {
            let ceremony_dir = std::path::PathBuf::from(&settings._ceremony.election_context)
                .parent()
                .unwrap_or(&cli.config)
                .to_path_buf();
            let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
                .await
                .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
            let wbb_url = match wbb_url {
                Some(url) => url,
                None => Url::parse(&settings.wbb.base_url)
                    .map_err(|e| anyhow::anyhow!("invalid wbb.base_url: {e}"))?,
            };
            let outcome = run_tally(TallyConfig {
                ceremony_dir,
                wbb_url,
                er_url: Url::parse(&settings.er.base_url)
                    .map_err(|e| anyhow::anyhow!("invalid er.base_url: {e}"))?,
                bb_urls: peer_urls(&settings, "bb")?,
                rt_urls: peer_urls(&settings, "rt")?,
                tt_urls: peer_urls(&settings, "tt")?,
                ca_pem,
                clock: Clock::from_settings(&settings.clock),
                n_acc: settings.election.n_acc,
                t_tt: settings.election.t_tt,
                t_rt: settings.election.t_rt,
                proceed_without,
            })
            .await?;
            println!(
                "tally complete: blank={} approve={} reject={} (released={} reconciled={} deduped={} valid={} legitimate={})",
                outcome.counts.blank,
                outcome.counts.si,
                outcome.counts.no,
                outcome.released,
                outcome.reconciled,
                outcome.deduped,
                outcome.valid,
                outcome.legitimate,
            );
        }
        Command::Results { wbb_url } => {
            let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
                .await
                .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
            let wbb_url = match wbb_url {
                Some(url) => url,
                None => Url::parse(&settings.wbb.base_url)
                    .map_err(|e| anyhow::anyhow!("invalid wbb.base_url: {e}"))?,
            };
            let client = referendum_poc::protocol::tls::reqwest_client_trusting_ca(&ca_pem)?;
            let wbb = referendum_poc::clients::wbb::WbbClient::new(client, wbb_url);
            let entries = wbb
                .entries()
                .await
                .map_err(|e| anyhow::anyhow!("WBB read failed: {e}"))?;
            let mut counts: Option<referendum_poc::protocol::tally::TallyCounts> = None;
            for sequenced in &entries.entries {
                let Some(data_b64) = sequenced.entry.get("data").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Ok(data) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_b64)
                else {
                    continue;
                };
                if let Some(parsed) = referendum_poc::protocol::voting::parse_wbb_data(&data) {
                    if parsed.entry_type == "tally_result" {
                        counts = Some(parsed.decode_payload()?);
                    }
                }
            }
            match counts {
                Some(counts) => println!(
                    "results: blank={} approve={} reject={}",
                    counts.blank, counts.si, counts.no
                ),
                None => anyhow::bail!("no tally_result entry on the WBB (tally not run yet?)"),
            }
        }
    }

    Ok(())
}
