//! Election administration CLI: phase transitions (PM), ACC generation, tally (M4/M8).

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use referendum_poc::actors::admin::{gen_credentials, GenCredentialsConfig};
use referendum_poc::actors::load_settings;
use referendum_poc::protocol::clock::LogicalClock;
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
        /// Directory where `enrollment_packages.json` is written.
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

            let clock = LogicalClock::new(settings.clock.base_ms, settings.clock.tick_ms);

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
    }

    Ok(())
}
