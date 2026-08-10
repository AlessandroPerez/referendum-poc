//! Election administration CLI: phase transitions (PM), ACC generation, tally (M4/M8).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    referendum_poc::actors::run_stub("election-admin").await
}
