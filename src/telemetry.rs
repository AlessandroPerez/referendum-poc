//! Telemetry: `tracing` with a Bunyan JSON formatter,
//! environment-driven filtering, and a once-per-process test initializer.

use std::sync::LazyLock;

use tracing::{subscriber::set_global_default, Subscriber};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, EnvFilter, Registry};

/// Compose a subscriber: EnvFilter (RUST_LOG, falling back to `env_filter`)
/// + JSON storage + Bunyan formatting to `sink`.
pub fn get_subscriber<Sink>(
    name: String,
    env_filter: String,
    sink: Sink,
) -> impl Subscriber + Send + Sync
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));
    let formatting_layer = BunyanFormattingLayer::new(name, sink);
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

/// Register the subscriber globally and redirect legacy `log` records.
///
/// Panics if called twice - by design (called once at process start).
pub fn init_subscriber(subscriber: impl Subscriber + Send + Sync) {
    LogTracer::init().expect("failed to set logger");
    set_global_default(subscriber).expect("failed to set subscriber");
}

/// Test telemetry, initialized at most once per test process (Sec. 04).
/// Set `TEST_LOG=1` to emit to stdout, otherwise logs go to a sink.
pub static TEST_TRACING: LazyLock<()> = LazyLock::new(|| {
    let (sink_name, filter) = ("test", "debug");
    if std::env::var("TEST_LOG").is_ok() {
        init_subscriber(get_subscriber(
            sink_name.into(),
            filter.into(),
            std::io::stdout,
        ));
    } else {
        init_subscriber(get_subscriber(
            sink_name.into(),
            filter.into(),
            std::io::sink,
        ));
    }
});

/// Force-initialize test telemetry. Call first in every test harness entrypoint.
pub fn init_test_tracing() {
    LazyLock::force(&TEST_TRACING);
}
