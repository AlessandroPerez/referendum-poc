# Referendum PoC

A fully reproducible, HTTP-microservices proof-of-concept of a **referendum** run with the Vote App protocol, built on top of the [`evoting-rs`](https://gitlab.fbk.eu/aleph/i-voting/evoting-rs) cryptographic library and a patched fork of the [`sunlight_test`](https://github.com/elenabortolameotti/sunlight_test) Web Bulletin Board.

This is research-grade code: it demonstrates the protocol end-to-end but intentionally omits production concerns such as persistence, high availability, and a real identity provider.

## Repository layout

This repository contains only the Rust PoC crate. It depends on two sibling repositories that must be checked out into a common workspace directory:

```
voting/
├── referendum-poc/          # this repository
├── resources/
│   ├── evoting-rs/          # git@gitlab.fbk.eu:aleph/i-voting/evoting-rs.git
│   └── sunlight_test/       # https://github.com/elenabortolameotti/sunlight_test.git
```

The `Cargo.toml` in `referendum-poc` uses path dependencies that reach `../resources/evoting-rs`, so the layout above is required.

## Prerequisites

- Rust (stable toolchain)
- Go >= 1.24
- `sqlite3` CLI
- `cargo-audit` (only for the `audit` CI job / local reproduction)
- A C compiler (for the WBB's BLS dependency)

## Workspace setup

1. Create the workspace directory:

   ```bash
   mkdir voting
   cd voting
   ```

2. Clone this repository:

   ```bash
   git clone git@github.com:AlessandroPerez/referendum-poc.git
   ```

3. Clone the cryptographic library:

   ```bash
   mkdir resources
   git clone git@gitlab.fbk.eu:aleph/i-voting/evoting-rs.git resources/evoting-rs
   ```

4. Clone the WBB and switch to the PoC branch:

   ```bash
   git clone https://github.com/elenabortolameotti/sunlight_test.git resources/sunlight_test
   cd resources/sunlight_test
   git checkout referendum-poc-wbb
   cd ../..
   ```

## Build

```bash
cd referendum-poc
cargo build --all-targets
```

### WBB build caveat

The WBB depends on `supranational/blst`, which by default builds with ADX instructions. On pre-2015 CPUs without ADX this causes an illegal-instruction crash. Always build/test the WBB with the portable flag:

```bash
cd resources/sunlight_test
CGO_CFLAGS="-O2 -D__BLST_PORTABLE__" go build ./cmd/sunlight
CGO_CFLAGS="-O2 -D__BLST_PORTABLE__" go test ./internal/ctlog/...
```

The Rust test harness sets this flag automatically when spawning the WBB.

## Run the tests

```bash
cd referendum-poc
cargo test --all-targets
```

This runs unit tests and the end-to-end suite, which boots a complete cluster (WBB, authorities, voter servers) over HTTPS using a deterministic cluster CA.

## CI

The repository includes a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs:

- `cargo fmt -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all-targets`
- `cargo audit`

The CI job clones the sibling repositories into `../resources/` before building. Because `evoting-rs` is hosted on a private GitLab instance, the workflow expects a `GITLAB_TOKEN` secret (Settings -> Secrets and variables -> Actions -> New repository secret) with read access to the repository.

## Architecture overview

- **WBB** (`resources/sunlight_test`): append-only transparency log with phase-aware write policy.
- **ER / RT / TT / BB**: Rust microservices implementing the registry, registration tellers, tabulation tellers, and ballot boxes.
- **Voter server**: per-voter backend that serves a vanilla-JS SPA.
- **Admin / Auditor CLIs**: drive the ceremony, election phases, and universal verification.

For the full protocol mapping, design decisions, and deviation register, see the project roadmap (kept outside this code repository).

## License

See the upstream repositories for licensing terms.
