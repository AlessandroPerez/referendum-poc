# Referendum PoC

A fully reproducible, HTTPS-microservices proof-of-concept of a **referendum** run with the Vote App protocol (PhD manuscript, Ch. 3 with the §3.11 referendum optimization), built on top of the [`evoting-rs`](https://gitlab.fbk.eu/aleph/i-voting/evoting-rs) cryptographic library and a patched fork of the [`sunlight_test`](https://github.com/elenabortolameotti/sunlight_test) Web Bulletin Board.

This is research-grade code: it demonstrates the protocol end-to-end but intentionally omits production concerns such as persistence, high availability, and a real identity provider.

## Architecture

Every service is an `axum` HTTPS server (rustls in-app TLS, certificates issued by a deterministic cluster CA that is the *only* trust anchor for every client). The Web Bulletin Board is the patched Go `sunlight` fork, serving TLS via its `-testcert` mode with ceremony-issued certificates.

| Component | Count | Role | Demo port |
|---|---|---|---|
| WBB (`sunlight`) | 1 | append-only transparency log, phase-aware write policy | 8090 |
| `er-server` | 1 | electoral roll: login, enrollment packages, tokens, revocation, eligible vids | 8001 |
| `dip-server` | 1 | identity-provider stub (signed assertions) | 8002 |
| `ns-server` | 1 | notification-service stub (PIN readiness) | 8003 |
| `rt-server` | 3 (t=2) | registration tellers: credential shares, DVNIZKP, tally controls | 8011–8013 |
| `tt-server` | 3 (t=2) | tabulation tellers: WBB co-signing, ζ-VSS, threshold decryption | 8021–8023 |
| `bb-server` | 2 | ballot boxes: CAT-verified intake, CAI, ballot release | 8031–8032 |
| `voter-server` + SPA | per voter | voter backend serving a vanilla-JS app | 9001–9003 |
| `wbb-ui` | 1 | public bulletin-board page (V14 manual verification) | 9100 |

CLIs: `setup-ceremony` (trusted setup: DKGs, entity keys, TLS material, per-service configs), `election-admin` (`gen-credentials`, `open-voting`, `close-voting`, `tally`, `results`) and `referendum-auditor` (§3.10 universal verification from the log alone, using only PUBLIC verifying keys).

## Repository layout

This repository contains only the Rust PoC crate. It depends on two sibling repositories that must be checked out into a common workspace directory:

```
voting/
├── referendum-poc/          # this repository
├── resources/
│   ├── evoting-rs/          # git@gitlab.fbk.eu:aleph/i-voting/evoting-rs.git (branch referendum-poc)
│   └── sunlight_test/       # https://github.com/elenabortolameotti/sunlight_test.git (branch referendum-poc-wbb)
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

3. Clone the cryptographic library (branch `referendum-poc`):

   ```bash
   mkdir resources
   git clone --branch referendum-poc git@gitlab.fbk.eu:aleph/i-voting/evoting-rs.git resources/evoting-rs
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

The Rust test harness and `scripts/demo.sh` set this flag automatically when building the WBB.

## Run the demo

```bash
cd referendum-poc
./scripts/demo.sh
```

The script builds everything, runs the setup ceremony, and boots the full cluster (WBB + all authorities + three voter apps + the public bulletin-board page). Open a voter app (e.g. `https://127.0.0.1:9001/`, fiscal id `VOTER-001`), enroll, wait for the PIN, vote and cast. The certificates come from the demo cluster CA, so accept the browser warning (test-only PKI).

Cast **at least 3 ballots** (the tally's verifiable mixes require it), then in another terminal:

```bash
./target/debug/election-admin -c demo-ceremony close-voting
./target/debug/election-admin -c demo-ceremony tally
./target/debug/election-admin -c demo-ceremony results
./target/debug/referendum-auditor -c demo-ceremony
```

`Ctrl-C` stops the cluster.

## Reproduce the tests

```bash
cd referendum-poc
cargo test --all-targets              # add CGO_CFLAGS="-O2 -D__BLST_PORTABLE__" on pre-ADX CPUs
```

This runs the unit tests and the end-to-end suite, which repeatedly boots a complete cluster (WBB, authorities, voter servers) over HTTPS using a deterministic cluster CA. The full protocol test plan lives in `tests/e2e/`:

| Test | What it proves |
|---|---|
| `referendum_happy_path` | V1–V15 for 8 voters (fixed matrix: 1 blank, 1 re-vote, all options) → exact tally `{blank:1, si:4, no:3}`, full WBB entry census, auditor all-OK |
| `coercion_ruse_pin` | ruse-PIN ballot accepted by both BBs (indistinguishable at cast time), filtered at the tally ACC check; the valid-PIN ballot counts |
| `wrong_pin` | wrong-PIN ballot passes BB proof checks, filtered by the ACC check |
| `revote_last_wins` | two valid ballots from one credential → only the last counts (ox dedup) |
| `revocation` | revoked vid's earlier ballot illegitimate at tally; spare-vid re-issue votes; commitment entry on the WBB |
| `new_device` | passphrase recovery on a fresh device; wrong passphrase fails closed |
| `pin_resend` | re-delivered PIN equals the original |
| `rate_limit_and_cat` | CAT rate limit over distinct commitments; cast-before-vote, tokenless and malformed intake rejected; commB-mismatch and consumed-token reuse refused at the ER verification point (real tokens minted with a test-owned device) |
| `idempotent_casting` | re-casting the same ballot returns identical receipts, no duplicate WBB entries |
| `wbb_policy_enforcement` | wrong-phase / wrong-role / insufficient-threshold WBB submissions rejected |
| `auditor_detects_tamper` | censored release, forged decryption share (re-signed with real TT keys), forged counts, flipped signature → auditor FAILs naming the step |
| `golden_determinism` | the full 8-voter flow reproduces `tests/e2e/golden/expected.json` field-by-field |
| `wbb_ui_smoke` | public page + proxy endpoints respond; digest search finds a cast ballot |

### Determinism and golden artifacts

The whole PoC is deterministic (D4/§9): a committed test master seed drives SHAKE256-derived per-actor seeds and ChaCha20 RNGs, a logical clock replaces wall time in every artifact, and TLS material is seed-derived. `golden_determinism` re-runs the full 8-voter election and compares the master seed, election-context hash, every WBB entry's data hash, all ballot emoji vectors, the tally counts, and the WBB tree size + checkpoint root against the committed `tests/e2e/golden/expected.json`. Regenerate it after an intentional protocol change with:

```bash
GOLDEN_UPDATE=1 cargo test golden_determinism
```

## CI

The repository includes a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs:

- `cargo fmt -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all-targets` (full suite, including the Go WBB build and the golden test)
- `cargo audit`

The CI job clones the sibling repositories into `../resources/` before building. Because `evoting-rs` is hosted on a private GitLab instance, the workflow expects a `GITLAB_TOKEN` secret (Settings -> Secrets and variables -> Actions -> New repository secret) with read access to the repository.

## Deviations register

Accepted, documented deviations from the manuscript (roadmap §11):

| # | Deviation | Reason |
|---|---|---|
| 1 | CAI codes mod 100 (not mod 10); single l1-code disclosure | library constants `CAI_POW=100`; referendum 1-candidate lists make l2 trivial |
| 2 | `PrivatePINEmoji`/`PublicPINEmoji` replaced by BallotEmoji + credential-point emoji | `o` and `o^x` not exposed via the library's public API |
| 3 | Trusted setup ceremony provisions RT/TT share files | library DKG is a one-call simulation (`setup()` returns all shares) |
| 4 | Ruse PIN via `VotingCredentialBuilder::simulate(ruse_pin)` (voter-side) | paper's trusted/untrusted-RT share substitution not exposed by the library; semantics preserved (local verify passes, tally filters) |
| 5 | PIN/mask delivery (§3.6.3) simplified: `voter_build_acc` yields builder + PIN directly | library API shape; shares still fetched over HTTPS from >= t_RT RTs |
| 6 | New-device recovery uses an encrypted server state blob + passphrase check | library `VoterSecretKey::recover` is not public |
| 7 | OAuth2/OIDC replaced by simplified ER tokens + CAT commitment (commB, AtSK EdDSA, rate limit) | PoC scope (locked decision D3) |
| 8 | WBB read API is an in-memory index (patch P1); the auditor verifies entry signatures + all artifacts, not Merkle tiles | PoC scope; the transparency root hash is still a golden artifact |
| 9 | WBB timestamps are logical; server-side timestamp validation disabled in tests (patch P2) | determinism (D4) |
| 10 | Enrollment shares the WBB `setup` phase window (the fork has 3 phases) | fork policy model matches §3.4.2 |
| 11 | In-memory stores in all services (no persistence) | PoC; matches the library's own `InMemoryBB` |
| 12 | One CT log + PM phase transitions (not 3 logs) | implemented fork behavior |
| 13 | ⊥ reconciliation compares released ballots across BBs directly (no homomorphic `bb_id_enc` decryption); canonical record = lowest bb_id, total order `(seq_no, bb_id)` | the §3.8.5 threshold check is equivalent on plaintext-equal records; `bb_id_enc` is still published in `ballot_metadata` |
| 14 | **Trust assumption**: TT `/decrypt/*` endpoints act as decryption oracles for callers holding the service bearer token (the tally driver) | mitigations: per-service bearer tokens (constant-time compared), full artifact audit trail on the WBB — every decryption the TTs perform is published and re-verified by the auditor, including the master-key binding of every share |
| 15 | The verifiable mixes require at least 3 elements (votes in the vote mix) | the library's shuffle-proof serialization enforces a minimum internal vector length; real referenda trivially satisfy this |
| 16 | §6.6 `GET /api/verify/{digest}` folded into `POST /api/ballot/status` + the wbb-ui digest search | same V14 information, one surface fewer; the public page is the manuscript's verification medium |

## Manuscript traceability

Every catalog action (roadmap §7) is executable through the public API and covered by a test:

| # | Action | Implementation | Test |
|---|---|---|---|
| V1 | eID login + app init | `voter-server /api/login` → DIP + ER | `referendum_happy_path` |
| V2 | Enrollment (DV keys, passphrase, vid) | `/api/enroll` | `referendum_happy_path` |
| V3 | PIN request (tokens, RT registration, τ) | `/api/enroll` → RT `/credentials/request` + NS | `referendum_happy_path` |
| V4 | PIN delivery (>= t_RT shares, DVNIZKP) | `/api/status`, `/api/pin/retrieve` | `referendum_happy_path` |
| V5 | PIN verification (unlimited) | `/api/pin/verify` | `referendum_happy_path`, `wrong_pin` |
| V6 | PIN re-sending | `/api/pin/resend` | `pin_resend` |
| V7 | Ruse PIN | `/api/pin/ruse` | `coercion_ruse_pin` |
| V8 | New-device registration | `/api/device/recover` | `new_device` |
| V9 | ACC revocation + re-issue | `/api/revoke`, ER `/revocations` | `revocation` |
| V10 | Trusted RT/BB selection | `/api/settings/trusted` | `referendum_happy_path`, `m7_integration` |
| V11 | Vote (3 options, PIN, BallotEmoji) | `/api/vote` | `referendum_happy_path` |
| V12 | Cast with CAT | `/api/cast` → ER `/tokens/casting` + BB `/ballots` | `referendum_happy_path`, `rate_limit_and_cat`, `idempotent_casting` |
| V13 | Confirmation + CAI disclosure | `/api/confirm` → BB `/cai` | `referendum_happy_path`, `m6_integration` |
| V14 | Manual verification (WBB page) | `/api/ballot/status`, `wbb-ui` | `referendum_happy_path`, `wbb_ui_smoke` |
| V15 | Results viewing | voter `GET /api/results`, wbb-ui results view, `election-admin results` | `referendum_happy_path` |
| A1 | Pre-setup parameters | `configuration/base.yaml` | configuration unit tests |
| A2 | Setup ceremony | `setup-ceremony`, ER `/admin/setup` | `referendum_happy_path`, `m3_integration` |
| A3 | ACC generation ×n_ACC | `election-admin gen-credentials` | `referendum_happy_path`, `m4_integration` |
| A4 | Phase transitions | `election-admin open-voting`/`close-voting` (PM-signed) | `wbb_policy_enforcement` |
| A5 | Tally (full pipeline → WBB) | `election-admin tally` | `referendum_happy_path` + every tally-flow test |
| A6 | Universal verification | `referendum-auditor` | `referendum_happy_path`, `auditor_detects_tamper` |
| A7 | Eligible-vid publication | ER `/admin/eligible-vids` (driven by the tally) | `referendum_happy_path`, `revocation` |

## License

See the upstream repositories for licensing terms.
