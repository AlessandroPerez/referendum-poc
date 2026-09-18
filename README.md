# Referendum PoC

A fully reproducible, HTTPS-microservices proof-of-concept of a **referendum** run with the Vote App protocol (PhD thesis, Ch. 3 with the Sec. 3.11 referendum optimization, and Ch. 5 for the access tokens), built on top of the [`evoting-rs`](https://gitlab.fbk.eu/aleph/i-voting/evoting-rs) cryptographic library and a patched fork of the [`sunlight_test`](https://github.com/elenabortolameotti/sunlight_test) Web Bulletin Board.

This is research-grade code: it demonstrates the protocol end-to-end but intentionally omits production concerns such as persistence, high availability, and a real identity provider.

## Architecture

Every service is an `axum` HTTPS server (rustls in-app TLS, certificates issued by a deterministic cluster CA that is the *only* trust anchor for every client). The Web Bulletin Board is the patched Go `sunlight` fork, serving TLS via its `-testcert` mode with ceremony-issued certificates.

| Component | Count | Role | Demo port |
|---|---|---|---|
| WBB (`sunlight`) | 1 | Cast-as-intended control values are taken mod 100 with a code and a sum per level; the referendum optimisation of Sec. 3.11 (one code, mod 10) is not applied | the library fixes `CAI_POW = 100` and the two-level proof structure at compile time |
| `er-server` | 1 | electoral roll: login, enrollment packages, tokens, revocation, eligible vids | 8001 |
| `dip-server` | 1 | identity-provider stub (signed assertions) | 8002 |
| `ns-server` | 1 | notification-service stub (PIN readiness) | 8003 |
| `rt-server` | 3 (t=2) | registration tellers: credential shares, DVNIZKP, tally controls | 8011-8013 |
| `tt-server` | 3 (t=2) | tabulation tellers: WBB co-signing, zeta-VSS, threshold decryption | 8021-8023 |
| `bb-server` | 2 | `PrivatePINEmoji` and `PublicPINEmoji` (Sec. 3.6.3, 3.8.4) are **not implemented**: the only visual encoding is the ballot emoji, which hashes the whole ballot | `o` and the encrypted `o^x` are internal to the library; two small accessors would close this |
| `voter-server` + SPA | per voter | voter backend serving a vanilla-JS app | 9001-9003 |
| `wbb-ui` | 1 | public bulletin-board page (V14 manual verification) | 9100 |
| `wbb-validator` (Go, demo only) | 3 | The setup ceremony runs the key generations in one process and deals the RT/TT share files (a trusted dealer), instead of the per-party DKG of Sec. 3.5.1-3.5.2 | PoC simplification: the library already offers the per-party rounds; running them over HTTPS between the tellers is not built yet |

CLIs: `setup-ceremony` (trusted setup: DKGs, entity keys, TLS material, per-service configs), `election-admin` (`gen-credentials`, `open-voting`, `close-voting`, `tally`, `results`) and `referendum-auditor` (Sec. 3.10 universal verification from the log alone, using only PUBLIC verifying keys).

## Repository layout

This repository contains only the Rust PoC crate. It depends on two sibling repositories that must be checked out into a common workspace directory:

```
voting/
|-- referendum-poc/          # this repository
|-- resources/
|   |-- evoting-rs/          # git@gitlab.fbk.eu:aleph/i-voting/evoting-rs.git (branch referendum-poc)
|   `-- sunlight_test/       # https://github.com/elenabortolameotti/sunlight_test.git (branch referendum-poc-wbb)
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

The script builds everything, runs the setup ceremony, and boots the full cluster (WBB + all authorities + three voter apps + the public bulletin-board page). The voter app is a phone-style single page with three sections, each a stack of full-height screens: `/enrollment` (eID login up to a verified PIN), `/voting` (build, cast, check publication, confirm) and `/management` (ruse PIN, PIN re-send, credential revocation, trusted authorities, device recovery). Open a voter app (e.g. `https://127.0.0.1:9001/`, fiscal id `VOTER-001`), enroll, wait for the PIN, vote, cast, and press **Confirm** - the cast-as-intended disclosure (Sec. 3.8.4 steps 8-17). A ballot that is cast but never confirmed is accepted by the ballot boxes yet **discarded at tally** (Sec. 3.9 step 2), exactly as in the thesis. The certificates come from the demo cluster CA, so accept the browser warning (test-only PKI).

Cast and confirm **at least 3 ballots** (the tally's verifiable mixes require it), then in another terminal:

```bash
./target/debug/election-admin -c demo-ceremony close-voting
./target/debug/election-admin -c demo-ceremony tally
./target/debug/election-admin -c demo-ceremony results
./target/debug/referendum-auditor -c demo-ceremony
```

`Ctrl-C` stops the cluster.

The demo also starts three **WBB validators** (`wbb-validator`, built from the fork). Each one independently fetches the signed checkpoint, verifies the log's signature, rebuilds the Merkle tree from the published leaves, checks that the root matches and that every leaf has a valid inclusion proof, then BLS-signs each leaf (over its index and Merkle hash) and submits the signature to the WBB, which verifies it against the registered validator key and serves it next to the entry with a BLS aggregate. The validators are deliberately slow, each one slower than the previous, so the public page shows the per-entry semaphore go red (no signature), yellow (some) and green (all three) a few seconds after each entry is published. Validators exist only in the demo: the test suite runs the WBB without any, and the page hides the column then.

The demo runs on the **wall clock**: every WBB entry, sequencing timestamp and ballot-box receipt carries the real Unix time (shown as a UTC date on the public page), and the WBB enforces its +/- 5 minute freshness window on submissions. The test suite runs the same code on a reproducible logical clock instead (see below). The time source is `clock.mode` in `configuration/base.yaml`, overridden per ceremony with `setup-ceremony --clock wall|logical` or `APP_CLOCK__MODE`.

## Reproduce the tests

```bash
cd referendum-poc
cargo test --all-targets              # add CGO_CFLAGS="-O2 -D__BLST_PORTABLE__" on pre-ADX CPUs
```

This runs the unit tests and the end-to-end suite, which repeatedly boots a complete cluster (WBB, authorities, voter servers) over HTTPS using a deterministic cluster CA. The full protocol test plan lives in `tests/e2e/`:

| Test | What it proves |
|---|---|
| `referendum_happy_path` | V1-V15 for 8 voters (fixed matrix: 1 blank, 1 re-vote, all options) -> exact tally `{blank:1, si:4, no:3}`, full WBB entry census, auditor all-OK |
| `coercion_ruse_pin` | ruse-PIN ballot accepted by both BBs (indistinguishable at cast time), filtered at the tally ACC check; the valid-PIN ballot counts |
| `wrong_pin` | wrong-PIN ballot passes BB proof checks, filtered by the ACC check |
| `revote_last_wins` | two valid ballots from one credential -> only the last counts (ox dedup) |
| `revocation` | revoked vid's earlier ballot illegitimate at tally; spare-vid re-issue votes; commitment entry on the WBB |
| `new_device` | passphrase recovery on a fresh device; wrong passphrase fails closed |
| `pin_resend` | re-delivered PIN equals the original |
| `rate_limit_and_cat` | CAT rate limit over distinct commitments; cast-before-vote, tokenless and malformed intake rejected; commB-mismatch and consumed-token reuse refused at the ER verification point (real tokens minted with a test-owned device) |
| `idempotent_casting` | re-casting the same ballot returns identical receipts, no duplicate WBB entries |
| `cai_choice_after_cast` | control values are withheld until the ballot is cast, then `sum - code` equals the chosen option; the voter picks the value to open only after casting; the ballot boxes publish exactly that slot with its decoded value, equal to the one the app showed; once a choice has left the device a different one is refused (both values would reveal the vote), while a retry of the same choice is allowed |
| `wbb_policy_enforcement` | wrong-phase / wrong-role / insufficient-threshold WBB submissions rejected |
| `unconfirmed_ballot_excluded` | a cast-but-unconfirmed ballot is accepted by the BBs, discarded at release (Sec. 3.9 step 2), never counted, and not a censorship finding for the auditor |
| `late_cast_rejected` | a cast after `close-voting` is refused by the BBs (digest unpublishable), rolled back, not counted; the election stays auditable |
| `auditor_detects_tamper` | censored release, forged decryption share (re-signed with real TT keys), mislabeled shares, a complete fake TT DKG (caught only by the master-key binding), forged counts, a released ballot with its confirmation removed, a ballot box publishing a forged opened control value, flipped signature -> auditor FAILs naming the step |
| `golden_determinism` | the full 8-voter flow reproduces `tests/e2e/golden/expected.json` field-by-field |
| `wbb_ui_smoke` | public page + proxy endpoints respond; digest search finds a cast ballot |
| `wbb_wall_clock_enforces_freshness_window` | a wall-clock WBB refuses a logical-tick timestamp (400) and sequences a fresh one on real time |

### Determinism and golden artifacts

The whole PoC is deterministic under test: a committed test master seed drives SHAKE256-derived per-actor seeds and ChaCha20 RNGs, a logical clock (`clock.mode: logical`, `base_ms + tick * tick_ms`) replaces wall time in every artifact, and TLS material is seed-derived. Real runs select `clock.mode: wall` and stamp the same artifacts with Unix time; nothing else changes. `golden_determinism` re-runs the full 8-voter election and compares the master seed, election-context hash, every WBB entry's data hash, all ballot emoji vectors, the tally counts, and the WBB tree size + checkpoint root against the committed `tests/e2e/golden/expected.json`. Regenerate it after an intentional protocol change with:

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

Accepted, documented deviations from the thesis (each linked to the thesis section it departs from):

| # | Deviation | Reason |
|---|---|---|
| 1 | CAI codes mod 100 (not mod 10); one opened value per level, chosen by the voter after casting | library constants `CAI_POW=100`; referendum 1-candidate lists make l2 trivial |
| 2 | `PrivatePINEmoji`/`PublicPINEmoji` replaced by BallotEmoji + credential-point emoji | `o` and `o^x` not exposed via the library's public API |
| 3 | Trusted setup ceremony provisions RT/TT share files | library DKG is a one-call simulation (`setup()` returns all shares) |
| 4 | Ruse PIN via `VotingCredentialBuilder::simulate(ruse_pin)` (voter-side) | paper's trusted/untrusted-RT share substitution not exposed by the library; semantics preserved (local verify passes, tally filters) |
| 5 | PIN/mask delivery (Sec. 3.6.3) simplified: `voter_build_acc` yields builder + PIN directly | library API shape; shares still fetched over HTTPS from >= t_RT RTs |
| 6 | New-device recovery uses an encrypted server state blob + passphrase check | library `VoterSecretKey::recover` is not public |
| 7 | OAuth2/OIDC replaced by simplified ER tokens + CAT commitment (commB, AtSK EdDSA, rate limit) | PoC scope |
| 8 | The auditor verifies entry signatures and every artifact but NOT the log structure: it trusts the entry list the bulletin board serves (no checkpoint signature, Merkle root or inclusion check). The read API is an index the board rebuilds from its data tiles at startup, after verifying its own signature on the stored tree head and that the leaves hash to that root | the validators do check the Merkle tree from outside; the auditor does not yet |
| 9 | Under test, WBB timestamps are logical and the fork's server-side freshness check is disabled (fork timestamp patch); on the wall clock (`clock.mode: wall`, the demo default) timestamps are real Unix time and the check is enforced | determinism of the test suite |
| 10 | Enrollment shares the bulletin board's `setup` write window (the board has 3 phases, as in Sec. 3.4.2). The write-permission table EXTENDS Sec. 3.4.2 with the electoral roll's `revocation_commitment` (setup and voting) and `eligible_vids` (tallying), which Sec. 3.7.5 and Sec. 3.9 step 1 require but the permission list omits | the thesis lists no write permission for those two publications |
| 11 | In-memory stores in all services (no persistence) | PoC; matches the library's own `InMemoryBB` |
| 12 | *(note, not a thesis deviation)* One transparency log with logged phase transitions | the thesis does not prescribe a number of logs; a single log keeps a total order across phases and makes the phase chain auditable |
| 13 | **The tally is stricter than Sec. 3.9 step 3**: a ballot whose digest was published by fewer than 2 ballot boxes is excluded, whereas the thesis releases every ballot with a published digest and uses the bottom symbol only to SIGNAL a failed ballot box. The encrypted ballot-box identifiers are published but never multiplied or decrypted (Sec. 3.8.4 step 5, Sec. 3.9 step 4), and carry no proof of correct encryption (Protocol 9) | PoC simplification; the plaintext ballot-box id travels next to the ciphertext |
| 14 | **Trust assumption**: TT `/decrypt/*` endpoints act as decryption oracles for callers holding the service bearer token (the tally driver) | mitigations: per-service bearer tokens (constant-time compared), full artifact audit trail on the WBB - every decryption the TTs perform is published and re-verified by the auditor, including the master-key binding of every share |
| 15 | The verifiable mixes require at least 3 elements (votes in the vote mix) | the library's shuffle-proof serialization enforces a minimum internal vector length; real referenda trivially satisfy this |
| 16 | *(note, not a thesis deviation)* No dedicated per-digest verification endpoint on the voter server: the voter checks their ballot on the public bulletin-board page, which is what Sec. 3.8.5 describes | - |
| 17 | **Credential generation (Sec. 3.5.4) runs inside `election-admin`**, a trusted dealer: it holds all RT share files, the RT signing keys and the RT operation seeds, learns every credential secret and PIN, and (in the demo and the test harness) signs the `acc_pub_key` entry in the tellers' names. Whoever holds the three operation seeds can regenerate every share | PoC simplification, same class as #3: the library exposes every round per party. What each SERVICE loads is split correctly - one share file per teller with only its own shares (a foreign share is refused), and the ER sees `A` and `E[A]` only - but the demo runs every service as one user in one directory, so file modes isolate nothing between tellers there. Services read their file at startup: a teller or ER started before `gen-credentials` must be restarted |
| 18 | *(closed)* Cast-as-intended human loop: formerly reduced, now complete. After casting, the app shows the control code and control sum (Sec. 3.8.4 step 9), the voter checks `sum - code` against the chosen option and picks which value to open (steps 10-11), the ballot boxes decode and publish the opened value (steps 13-16), the app cross-checks it, the bulletin board displays it for the voter's later comparison, and the auditor re-derives it from the released ballot | needed two additive accessors in the library (`Voter::vote_with_cai_values`, `Ballot::open_cai_disclosure`); the ballot always holds both encrypted values and does not depend on the slot flags, so the app builds it once, keeps both openings, pins the voter's choice before anything leaves the device and destroys the unused openings (a second, different choice is refused: both values together would reveal the vote). Only the list-level values are shown - the candidate level is trivial in a referendum (Sec. 3.11) and its coin is tossed by the app |
| 19 | The RT waiting period tau (Sec. 5.3.1.3-5) is sampled in clock ticks but not enforced as a delivery gate | extends #9: on the logical clock there is nothing to wait for; tau is recorded per request so a wall-clock deployment can gate on it |
| 20 | Credential control elements (Sec. 3.9 step 19) are published inside a TT-co-signed `re_encryption_proof` entry rather than an RT-written entry | the WBB fork's write policy has a fixed entry-type table (RT may not write during tallying); the `CredentialControlProof` NIZKPs inside verify against pk_RT, so accountability is cryptographic rather than by log authorship |
| 21 | Pseudonymous identifiers are sequential (v_id = registry position; spare vids n_V+1..n_ACC), not random | PoC simplification; anyone who knows the registry order can de-pseudonymize, which a deployment fixes with a seed-derived permutation |
| 22 | Fail-closed instead of filter for Sec. 3.9 step 5 / Sec. 3.10 1(d)-(e): an invalid or unconfirmed RELEASED ballot aborts the tally and fails the audit instead of being discarded | a deliberate choice, not a library limit: ballot boxes verify proofs at intake and release only confirmed ballots, so such a ballot proves a misbehaving ballot box |
| 23 | Casting tokens carry no time validity (Sec. 5.3.1.6) - single use + commB binding only | extends #7 (simplified tokens on a logical clock) |
| 24 | RT `/decoy` is dead code: it is not the Sec. 3.7.3 mechanism (it draws an unrelated credential) and nothing calls it | the ruse PIN uses the voter-side simulation of #4 |
| 25 | **Trust assumption**: the tally driver (`election-admin`) holds the ballot boxes' signing keys and the tellers' seeds, and signs the `encrypted_ballot` entries on the ballot boxes' behalf | same trusted-coordinator class as #14 and #17; in the thesis each authority publishes its own entries |
| 26 | Validator signatures are collected and displayed but not audited: `referendum-auditor` does not verify them, nor the checkpoint signature or the Merkle root (see #8), and a validator learns the log key from the log itself | demo facility; the verification logic exists in the fork's `internal/validation` only |
| 27 | After a bulletin-board restart the staging area and the validator signatures start empty (entries and phase are restored from the log) | validators re-sign on their own; a re-submission of an already published entry is sequenced again instead of becoming a late-arrival reference |

## Thesis traceability

Every voter (V) and authority (A) action of the protocol is executable through the public API and covered by a test:

| # | Action | Thesis | Implementation | Test |
|---|---|---|---|---|
| V1 | eID login + app init | Sec. 5.3.1.1, 3.6.1 | `voter-server /api/login` -> DIP + ER | `referendum_happy_path` |
| V2 | Enrollment (DV keys, passphrase, vid) | Sec. 3.6.1 | `/api/enroll` | `referendum_happy_path` |
| V3 | PIN request (tokens, RT registration, tau) | Sec. 5.3.1.2-5.3.1.3 | `/api/enroll` -> RT `/credentials/request` + NS | `referendum_happy_path` |
| V4 | PIN delivery (>= t_RT shares, DVNIZKP) | Sec. 5.3.1.4-5.3.1.5, 3.6.3 | `/api/status`, `/api/pin/retrieve` | `referendum_happy_path` |
| V5 | PIN verification (unlimited) | Sec. 3.7.1 | `/api/pin/verify` | `referendum_happy_path`, `wrong_pin` |
| V6 | PIN re-sending | Sec. 3.7.2 | `/api/pin/resend` | `pin_resend` |
| V7 | Ruse PIN (after a ruse request only the ruse PIN verifies locally, Sec. 3.7.3; the valid PIN still casts a counted vote) | Sec. 3.7.3 | `/api/pin/ruse`, `/api/pin/verify` | `coercion_ruse_pin`, `pin_management` |
| V8 | New-device registration | Sec. 3.7.4 | `/api/device/recover` | `new_device` |
| V9 | ACC revocation + re-issue | Sec. 3.7.5 | `/api/revoke`, ER `/revocations` | `revocation` |
| V10 | Trusted RT/BB selection | Sec. 3.12 | `/api/settings/trusted` | `referendum_happy_path`, `pin_management` |
| V11 | Vote (3 options, PIN, BallotEmoji) | Sec. 3.8.2, 3.11 | `/api/vote` | `referendum_happy_path` |
| V12 | Cast with CAT | Sec. 5.3.1.6, 3.8.4 | `/api/cast` -> ER `/tokens/casting` + BB `/ballots` | `referendum_happy_path`, `rate_limit_and_cat`, `idempotent_casting` |
| V13 | Confirmation + CAI disclosure with the voter's post-cast choice of the opened value (load-bearing: only confirmed ballots are released/counted, Sec. 3.9 step 2) | Sec. 3.8.4 steps 8-17 | `/api/cai/values` (after the cast), `/api/confirm {l1, l2}` -> BB `/cai` (decodes + publishes the opened value); BB release filter; auditor `cai_confirmation` | `referendum_happy_path`, `cai_choice_after_cast`, `unconfirmed_ballot_excluded`, `auditor_detects_tamper` |
| V14 | Manual verification (WBB page) | Sec. 3.8.5 | `/api/ballot/status`, `wbb-ui` | `referendum_happy_path`, `wbb_ui_smoke` |
| V15 | Results viewing | Sec. 3.9 step 30, 3.10 | voter `GET /api/results`, wbb-ui results view, `election-admin results` | `referendum_happy_path` |
| A1 | Pre-setup parameters | Sec. 3.4 | `configuration/base.yaml` | configuration unit tests |
| A2 | Setup ceremony | Sec. 3.5 | `setup-ceremony`, ER `/admin/setup` | `referendum_happy_path`, `setup_ceremony` |
| A3 | ACC generation xn_ACC | Sec. 3.5.4 | `election-admin gen-credentials` | `referendum_happy_path`, `credential_generation` |
| A4 | Phase transitions (BB intake rolls back any ballot whose digest the WBB refuses, so a late cast is not stored) | Sec. 3.4.2 | `election-admin open-voting`/`close-voting` (PM-signed) | `wbb_policy_enforcement`, `late_cast_rejected` |
| A5 | Tally (full pipeline -> WBB) | Sec. 3.9 | `election-admin tally` | `referendum_happy_path` + every tally-flow test |
| A6 | Universal verification | Sec. 3.10 | `referendum-auditor` | `referendum_happy_path`, `auditor_detects_tamper` |
| A7 | Eligible-vid publication | Sec. 3.9 step 1 | ER `/admin/eligible-vids` (driven by the tally) | `referendum_happy_path`, `revocation` |

## License

See the upstream repositories for licensing terms.
