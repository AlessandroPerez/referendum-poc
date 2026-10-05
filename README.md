# Referendum PoC

A fully reproducible, HTTPS-microservices proof-of-concept of a **referendum** run with the Vote App protocol (PhD thesis, Ch. 3 with the Sec. 3.11 referendum optimization, and Ch. 5 for the access tokens), built on top of the [`evoting-rs`](https://gitlab.fbk.eu/aleph/i-voting/evoting-rs) cryptographic library and a patched fork of the [`sunlight_test`](https://github.com/elenabortolameotti/sunlight_test) Web Bulletin Board.

This is research-grade code: it demonstrates the protocol end-to-end but intentionally omits production concerns such as persistence, high availability, and a real identity provider.

## Architecture

Every service is an `axum` HTTPS server (rustls in-app TLS, certificates issued by a deterministic cluster CA that is the *only* trust anchor for every client). The Web Bulletin Board is the patched Go `sunlight` fork, serving TLS via its `-testcert` mode with ceremony-issued certificates.

| Component | Count | Role | Demo port |
|---|---|---|---|
| WBB (`sunlight`) | 1 | append-only transparency log, phase-aware write policy | 8090 |
| `er-server` | 1 | electoral roll: login, enrollment packages, tokens, revocation, eligible vids | 8001 |
| `dip-server` | 1 | identity-provider stub (signed assertions) | 8002 |
| `ns-server` | 1 | notification-service stub (PIN readiness) | 8003 |
| `rt-server` | 3 (t=2) | registration tellers: credential shares, DVNIZKP, tally controls | 8011-8013 |
| `tt-server` | 3 (t=2) | tabulation tellers: WBB co-signing, zeta-VSS, threshold decryption | 8021-8023 |
| `bb-server` | 2 | ballot boxes: locally verified casting tokens, cast-as-intended, ballot release | 8031-8032 |
| `voter-server` + SPA | per voter | voter backend serving a vanilla-JS app | 9001-9003 |
| `wbb-ui` | 1 | public bulletin-board page (V14 manual verification) | 9100 |
| `wbb-validator` (Go, demo only) | 3 | independent WBB validators: rebuild the Merkle tree, verify it against the signed checkpoint, BLS-sign every leaf | - |

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

The script builds everything, runs the setup ceremony, and boots the full cluster (WBB + all authorities + three voter apps + the public bulletin-board page). The voter app is a phone-style single page with three sections, each a stack of full-height screens: `/enrollment` (eID login up to a verified PIN), `/voting` (build, cast, check publication, confirm) and `/management` (ruse PIN, PIN re-send, credential revocation, trusted authorities, device recovery). Open a voter app (e.g. `https://127.0.0.1:9001/`, log in with the test eID `VOTER-001`), enroll, wait for the PIN, vote, cast, and press **Confirm** - the cast-as-intended disclosure (Sec. 3.8.4 steps 8-17). A ballot that is cast but never confirmed is accepted by the ballot boxes yet **discarded at tally** (Sec. 3.9 step 2), exactly as in the thesis. The certificates come from the demo cluster CA, so accept the browser warning (test-only PKI).

Cast and confirm **at least 2 ballots** (a verifiable mix needs two to hide anything), then in another terminal:

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
| `pin_lifecycle_ruse_resend_recover_revoke_trusted` | the whole PIN life cycle on a hand-built cluster: retrieval, ruse PIN, a re-send delivers the valid PIN and disarms the decoy, recovery on a new device, revocation onto a spare, trusted-authority selection |
| `pin_emoji_private_and_public` | the private PIN emoji matches for the real PIN and differs for a wrong one; the public one is what the ballot boxes publish |
| `waiting_period_on_the_wall_clock` | on the wall clock the tellers refuse PIN retrieval before tau and deliver after it |
| `revocation_during_enrollment_and_after_close` | a revocation is accepted during setup and voting and refused once voting is closed |
| `failed_revocation_burns_no_spare` | a revocation whose commitment could not be published changes nothing; one whose answer was lost is adopted on retry |
| `concurrent_revocations_of_one_voter_chain` | concurrent revocations of one voter are serialised into a chain, one spare each |
| `spare_ids_follow_the_board_across_restarts` | after a roll restart the next spare is derived from the board's published commitments |
| `three_voters_cast_with_cat_and_cai` | a hand-built cluster: casting tokens, casting, confirmation and release for three voters |
| `voter_enrolls_and_verifies_deterministic_pin` | enrollment on a hand-built cluster reproduces the committed test PIN |
| `er_publishes_its_setup_entries_to_wbb` | the roll publishes its five setup entries, each signed by ER-1 |
| `admin_generates_credentials_and_publishes_acc_pub_key`, `rt_server_signs_with_its_service_token` | credential generation and the co-signed public-credential entry |
| `full_election_tally_and_audit` | a complete election through the tally CLI path and the auditor, with the log key pinned from the ceremony file |
| `single_ballot_tally_is_refused_clearly`, `smallest_tally_has_two_ballots` | the tally refuses fewer than two mixable ballots with a clear error and works with exactly two |
| `auditor_verifies_the_log_itself` | the auditor's own log verification: altered, dropped, reordered or re-timestamped entries, a short list, an edited or foreign tree head, a foreign log name |
| `validator_signatures_are_audited_against_pinned_keys` | the validators' BLS signatures are verified against pinned keys; forged or misattributed ones fail, withheld ones are reported |
| `wbb_threshold_entry_and_deterministic_checkpoint` | a co-signed threshold entry on the real board, and a reproducible checkpoint |
| `harness_loads` | the e2e harness itself boots |
| `a_wrong_pin_ballot_dies_and_the_last_valid_ballot_wins` | a wrong-PIN ballot passes BB proof checks and is filtered by the ACC check; of two valid ballots from one credential only the last counts (ox dedup) |
| `revocation` | revoked vid's earlier ballot illegitimate at tally; spare-vid re-issue votes; commitment entry on the WBB |
| `new_device` | passphrase recovery on a fresh device; wrong passphrase fails closed |
| `rate_limit_and_cat` | CAT rate limit over distinct commitments; cast-before-vote, tokenless and malformed intake rejected; casting tokens verified by the ballot box alone: wrong ballot box, commB mismatch, stretched validity, re-targeted or forged token refused (real tokens minted with a test-owned device) |
| `casting_token_validity_and_pacing` | An expired casting token is refused by the ballot boxes (wall clock); a NEW ballot too soon after the previous one is refused by the electoral roll (429) while the same ballot can be cast again |
| `a_roll_cannot_swap_an_identifier_without_a_revocation` | a stand-in electoral roll publishes, with the roll's real key, an eligible list in which one voter's identifier is swapped for a spare: the tally is self-consistent and drops that vote, and the audit fails against the identifiers committed at setup |
| `an_identifier_the_roll_cannot_prove_is_refused` | a stand-in roll hands the app an identifier other than the one committed for that voter: the app refuses to enrol |
| `a_revoked_voter_can_log_in_again_on_the_spare` | after a revocation a fresh device logs in on the proved spare |
| `the_board_orders_the_tally_not_the_ballot_boxes` | an honest election is re-audited with every receipt of one ballot box renumbered backwards, consistently in what it published and what it released: the audit still passes and the recomputed tally is unchanged, because the order comes from the board |
| `one_valid_confirmation_is_enough` | one box never receives the voter's disclosure (a stand-in drops it); the app delivers it to the other box, the ballot counts on that one confirmation, the audit passes; BB-1, which released on the board's word, is not named |
| `a_forged_confirmation_counts_for_nothing_and_names_its_box` | a box publishes a genuine disclosure re-labelled with the digest of an unconfirmed ballot: the board says confirmed, the tally does not count it, the audit names the box |
| `a_teller_whose_co_signature_does_not_verify_is_named_before_anything_is_published` | a teller returns a corrupt co-signature for the result: the driver names it before anything reaches the board; an honest rerun succeeds |
| `a_submission_cut_off_part_way_is_finished_by_the_next_run` | a network fault loses one teller's partial of the result twice; the next run resumes the saved submission - one result, no duplicate, audit PASS, a third run refused |
| `a_teller_decrypting_under_its_own_key_is_set_aside_and_the_honest_result_stands` | a teller answers a decryption under a key share of its own with a proof that verifies against it: set aside and named, the honest result is published |
| `a_replayed_eid_assertion_is_refused` | the same signed eID assertion presented twice logs in once and revokes nothing |
| `a_device_cannot_be_rebound_without_the_old_key` | a registration token alone cannot rebind a registered voter's app key |
| `a_second_decoy_does_not_disturb_the_story_the_first_one_tells` | decoy, real vote, second decoy across gaps: the PIN shown, what verifies, the control values, the status and the confirmation all keep telling one story |
| `a_planted_confirmation_does_not_make_a_ballot_counted` | a box publishes another ballot's disclosure under an unconfirmed ballot's digest: the device says not counted, no box releases it, the tally never sees it |
| `a_box_releases_what_the_board_shows_confirmed_even_if_its_own_cai_failed` | a box whose own `/cai` failed still releases the ballot the board shows confirmed; no box is named for withholding |
| `a_planted_release_entry_does_not_block_the_tally` | a release entry planted by one box before the tally changes nothing: the tally runs, the result stands, the box is named |
| `one_corrupt_teller_share_does_not_deny_the_credential` | a teller delivers a share that does not fit: the credential is rebuilt from the other tellers, which are reported |
| `the_control_values_and_confirmation_screens_keep_the_ruse_cover_story` | a coercer's unconfirmed ruse ballot is still there, unchanged, after the voter's real vote and confirmation |
| `the_recovery_blob_size_does_not_reveal_a_ruse` | the roll-stored blob has the same size with and without a ruse PIN |
| `a_teller_answering_with_the_wrong_shape_is_set_aside` | a teller returns one partial decryption too few: set aside by the shape the other tellers agree on, honest result published |
| `a_ballot_one_box_withholds_is_still_counted` | a stand-in ballot box withholds a voter's last ballot at release; the tally counts it from the other box's copy, the audit passes and names the withholding box with a warning |
| `a_ballot_every_box_withholds_is_not_counted_and_both_boxes_are_named` | when every box withholds a counted ballot (no honest box is left) the tally goes on without it and the audit names both boxes |
| `a_tally_that_fails_part_way_leaves_the_board_untouched` | a stand-in teller refuses the very last co-signature after every mix, proof and decryption was produced: nothing reaches the board, and the tally runs to the end once the teller is back |
| `auditor_resolves_a_late_co_signature` | a teller co-signing after publication (the board's `ref:N` leaf) passes the audit; the same signature pointed at any other entry, or at none, fails |
| `idempotent_casting` | re-casting the same ballot returns identical receipts, no duplicate WBB entries |
| `cai_choice_after_cast` | control values are withheld until the ballot is cast, then `sum - code` equals the chosen option; the voter picks the value to open only after casting; the ballot boxes publish exactly that slot with its decoded value, equal to the one the app showed; once a choice has left the device a different one is refused (both values would reveal the vote), while a retry of the same choice is allowed |
| `wbb_policy_enforcement` | wrong-phase / wrong-role / insufficient-threshold WBB submissions rejected |
| `unconfirmed_ballot_excluded` | a cast-but-unconfirmed ballot is accepted by the BBs, discarded at release (Sec. 3.9 step 2), never counted, and not a censorship finding for the auditor |
| `late_cast_rejected` | a cast after `close-voting` is refused by the BBs (digest unpublishable), rolled back, not counted; the election stays auditable |
| `auditor_detects_tamper` | censored release, forged decryption share (re-signed with real TT keys), mislabeled shares, a complete fake TT DKG (caught only by the master-key binding), forged counts, a released ballot with its confirmation removed, a forged emoji or public PIN emoji (also when covered by a later, correct entry, or hidden in an unreadable one), an entry naming a ballot box that did not sign it, an entry carrying both signer forms, a forged opened control value covered by a later genuine confirmation, a forged opening by a box that releases nothing, a ballot box releasing ballots under swapped receipts, a released ballot with no published receipt, two different receipts published for one ballot, ballot_metadata that is unreadable, another box's, or about a ballot that box never accepted, a ballot box publishing a forged opened control value, flipped signature -> auditor FAILs naming the step |
| `a_ballot_box_never_opens_the_second_slot_of_a_ballot` | the disclosure PUBLISHED for a ballot is replayed straight at every box: each answers with the values it opened the first time and the board gains nothing (the two slots together are the vote) |
| `the_rolls_setup_publication_is_once_only` | a repeated `POST /admin/setup` is adopted, not published again; the board keeps one `tt_public_shares` |
| `the_decoy_choice_says_nothing_about_the_real_pin` | probing `/api/pin/ruse` with the real PIN leaves EXACTLY the state any other candidate leaves - same answer, and the same answer from the verification screen afterwards - and arming another value puts the real PIN back |
| `a_decoy_equal_to_the_real_pin_still_casts_a_counted_ballot` | Sec. 3.7.3 step 5 makes that decoy the valid credential (`x^ruse = x` when the PINs are equal), so the voter loses nothing |
| `one_teller_that_drops_out_of_the_credential_proof_denies_nobody` | a stand-in makes rt-1 fail the second DVNIZKP round; the credential is rebuilt over the other tellers |
| `a_decoy_cast_between_two_casts_leaves_one_record` | a decoy cast wedged between two casts of one real ballot leaves one record, so confirmation and the status screen agree |
| `a_revocation_is_a_fresh_start` | after a revocation the retrieval shows the NEW valid PIN, the old decoy no longer verifies, a ballot on the new PIN counts, and the voter can arm the old decoy again by typing it (Sec. 3.7.5 step 3, Sec. 3.6.3 footnote 9) |
| `a_revocation_whose_pin_request_fails_leaves_the_device_registered` | the device is registered on the new identifier before the PIN request; a request that then fails is reported as "revoked - use Re-send", and a re-send followed by a cast succeeds |
| `a_second_opening_parked_under_a_junk_record_is_still_found` | a second genuine opening published under the digest of a released non-ballot that shares the ballot's ciphertexts is still weighed against the ballot, and the junk record is named |
| `a_device_recovered_after_a_cast_can_still_confirm` | a device recovered from the blob finishes and counts a ballot the first device cast |
| `a_teller_decrypts_only_the_tally_the_board_adds_up_to` | a ciphertext in the request changes nothing: the teller recomputes the sum from the published artifacts |
| `a_recovered_device_cannot_open_a_ballot_it_did_not_build` | two devices confirm the same ballot at the same moment with opposite selections; the recovered one has no ballot to disclose, so the board carries one |
| `a_planted_confirmation_cannot_veto_an_honest_one` | a box plants a confirmation naming the other slots before the voter confirms; the honest confirmation still goes through and the ballot is counted |
| `casting_is_rate_limited_and_local_checks_are_not` | PIN verification is unlimited (Sec. 3.7.1) and the roll refuses a cast beyond the voter's budget (Sec. 5.2) |
| `one_teller_cannot_stop_the_credential_controls` | a teller stating a control key share it never held is dropped and the honest subset finishes the step |
| `a_teller_decrypts_only_what_its_own_blinding_produced` | a caller-chosen list, and a well-formed blinding the teller had no part in, are both refused at every `/decrypt/*` |
| `a_teller_that_delivers_a_bad_share_is_named_and_dropped` | a stand-in swaps two of rt-1's scalars: the share fails the dealers' commitments, the voter still gets their credential, and `rebuilt_without_rts` names rt-1 |
| `a_teller_refuses_a_zeta_vss_deal_that_is_not_the_tellers_own` | a substituted own broadcast, a deal that is not one per teller, and a tampered sealed share are each refused (Sec. 2.8 Protocol 2 steps 4, 6) |
| `the_passphrase_alone_reaches_no_ballot` | the control values, the cast status and the confirmation all refuse a request that carries no PIN (Sec. 3.7.1 step 3), so the passphrase alone reads no vote and confirms nothing |
| `arming_a_decoy_needs_the_pin_in_force` | `/api/pin/ruse` refuses a request that does not carry the PIN the app holds (Sec. 3.7.3 step 5 needs `PIN^valid` to build `x^ruse`), so nobody can void a voter's ballots with the passphrase alone |
| `a_confirmation_names_the_ballot_whose_values_were_checked` | a confirmation naming another ballot's digest is refused: the ballot checked at Sec. 3.8.4 step 9 is the ballot opened at step 11 |
| `a_slow_screen_cannot_bring_back_a_confirmed_ballot` | a PIN re-send in flight across a confirmation does not put the confirmed ballot, or its unused openings, back within reach |
| `a_teller_that_drops_out_of_the_second_control_round_denies_nobody` | a teller that answers control round 1 and fails round 2 is named and set aside, and the honest tellers finish the step from a fresh round 1 |
| `a_box_refuses_the_opening_that_completes_a_published_one` | a box holding the ballot refuses a disclosure that opens its other option slot, accepts a retry of the one it published, and vetoes a plant that opens nothing |
| `both_openings_of_a_blank_ballot_reveal_it_too` | `sum - code = 0` is the blank vote, so two openings of the option level give it away even when the two numbers are equal |
| `a_second_opening_is_found_under_whatever_digest_it_is_parked` | a second genuine opening published under ANOTHER released ballot's digest is still weighed against the ballot it opens, and the box that parked it is named |
| `a_restart_does_not_repeat_a_nonce` | the per-purpose nonce counter is persisted before the nonces are drawn, so a restart over the same seed cannot answer two challenges with one commitment |
| `a_teller_that_lies_in_the_second_control_round_denies_nobody` | a registration teller that answers control round 2 with the wrong scalars and then refuses to co-sign is named and set aside, and t_RT honest tellers finish the step |
| `a_second_vote_does_not_strand_the_ballot_already_cast` | building another ballot leaves the cast one confirmable, the confirmation screens keep answering for it, and the app says it is still waiting |
| `a_recovery_on_a_live_device_takes_no_ballot_away` | a device recovery run on a device that is mid-cast takes nothing away: the ballot is still confirmable |
| `a_box_that_refuses_a_confirmation_is_named_to_the_voter` | a box refusing the disclosure with a 4xx is reported to the voter by name even though the other box published |
| `a_slow_cast_cannot_undo_a_confirmation` | a cast still in flight when the voter confirms cannot write its stale copy of the device state back over the confirmation, so the other opening never becomes reachable again |
| `a_re_send_delivers_the_voters_own_pin` | a PIN re-send hands back the valid PIN even after somebody else armed a decoy, and that PIN still casts a counted ballot |
| `a_record_that_is_not_a_ballot_cannot_be_revealed` | a released record whose proofs do not verify, opened under both tags of one disclosure, reveals nothing and does not fail the audit; the box that released it is named |
| `a_vote_during_a_slow_cast_does_not_strand_the_ballot_being_cast` | a second vote while the first ballot's cast is still in flight leaves that ballot confirmable |
| `a_revocation_during_a_slow_cast_leaves_one_session` | a cast finishing after a revocation cannot write the revoked session back: every later read resolves to the new identifier |
| `fresh_entropy_makes_a_rolled_back_ledger_harmless` | on a real run a nonce ledger restored from an older backup does not replay a nonce |
| `a_ledger_is_never_created_over_an_existing_one` | a ceremony re-run over a used directory is refused rather than zeroing the counters |
| `a_revocation_whose_device_registration_fails_still_casts` | the roll moves the device record onto the new identifier within the revocation; the device's own re-registration can be lost and it still casts |
| `an_enrollment_whose_last_requests_fail_still_hands_over_the_passphrase` | a PIN request or recovery-blob upload lost after the roll registered the device still hands the voter the passphrase; the status screen says no request is open and a re-send completes the enrollment (Sec. 3.6.1 steps 5-9) |
| `a_stalled_confirmation_holds_no_other_voter` | a box that stalls one voter's confirmation does not hold another voter's on the same app server (A9) |
| `a_refused_metadata_entry_does_not_drop_an_accepted_ballot` | once a box's digest entry is on the board the box holds the ballot, even if its metadata entry is refused (Sec. 3.8.5 1(d)) |
| `a_stale_session_file_never_takes_over_after_a_revocation` | a session file of the revoked generation found beside the new one is never used and is removed (Sec. 3.7.5) |
| `a_recovery_racing_a_revocation_writes_nothing_back` | a device recovery in flight while the device revokes does not write the revoked session back (Sec. 3.7.2 step 4: one writer per device) |
| `a_lost_digest_publication_is_published_by_the_cast_again` | a box whose digest submission was lost keeps the signed entry and publishes it when the voter casts again; it confirms and releases only a ballot whose digest it saw on the board (Sec. 3.8.4 step 6) |
| `a_released_record_of_another_shape_does_not_stop_the_tally` | a record a dishonest box releases with a choice of another shape than the election's is discarded, not a crash of the tally (Sec. 3.9 step 5) |
| `a_forwarded_disclosure_does_not_read_as_a_refusal` | a box answering "confirmation in progress" because a dishonest box forwarded the voter's disclosure to it is asked again, not counted as refusing (A9) |
| `a_second_writer_during_a_revocation_waits_for_it` | a second revocation sent while the first is waiting on the tellers waits for it: one session at the end (one writer per device, keyed by the passphrase) |
| `a_lost_answer_to_the_device_registration_does_not_lock_the_voter_out` | the enrollment saves the session before registering the device; a lost answer from the roll still hands over the passphrase, and a re-send registers the same key (Sec. 3.7.4 step 7) |
| `a_lost_answer_to_a_revocation_spends_one_spare` | a revocation retried after a lost answer (same request id, saved before sending) gets the spare the first request issued; no second spare is spent (Sec. 3.7.5) |
| `a_revocation_from_an_out_of_date_second_device_revokes` | a second device still on an identifier the first device revoked sends no matching request id: its revocation is a real one, and the credential the first revocation issued is revoked (Sec. 3.7.5) |
| `a_slow_enrollment_hands_over_the_passphrase_at_once` | the passphrase is returned before the enrollment goes on the network; registration and PIN request finish in the background (Sec. 3.6.1 steps 5-9) |
| `a_registration_repair_keeps_the_recovery_blob` | a device re-registering its same key without a blob keeps the blob the roll holds (Sec. 3.7.4) |
| `a_lost_board_answer_does_not_keep_a_published_ballot_from_the_release` | a box asks the board, not its own record, whether a digest is published: a lost answer during voting does not make it withhold the ballot at release (Sec. 3.9 step 3, A9) |
| `copied_disclosures_do_not_keep_the_voter_from_confirming` | a box checks a disclosure before taking the ballot's confirmation slot, so a flood of copied disclosures cannot turn the voter's own away |
| `concurrent_re_casts_publish_one_metadata_entry` | concurrent re-casts of a pending ballot publish one metadata entry |
| `a_ballot_published_after_the_re_vote_does_not_replace_it` | the app sends a disclosure only for a ballot the board already shows, so a box holding an unpublished ballot cannot publish it after the voter's re-vote and have it counted instead (Sec. 3.8.4 steps 6-8, Sec. 3.9 step 10) |
| `a_dropped_board_read_does_not_shorten_a_release` | a box decides from one board read which of its ballots are published, and fails the release if that read fails rather than return a shorter list (Sec. 3.9 step 3) |
| `a_recovered_device_does_not_inherit_a_pending_revocation` | a pending revocation request id never travels in the recovery blob: a recovered device's own revocation is a real one (Sec. 3.7.4, 3.7.5) |
| `a_revocation_retry_after_voting_closed_is_refused` | a retried revocation is refused once voting has closed, like any other (Sec. 3.7.5) |
| `a_superseded_ballot_is_not_revived_after_the_re_vote` | Cast sends the ballot on screen; confirming a ballot drops the PIN's older ones, and a ballot cast before a confirmed one is never confirmed (Sec. 3.9 step 10) |
| `confirming_an_older_ballot_neither_counts_it_nor_strands_the_newer` | a ballot is not confirmed once a NEWER ballot of the same PIN is on the board, and confirming never drops a newer ballot (Sec. 3.9 step 10) |
| `confirming_a_ballot_keeps_a_newer_one_not_yet_cast` | confirming forgets only the ballots of the PIN built before it |
| `a_late_published_older_ballot_cannot_be_confirmed_over_the_re_vote` | an older ballot published after the re-vote cannot be confirmed over it: "most recent" is read from the board (Sec. 3.9 step 10) |
| `one_board_reading_decides_both_superseded_and_published` | the checks that no newer ballot is on the board and that this ballot is published come from one reading, so a box cannot publish the re-vote and then the older ballot in between (Sec. 3.8.4 steps 6-8, Sec. 3.9 step 10) |
| `a_failed_release_is_asked_again_not_tallied_as_empty` | the tally asks a box whose release failed again instead of tallying it as empty (Sec. 3.9 steps 2-3, A9) |
| `a_digest_published_by_another_box_releases_the_ballot` | a box releases a confirmed ballot whose digest any box published, not only itself (Sec. 3.9 step 3) |
| `a_box_that_stays_silent_at_release_stops_the_tally_rather_than_lose_a_ballot` | a counted ballot no box released while a box that published it stays silent stops the tally (nothing published) instead of being dropped (Sec. 3.9 steps 2-3) |
| `releasing_on_another_boxs_digest_is_not_misconduct` | an honest box releasing a ballot on another box's digest entry is not accused by the audit |
| `a_release_a_box_writes_to_the_board_is_tallied` | a release a box writes to the board itself is taken into the tally, whatever it answered the driver, and the audit agrees (Sec. 3.9 step 2) |
| `a_release_written_after_the_tally_started_is_named_not_counted` | a release written after the tally's first artifact changes nothing the tally used: the audit names it and passes |
| `a_release_just_before_the_tally_starts_is_named_not_counted` | the tally's first artifact states the release entries it took in, so a release landing just before it is named, not counted, and the audit of the correct tally passes (Sec. 3.9 steps 2-3, Sec. 3.10 1(b)) |
| `copies_of_a_released_ballot_do_not_stop_the_tally` | a box writing copies of a ballot already taken in cannot stop the tally: only a release that would add a counted ballot stops a run (Sec. 3.9 step 3) |
| `a_missing_ballot_released_after_the_reading_stops_the_run` | a counted ballot a box withheld and writes to the board after the driver's reading stops the run before the tally starts; the next run counts it |
| `a_trusted_dishonest_teller_cannot_veto_a_re_send` | the PIN request goes to every teller and any t_RT of them rebuild the credential; the trusted selection cannot let one dishonest teller veto a re-send (Sec. 3.6.3, Sec. 3.12) |
| `a_trusted_dishonest_teller_cannot_veto_the_credential_after_a_revocation` | the same after a revocation, when the voter has no credential left |
| `changing_the_trusted_tellers_before_the_pin_arrives_does_not_strand_it` | a change of trusted tellers while the PIN is on its way does not strand it (Sec. 3.12) |
| `a_silent_box_that_holds_a_ballot_it_did_not_publish_stops_the_tally` | a counted ballot no box released stops the tally while ANY box is silent, not only one that published its digest, and names, per missing ballot, its publishers, its confirmers, the silent boxes that may hold it and the boxes that answered without releasing it; once the box answers the ballot is counted (Sec. 3.9 steps 2-4) |
| `the_operator_can_tally_without_a_box_that_stays_silent` | a box that publishes a digest and confirmation for a ballot nobody cast and then stays silent stops the tally only until the operator names it to proceed without (`--proceed-without`, Sec. 3.9 step 4); an id that is no ballot box is refused |
| `golden_determinism` | the full 8-voter flow reproduces `tests/e2e/golden/expected.json` field-by-field |
| `wbb_ui_smoke` | public page + proxy endpoints respond; digest search finds a cast ballot; four forgeries published to the real board with a ballot box's REAL key (a string `bb_id`, the other box's id with markup in the emoji, and the same two for a confirmation, plus an entry carrying both signer forms) count for nothing and are shown as ignored; both servers send `Content-Security-Policy` and the page writes entry data as text only |
| (library) `a_credential_share_is_checked_against_the_dealers_commitments` | each of x, sigma and r is covered, and a share offered under another party's index is refused |
| (library) `a_zeta_vss_deal_that_is_not_the_tellers_own_is_refused` | a whole deal from an outsider sealed to the same published key shares, a deal for another session, and a deal that is not one per party |
| (library) `a_credential_control_share_is_checked_against_its_own_key_share` | a party that states a key share it did not prove under is refused, and the accepted shares must interpolate to pk_RT |
| `wbb_wall_clock_enforces_freshness_window` | a wall-clock WBB refuses a logical-tick timestamp (400) and sequences a fresh one on real time |

### Determinism and golden artifacts

The whole PoC is deterministic under test: a committed test master seed drives SHAKE256-derived per-actor seeds and ChaCha20 RNGs, a logical clock (`clock.mode: logical`, `base_ms + tick * tick_ms`) replaces wall time in every artifact, and TLS material is seed-derived. Real runs select `clock.mode: wall` and stamp the same artifacts with Unix time; the one other thing that changes is the voter app, which then draws the voter's own secrets - the passphrase, the app key, the ballot randomness, an app-drawn decoy PIN - from the OS CSPRNG rather than from the ceremony-derived seed. `golden_determinism` re-runs the full 8-voter election and compares the master seed, election-context hash, every WBB entry's data hash, all ballot emoji vectors, the tally counts, and the WBB tree size + checkpoint root against the committed `tests/e2e/golden/expected.json`. Regenerate it after an intentional protocol change with:

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

The thesis fixes its threat model in Sec. 6.3.1 (assumptions A1-A10): the electoral roll is honest (A4), the bulletin board's integrity holds (A3), the identity provider is reliable (A5), at least one ballot box is honest (A9), and the coercer is the primary adversary.

This register lists what is STILL OPEN: where the implementation departs from the thesis, what that costs, and why it was accepted. Deviations that have since been closed are not listed - the protocol they implement is simply the thesis's, and the code and its tests say so. Rows that were closed only in part appear here with the part that remains.

Each row is linked to the thesis section it departs from:

| # | Deviation | Reason |
|---|---|---|
| 1 | Cast-as-intended control values are taken mod 100 with a code and a sum per level; the referendum optimisation of Sec. 3.11 (one code, mod 10) is not applied to the BALLOT. The voter is asked for ONE selection, as in Sec. 3.11: the candidate level opens a fixed, public slot, because a referendum has one candidate per option, `Ca = 0` for every ballot, both candidate values are always the same number and that check (`s_Ca + Ca = s_Ca`) holds identically for every honest ballot - knowing the slot in advance gives a device nothing | the library fixes `CAI_POW = 100` and the two-level proof structure at compile time |
| 2 | The setup ceremony runs the key generations in one process and deals the RT/TT share files (a trusted dealer), instead of the per-party DKG of Sec. 3.5.1-3.5.2 | PoC simplification: the library already offers the per-party rounds; running them over HTTPS between the tellers is not built yet. The ceremony therefore knows every seed it derives: the actors' keys, the electoral roll's identifier assignment and the bulletin board's log key. The board itself is handed only its own log seed, never the master seed |
| 3 | Ruse PIN via `VotingCredentialBuilder::simulate(ruse_pin)` (voter-side) | paper's trusted/untrusted-RT share substitution not exposed by the library; semantics preserved (local verify passes, tally filters) |
| 4 | PIN/mask delivery (Sec. 3.6.3) simplified: `voter_build_acc` yields builder + PIN directly | library API shape; shares still fetched over HTTPS from >= t_RT RTs |
| 5 | New-device recovery uses an encrypted server state blob + passphrase check | library `VoterSecretKey::recover` is not public |
| 6 | The OAuth2/OIDC flows of Sec. 5.3 are replaced by opaque tokens minted and checked by the electoral roll: a registration token (a bearer token, reused for the voter's requests) and single-use PIN-request and retrieval tokens. The CASTING token is the Commitment Access Token of Sec. 5.2 as specified: the electoral roll's signature over `commB`, one per ballot box, time-limited, verified by the ballot box alone (signature, audience, expiry, commitment; a token is bound to ONE ballot through `commB`, so it can admit no other, and the same ballot arriving again is an idempotent replay) - the electoral roll never sees a redemption and the token names nobody. A token issued before a revocation stays usable until it expires; such a ballot carries the revoked credential and is dropped by the credential filter at tally. Casting policy: at most `max_casts_per_voter` different ballots, and `min_cast_interval_s` between two of them | PoC scope for the identity-provider side; the casting path follows the thesis |
| 7 | Under test, WBB timestamps are logical and the fork's server-side freshness check is disabled (fork timestamp patch); on the wall clock (`clock.mode: wall`, the demo default) timestamps are real Unix time and the check is enforced | determinism of the test suite |
| 8 | Enrollment shares the bulletin board's `setup` write window (the board has 3 phases, as in Sec. 3.4.2). The write-permission table EXTENDS Sec. 3.4.2 with the electoral roll's `revocation_commitment` (setup and voting) and `eligible_vids` (tallying), which Sec. 3.7.5 and Sec. 3.9 step 1 require but the permission list omits | the thesis lists no write permission for those two publications |
| 9 | In-memory stores in all services (no persistence) | PoC; matches the library's own `InMemoryBB` |
| 10 | The counting rule is the thesis's (Sec. 3.9 steps 3 and 5, Sec. 3.10 1(c)-(d)): a ballot counts when at least ONE ballot box published its digest during voting and at least ONE published a cast-as-intended disclosure that opens on the released ballot - any box's release will do. The encrypted ballot-box identifiers are published but never multiplied or decrypted (Sec. 3.8.4 step 5, Sec. 3.9 step 4), and carry no proof of correct encryption (Protocol 9); fewer than two publishers is shown to the voter and on the board page as the bottom symbol's warning ("cast again is safer"), never used to discard. An earlier version required TWO boxes for both the digest and the confirmation: that handed one dishonest box a veto over any ballot it chose, indistinguishable on the board from a voter who never confirmed - the thesis relies on one honest box (A9) | what one honest box cannot prevent under this rule: a ballot that reached ONLY the dishonest box (the honest one unreachable from the voter at that moment) can have its digest published by that box at a time of its choosing within the voting phase, so a coerced ballot cast that way could be made the voter's "most recent" one; the device and the board show such a ballot as published by one box only, and the voter's remedy is to cast again. Bounding it further would take the casting token's validity checked by the board (Sec. 5.2) |
| 11 | **Trust assumption**: TT `/decrypt/*` endpoints act as decryption oracles for callers holding the service bearer token (the tally driver) | mitigations: per-service bearer tokens (constant-time compared), full artifact audit trail on the WBB - every decryption the TTs perform is published and re-verified by the auditor, including the master-key binding of every share |
| 12 | **Credential generation (Sec. 3.5.4) runs inside `election-admin`**, a trusted dealer: it holds all RT share files, the RT signing keys and the RT operation seeds, learns every credential secret and PIN, and (in the demo and the test harness) signs the `acc_pub_key` entry in the tellers' names. Whoever holds the three operation seeds can regenerate every share | PoC simplification, same class as #2: the library exposes every round per party. What each SERVICE loads is split correctly - one share file per teller with only its own shares (a foreign share is refused), and the ER sees `A` and `E[A]` only - but the demo runs every service as one user in one directory, so file modes isolate nothing between tellers there. Services read their file at startup: a teller or ER started before `gen-credentials` must be restarted. The mixes' randomness - the permutation, the re-encryption and the shuffle argument's commitment randomness - is drawn from the operating system on a real run, so the seed files no longer recompute a published permutation; under the harness's logical clock it is a function of the three teller seeds, as everything else is there |
| 13 | Fail-closed instead of filter for Sec. 3.9 step 5 / Sec. 3.10 1(e): a RELEASED ballot whose proofs do not verify aborts the tally. Everything a single box can do wrong is an attributed WARNING in the audit - a release without a disclosure of its own, a disclosure that does not open on the released ballot, a confirmation for a digest the box never published, a counted ballot it did not release, a ballot no box released (named to the boxes that published its digest, Sec. 3.9 step 4) - and the ballot is counted or not exactly as the driver counted it. The audit FAILS only for what is not the word of one box: a mix or proof that does not verify, a reconciled list that does not match the published mix, a decryption not bound to the tellers' shares | a deliberate choice, not a library limit: one dishonest box (A9 allows one) must not be able to fail an honest election's audit, only to be named in it; and a silent box stops the tally only for as long as a counted ballot is missing: the driver then publishes nothing (the box may hold that ballot and be merely unreachable) and the operator either runs it again once the box answers or names the box with `--proceed-without`, after which the tally goes on without it and logs that it did (Sec. 3.9 step 4) |
| 14 | **Trust assumption**: the tally driver (`election-admin`) holds the ballot boxes' signing keys and the tellers' seeds, and signs the `encrypted_ballot` entries on the ballot boxes' behalf. It drops any released record whose receipt names another ballot box, and the auditor requires every released receipt (ballot box, sequence number, arrival time) to be the one that box published when it accepted the ballot. The order that decides which of a voter's ballots is the last one is NOT a ballot box's own sequence number but the bulletin board's: the leaf its first acceptance was published at, recomputed by the auditor and by the tally driver from the same rule, each verifying the tree head against the ceremony-pinned log key before reading it. Every tally artifact - releases, mixes, proofs, result - is signed as the pipeline produces it, each teller's co-signature checked against the key pinned for that teller at the ceremony (a teller returning a signature that does not verify is named before anything is published), and submitted only once the LAST step has succeeded; the signed set is saved first (`tally-outbox.json`), so a submission cut off part-way - a lost request, a board restart - is finished by the next run instead of stranding the election, and a board holding a complete tally refuses a second run. Every teller's partial decryption is held to the public key share published for that teller at setup (`setup,ER,tt_public_shares`, from the ceremony; Protocol 12 proves a share against the shared key, not one the prover names): a teller answering under a key of its own, or with partials of a shape the other tellers do not share, is set aside and named, and the step goes on with any t_TT good tellers. What the driver CANNOT do is deal or alter the tellers' threshold blinding: every zeta VSS broadcast is signed by the teller that dealt it with its ceremony-pinned key, and each teller refuses a deal that is not signed, that does not carry exactly one broadcast per teller, or that does not carry its OWN broadcast unchanged (Sec. 2.8 Protocol 2 steps 4 and 6) | same trusted-coordinator class as #11 and #12; in the thesis each authority publishes its own entries. Holding the tellers' operation seeds remains a real power in the demo: a proof nonce is derived from the teller's seed and a counter, so whoever holds the seed can recompute the nonce of a published proof and solve for that teller's secret. In a deployment the seeds belong to the tellers alone; the counter is kept in a durable per-teller ledger so that a restart cannot re-use a nonce. Both kinds of teller keep one here: the registration tellers' `rt-{i}-nonce-ledger.json` is created by the ceremony beside the seed it paces, sealed under that seed, written through a temporary file and a rename so a crash leaves a whole ledger or the previous one, and a teller that finds none refuses to start rather than draw from zero over a used seed. A ledger RESTORED FROM AN OLDER BACKUP carries a valid seal over stale counters and nothing on the device can tell; so on a real run (wall clock) every nonce of both kinds of teller also carries fresh entropy from the operating system, and two processes never share a nonce whatever the counters say - the counter remains as a second line. Under the harness's reproducible logical clock the stream is deterministic and a rollback WOULD replay, which is one more reason that mode never runs a real election. What remains is the operational cost: every nonce any teller endpoint needs is one serialised disk write, and `/credentials/dvnizkp/round1`, which draws one, is repeatable by whoever holds a device's DV session (the device cracker of Ch. 6), so one such caller can slow every other draw on that teller, the tally's control round included. The shuffle arguments' Pedersen commitment key is DERIVED, by prover and verifier alike, from the election context hash, the step's label and the list length (`ElectionContext::mix_parameters`), and a mix artifact carrying any other key is refused: Groth's argument is sound only while the prover knows no discrete-log relation among the commitment generators, which a key the mixer sampled and shipped asked the verifier to take on trust. The arguments' Fiat-Shamir transcript absorbs the STATEMENT - the key, the list length, the original list and the shuffled list - before any prover message (Sec. 2.10.2 hashes "all the public values involved in the ZKP, including ... the common value x"), and a malformed artifact is refused rather than indexed into. The roll's tokens are fresh from the operating system on a real run. The wall clock is the DEFAULT clock mode and the reproducible logical mode must be asked for by name in every configuration; both kinds of teller ledger are created by the ceremony, sealed, written through a temporary file, flushed and renamed, and a missing one stops the teller |
| 15 | After a bulletin-board restart the PENDING staging area and the validator signatures start empty (entries, phase and the record of which threshold entries are already published - with their signers - are restored from the log) | validators re-sign on their own; partial signatures that had not reached publication are lost and must be re-submitted. Published ones are restored precisely so a replay of the signatures the log serves cannot open a second round for the same data |
| 16 | The notification service accepts announcements without authenticating the teller, and its per-voter endpoints are unauthenticated with guessable request ids (`rid-{vid}-{counter}`), so anyone who can reach it can also see who is enrolling: anyone who guesses a voter's `(vid, rid)` - identifiers can be enumerated in `1..=n_ACC` and a request id is the identifier plus a counter - can make the app's `pin_ready` flag turn true early, and `/register` answers 201 for a request id it has not seen and 200 for one it has, which tells a prober which `(vid, rid)` pairs are real. Nothing is disclosed and no token is spent - the tellers themselves still refuse until tau is over - but the flag is only a hint | the notification service and the identity provider are stubs (Sec. 3.2.2 lists them as services, apart from the trusted authorities; the identity provider is out of scope by A5). The same stub stands behind REVOCATION: `/api/revoke` re-authenticates the voter through it on the fiscal id the device already holds, so on this PoC the passphrase alone revokes - and a revocation voids every ballot cast on the old credential, including a confirmed one (Sec. 3.7.5, Sec. 3.9 step 1). In the thesis the voter proves their digital identity again (Sec. 3.7.5 step 3 sends them through a new registration), which A5 assumes is reliable; requiring the PIN instead would contradict Sec. 3.7.5, whose case is a voter who has LOST access to their credential. The converse also holds and is OPEN: without the passphrase this PoC offers no revocation, no recovery and no re-enrollment, where Sec. 3.7.4 step 5 sends a voter who cannot retrieve their passphrase to a revocation on their digital identity alone (Sec. 3.7.5 steps 1-3). The enrollment narrows that case by handing over the passphrase as soon as the roll holds the device key, whatever happens to the requests after it |
| 17 | Revocation commitments (Sec. 3.7.5) are published as salted hashes and never opened: nothing on the board says that a revocation really took effect, or that the spare handed to the voter is the one committed. The salt is derived from the roll's operation seed and the old identifier, so that a lost answer can be recognised and the same spare adopted on retry - which means whoever copies `er-seed.bin` (the curious authority's exfiltration, Sec. 6.3.1) can open every commitment by trying the `n_ACC x n_ACC` candidate pairs; the hiding is conditional on that file | opening them would reveal exactly the (old, new) linkage the commitment exists to hide. What the voter CAN check is that the identifier they were given - first or spare - is a leaf of the identifier tree published at setup, which the app verifies on every login and on revocation. Leaves are tagged: an identifier committed to a voter and a spare are different leaves, so neither can be passed off as the other, and a revoked voter can log in again on their proved spare |
| 18 | The device-recovery blob the electoral roll stores for a voter carries no version or freshness marker, so a roll could serve an older session state to a recovering device (a dishonest roll is beyond the thesis's model, A4; a lost or rolled-back store is not). The device refreshes the blob after every change and goes on when the roll refuses the refresh - the change is committed either way - so a refresh the roll refused leaves the roll holding the PREVIOUS state (a decoy since disarmed, a PIN since re-sent) until the next successful refresh, and a recovery in that window brings it back | the blob is encrypted with the voter's passphrase and the roll cannot read or forge its contents; a rolled-back state loses cast records, which the voter can still check on the board |
| 19 | *(accepted for the PoC)* A coercer holding a ruse PIN can spend the voter's whole casting budget (`max_casts_per_voter`, counted per identifier, default 10 and therefore on in every run), after which the voter cannot cast the real ballot - the decoy alone is enough to do it; and the budget itself talks: a coercer who hits the limit earlier than their own casts account for learns how many ballots the voter cast without them | the electoral roll cannot tell a ruse ballot from a real one - that is what makes the ruse work. A per-credential budget would need the roll to distinguish them. The thesis has no per-voter cap, only the rate limit of Sec. 5.3 (`min_cast_interval_s` here), which leaks nothing; dropping the cap is the candidate fix |
| 20 | The electoral roll keeps revocations in memory (#9): after a restart it names the voter's ORIGINAL identifier again, so the ballot cast on the spare is dropped and the revoked credential becomes eligible once more | the board carries the revocation commitments, so the state could be rebuilt from it at startup; not done yet |
| 21 | The tally driver tolerates n - t_TT tellers that fail, answer under the wrong key, with the wrong shape, or with a partial whose proof does not hold - at every threshold DECRYPTION and at every threshold BLINDING, and n_RT - t_RT registration tellers at both credential-control rounds and at the co-signature of the entry they publish (Sec. 3.9 step 16 applied to both: each answer is verified on its own, a bad one is set aside and NAMED, and any threshold of good ones finishes the step). It still needs EVERY tabulation teller for the zeta VSS round 1 and for the TT co-signatures (those entries are declared with threshold 3 = n_TT); a teller down at those steps stops the tally cleanly (#14) | the TT co-signature threshold is a board-policy matter; the VSS one is the library's `gen_zeta_vss_round1(n, t)` contract |
| 22 | The device state - and the recovery blob (#5), which is the same serialised session without the ballots - holds the real PIN (re-displayed on retrieval) and the ruse PIN inside the passphrase-encrypted envelope. Nothing about a BALLOT is written to either: Sec. 3.6.1 lists what the app saves encrypted - keys, public ACC, masked private ACC, passphrase - and a ballot, a disclosure and a receipt are not among them, so held ballots, their control values, their openings and their `ruse` flag live in memory for as long as the process does. Sec. 3.6.3 stores the truncated mask `sigma - PIN` and the DVNIZKP, never the PIN, and in Sec. 3.7.3 the ruse credential simply REPLACES the stored one, so the stored state tells no ruse story. Whoever holds both the passphrase and the bytes (a device cracker, or a coercer who forces the passphrase and recovers on their own device) learns the valid PIN, but no ballot and no opening | consequence of #3 (the ruse is a voter-side simulation, so the app must know which credential is the ruse) and of the PoC re-displaying the PIN. The passphrase is machine-generated (6 words of a 2048-word list, 66 bits) and the key is one SHA3-256 of salt and passphrase: adequate for a random 66-bit secret, not for a user-chosen one; a memory-hard KDF (Argon2id) is the proper hardening and is not applied here, because the passphrase is re-derived on every API call. The SIZE says nothing: every state is padded to a 64 KiB bucket, which covers a full session with both held ballots and every cast |
| 23 | A ruse request is distinguishable from a PIN re-send on the WIRE: its only network effect is one recovery-blob upload, where a re-send produces token, notification and teller traffic. Sec. 3.7.3 pads the ruse request so that the untrusted tellers take it for a re-send. The blob itself no longer tells: every encrypted state is padded to a fixed bucket (16 KiB), so a curious roll holding every voter's blob cannot sort voters into "armed a ruse" and "did not" (`the_recovery_blob_size_does_not_reveal_a_ruse`) | consequence of #3; a decoy re-send round-trip would close the traffic pattern |
| 24 | The registration tellers' `/sign` is a blind co-signing oracle for their own entries: a caller holding their service tokens can have them co-sign data they never produced. The tabulation tellers' is not - a teller refuses a tally artifact carrying a blinding share in its name that it did not produce | the tally artifacts are covered; the registration tellers' entries are not, and the driver holds their tokens (#12, #14) |
| 25 | The confirmation time the app shows and stores is the DEVICE's clock at the moment the disclosure was sent (Sec. 3.8.4 step 12: a time that does not match the real one is a symptom that something is wrong with the device), never a ballot box's claim; the board page shows the board's sequencing timestamp for every publication, with the box's self-declared arrival time marked as such (Sec. 3.8.4 step 4, Sec. 3.8.5 1(b)-(c)) | a box's claimed time was displayed as the confirmation time |

## Thesis traceability

Every voter (V) and authority (A) action of the protocol is executable through the public API and covered by a test:

| # | Action | Thesis | Implementation | Test |
|---|---|---|---|---|
| V1 | eID login + app init | Sec. 5.3.1.1, 3.6.1 | `voter-server /api/login` -> DIP + ER | `referendum_happy_path` |
| V2 | Enrollment (DV keys, passphrase, vid) | Sec. 3.6.1 | `/api/enroll` | `referendum_happy_path` |
| V3 | PIN request (tokens, RT registration, tau) | Sec. 5.3.1.2-5.3.1.3 | `/api/enroll` -> RT `/credentials/request` + NS | `referendum_happy_path` |
| V4 | PIN delivery (>= t_RT shares, DVNIZKP) | Sec. 5.3.1.4-5.3.1.5, 3.6.3 | `/api/status`, `/api/pin/retrieve` | `referendum_happy_path` |
| V5 | PIN verification (unlimited) | Sec. 3.7.1 | `/api/pin/verify` | `referendum_happy_path`, `voter_enrolls_and_verifies_deterministic_pin` |
| V6 | PIN re-sending | Sec. 3.7.2 | `/api/pin/resend` | `a_re_send_delivers_the_voters_own_pin` |
| V7 | Ruse PIN (after a ruse request only the ruse PIN verifies locally, Sec. 3.7.3; the valid PIN still casts a counted vote) | Sec. 3.7.3 | `/api/pin/ruse`, `/api/pin/verify` | `coercion_ruse_pin`, `pin_management` |
| V8 | New-device registration | Sec. 3.7.4 | `/api/device/recover` | `new_device` |
| V9 | ACC revocation + re-issue | Sec. 3.7.5 | `/api/revoke`, ER `/revocations` | `revocation` |
| V10 | Trusted RT/BB selection | Sec. 3.12 | `/api/settings/trusted` | `referendum_happy_path`, `pin_lifecycle_ruse_resend_recover_revoke_trusted` |
| V11 | Vote (3 options, PIN, BallotEmoji) | Sec. 3.8.2, 3.11 | `/api/vote` | `referendum_happy_path` |
| V12 | Cast with CAT | Sec. 5.3.1.6, 3.8.4 | `/api/cast` -> ER `/tokens/casting` + BB `/ballots` | `referendum_happy_path`, `rate_limit_and_cat`, `idempotent_casting` |
| V13 | Confirmation + CAI disclosure with the voter's post-cast choice of the opened value (load-bearing: only confirmed ballots are released/counted, Sec. 3.9 step 2) | Sec. 3.8.4 steps 8-17 | `/api/cai/values` (after the cast), `/api/confirm {l1, l2}` -> BB `/cai` (decodes + publishes the opened value); BB release filter; auditor `published_entries`, `cai_confirmation` and `published_emoji` (EVERY confirmation a BB published opens, on the released ballot, to the values it shows - not just the last one; every ballot emoji and public PIN emoji a BB published under its own signature is the one its released ballot hashes to; an entry naming a ballot box that did not sign it, or one that cannot be read, fails the audit and is ignored by the app and the board page. The emoji of a ballot that is never released - unconfirmed, or withheld - cannot be checked by anyone but the voter) | `referendum_happy_path`, `cai_choice_after_cast`, `unconfirmed_ballot_excluded`, `auditor_detects_tamper` |
| V14 | Manual verification (WBB page) | Sec. 3.8.5 | `/api/ballot/status`, `/api/verify/:digest`, `wbb-ui`. Both qualify "will be counted" with "unless you cast again" - the board cannot see the credential, so a superseded ballot still looks counted there (`a_wrong_pin_ballot_dies_and_the_last_valid_ballot_wins`) - count a publication only when it is well-formed and signed by the ballot box it names (an entry carrying both signer forms counts for nobody, exactly as in the auditor), report a ballot as counted only when at least 2 ballot boxes published BOTH its digest and a confirmation - read back from the board, never from a ballot box's own answer - show a published result only when the tabulation tellers' co-signature is there (checked server-side, both apps) and warn when two signed results disagree, relay the validators' semaphore as the board reports it (the BLS signatures behind it are verified by the auditor, not by the page), render entry data as text only (`Content-Security-Policy: default-src 'self'`), and TRUST THE BOARD THEY READ: they verify neither entry signatures nor the tree head (the board checks signatures on write), so a substituted board could show a voter anything - beyond the thesis's model (A3); that is what the auditor is for | `referendum_happy_path`, `wbb_ui_smoke` |
| V15 | Results viewing | Sec. 3.9 step 30, 3.10 | voter `GET /api/results`, wbb-ui results view, `election-admin results` | `referendum_happy_path` |
| A1 | Pre-setup parameters | Sec. 3.4 | `configuration/base.yaml` | configuration unit tests |
| A2 | Setup ceremony | Sec. 3.5 | `setup-ceremony`, ER `/admin/setup` | `referendum_happy_path`, `er_publishes_its_setup_entries_to_wbb` |
| A3 | ACC generation xn_ACC | Sec. 3.5.4 | `election-admin gen-credentials` | `referendum_happy_path`, `admin_generates_credentials_and_publishes_acc_pub_key` |
| A4 | Phase transitions (BB intake rolls back any ballot whose digest the WBB refuses, so a late cast is not stored) | Sec. 3.4.2 | `election-admin open-voting`/`close-voting` (PM-signed) | `wbb_policy_enforcement`, `late_cast_rejected` |
| A5 | Tally (full pipeline -> WBB) | Sec. 3.9 | `election-admin tally` | `referendum_happy_path` + every tally-flow test; `a_ballot_one_box_withholds_is_still_counted`, `a_ballot_every_box_withholds_is_not_counted_and_both_boxes_are_named`, `a_tally_that_fails_part_way_leaves_the_board_untouched`, `the_board_orders_the_tally_not_the_ballot_boxes` |
| A6 | Universal verification | Sec. 3.10 | `referendum-auditor` | `referendum_happy_path`, `auditor_detects_tamper` |
| A7 | Eligible-vid publication | Sec. 3.9 step 1 | ER `/admin/eligible-vids` (driven by the tally) | `referendum_happy_path`, `revocation` |

## License

See the upstream repositories for licensing terms.
