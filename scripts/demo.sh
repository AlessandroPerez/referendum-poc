#!/usr/bin/env bash
#
# referendum-poc demo : boots the whole cluster locally for a
# manual browser demo - ceremony, WBB (Go sunlight fork), DIP/NS/ER, RT x3,
# TT x3, BB x2, one voter-server, and the public wbb-ui.
#
# Prerequisites: Rust stable, Go >= 1.24, sqlite3, and the sibling
# `../resources/sunlight_test` checkout (branch referendum-poc-wbb).
#
# Usage: ./scripts/demo.sh [ceremony-output-dir]
# Stop with Ctrl-C; all services are killed on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/demo-ceremony}"
WBB_SRC="$ROOT/../resources/sunlight_test"
# blst SIGILLs on pre-ADX CPUs without the portable build (see README).
export CGO_CFLAGS="${CGO_CFLAGS:--O2 -D__BLST_PORTABLE__}"

echo "==> Building the Rust binaries"
cargo build --manifest-path "$ROOT/Cargo.toml" --bins

echo "==> Building the WBB (sunlight fork)"
mkdir -p "$ROOT/target/wbb-bin"
(cd "$WBB_SRC" && go build -o "$ROOT/target/wbb-bin/sunlight" ./cmd/sunlight)
(cd "$WBB_SRC" && go build -o "$ROOT/target/wbb-bin/wbb-validator" ./cmd/wbb-validator)

echo "==> Running the setup ceremony -> $OUT"
rm -rf "$OUT"
# Real (wall-clock) timestamps for the demo; the test suite keeps the
# reproducible logical clock.
"$ROOT/target/debug/setup-ceremony" -c "$ROOT" -o "$OUT" --clock wall

pids=()
cleanup() {
    echo
    echo "==> Shutting down"
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# WBB validators (demo only): independent parties that rebuild the log's
# Merkle tree, verify it against the signed checkpoint and BLS-sign every
# leaf. Their public keys are registered with the WBB before it starts.
N_VALIDATORS=3
echo "==> Generating $N_VALIDATORS validator BLS keys"
(
    umask 077
    for i in $(seq 1 "$N_VALIDATORS"); do
        head -c 32 /dev/urandom >"$OUT/validator-$i-seed.bin"
    done
)
{
    echo "    validator_bls_keys:"
    for i in $(seq 1 "$N_VALIDATORS"); do
        key=$("$ROOT/target/wbb-bin/wbb-validator" -name "V-$i" \
            -seed-file "$OUT/validator-$i-seed.bin" -print-key)
        echo "      V-$i: $key"
    done
} >>"$OUT/sunlight.yaml"

echo "==> Starting the WBB on https://127.0.0.1:8090/wbb/"
(cd "$OUT" && exec "$ROOT/target/wbb-bin/sunlight" -c sunlight.yaml -testcert) \
    >"$OUT/wbb.log" 2>&1 &
pids+=($!)
# Fail fast, with the WBB's own log, instead of letting every later step
# hit "connection refused".
for _ in $(seq 1 30); do
    if curl --silent --fail --cacert "$OUT/ca.pem" https://127.0.0.1:8090/health >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "${pids[-1]}" 2>/dev/null; then
        echo "!! the WBB exited during startup - $OUT/wbb.log says:" >&2
        grep -v '^{' "$OUT/wbb.log" | tail -5 >&2
        exit 1
    fi
    sleep 0.5
done
if ! curl --silent --fail --cacert "$OUT/ca.pem" https://127.0.0.1:8090/health >/dev/null 2>&1; then
    echo "!! the WBB did not become ready in 15s - see $OUT/wbb.log" >&2
    exit 1
fi

# Validators are deliberately slow (a few seconds per leaf, each one slower
# than the previous) so the public page shows signatures landing one by one.
echo "==> Starting $N_VALIDATORS WBB validators"
for i in $(seq 1 "$N_VALIDATORS"); do
    "$ROOT/target/wbb-bin/wbb-validator" -name "V-$i" \
        -seed-file "$OUT/validator-$i-seed.bin" \
        -log https://127.0.0.1:8090/wbb -cacert "$OUT/ca.pem" \
        -interval 1s -delay "$((2 + 2 * i))s" \
        >"$OUT/validator-$i.log" 2>&1 &
    pids+=($!)
    echo "    V-$i (delay $((2 + 2 * i))s, $OUT/validator-$i.log)"
done

# Start one service binary with cwd = ceremony dir (keys, shares, tokens and
# election_context.json resolve relative to it) and per-service overrides.
start_service() {
    local name="$1" port="$2" bin="$3"
    shift 3
    (
        cd "$OUT" &&
            env APP_SERVICE__NAME="$name" APP_SERVICE__PORT="$port" \
                APP_TLS__CERT_PEM="$OUT/$name.pem" \
                APP_TLS__KEY_PEM="$OUT/$name-key.pem" \
                APP_TLS__CA_PEM="$OUT/ca.pem" \
                "$@" \
                "$ROOT/target/debug/$bin"
    ) >"$OUT/$name.log" 2>&1 &
    pids+=($!)
    echo "    $name on https://127.0.0.1:$port ($OUT/$name.log)"
}

# Credentials must exist before the ER and the RTs boot: each loads only its
# own file from output/ at startup (the ER never sees a teller share, a teller
# never sees another teller's).
echo "==> Generating credentials (A3) and publishing acc_pub_key"
"$ROOT/target/debug/election-admin" -c "$OUT" gen-credentials

echo "==> Starting the services"
start_service dip 8002 dip-server
start_service ns 8003 ns-server
start_service er 8001 er-server
start_service rt-1 8011 rt-server
start_service rt-2 8012 rt-server
start_service rt-3 8013 rt-server
start_service tt-1 8021 tt-server
start_service tt-2 8022 tt-server
start_service tt-3 8023 tt-server
start_service bb-1 8031 bb-server
start_service bb-2 8032 bb-server
# Three voter apps: the tally's verifiable mixes need at least 3 ballots.
for i in 1 2 3; do
    start_service "voter-$i" "900$i" voter-server \
        APP_VOTER__STATIC_DIR="$ROOT/static" \
        APP_VOTER__STATE_DIR="$OUT/voter-$i-state"
done
start_service wbb-ui 9100 wbb-ui \
    APP_WBB_UI__STATIC_DIR="$ROOT/static-wbb"
sleep 2

echo "==> Publishing the ER setup entries (A2)"
# Header via file so the admin token never appears in argv (/proc-visible);
# created under umask 077 so it is never world-readable, even briefly.
(
    umask 077
    printf 'Authorization: Bearer %s\n' "$(cat "$OUT/er-admin-token.txt")" \
        >"$OUT/.admin-header"
)
curl --fail --silent --show-error --cacert "$OUT/ca.pem" -X POST \
    -H @"$OUT/.admin-header" \
    https://127.0.0.1:8001/admin/setup >/dev/null
rm -f "$OUT/.admin-header"

echo "==> Opening the voting window (A4)"
"$ROOT/target/debug/election-admin" -c "$OUT" open-voting

cat <<EOF

==========================================================================
 Demo cluster is up (all HTTPS, cluster CA: $OUT/ca.pem)

   Voter apps:            https://127.0.0.1:9001/  (fiscal id VOTER-001)
                          https://127.0.0.1:9002/  (fiscal id VOTER-002)
                          https://127.0.0.1:9003/  (fiscal id VOTER-003)
   Public bulletin board: https://127.0.0.1:9100/
   WBB log (raw):         https://127.0.0.1:8090/wbb/entries

 $N_VALIDATORS validators check the WBB's Merkle tree and BLS-sign every entry;
 the bulletin board shows a semaphore per entry (red: no signature yet,
 yellow: some, green: all) that turns green a few seconds after each
 entry is published.

 The TLS certificates are issued by the demo cluster CA, so the browser
 will warn on first visit - accept the exception (test-only PKI).

 Try: log in with a fiscal id, enroll, wait for the PIN, vote, cast, and
 press CONFIRM (the cast-as-intended disclosure - unconfirmed ballots are
 discarded at tally, manuscript 3.9 step 2).
 Cast+confirm at least 3 ballots (the verifiable mixes require it), then:
   ./target/debug/election-admin -c "$OUT" close-voting
   ./target/debug/election-admin -c "$OUT" tally
   ./target/debug/election-admin -c "$OUT" results
   ./target/debug/referendum-auditor -c "$OUT"

 Ctrl-C stops the cluster.
==========================================================================
EOF

wait
