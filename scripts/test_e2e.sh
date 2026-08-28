#!/usr/bin/env bash
#
# End-to-end test suite for simply_ip_exporter.
#
# Builds simply_ip_exporter and the reference simply_ip_vault checked out under example/, boots
# both against throwaway SQLite databases with deterministic bootstrap master keys (via
# INITIAL_MASTER_KEY / INITIAL_MASTER_SIGNING_SECRET — no log-scraping needed), and drives the
# whole workflow with curl + jq:
#
#   1. Environment setup: build + boot both instances, wait for /ready on each.
#   2. Vault provisioning: a scoped read-only key for the exporter, seeded with a contiguous/
#      overlapping pair of public addresses, a CGN "bogon" address, a dedicated address for the
#      soft-delete test, and (via a whitelist group, since simply_ip_vault refuses to /ban a
#      private address) an RFC 1918 address.
#   3. Exporter configuration: an HMAC CANONICAL_V1-signed POST /api/endpoints wired to those Vault
#      groups with ttl_seconds=2, filter_rfc1918=true, filter_bogons=true.
#   4. Feed verification: text/plain output, ipnet::IpNet::aggregate() merging the overlapping
#      pair, and both filters actually removing what they claim to.
#   5. HTTP optimizations & anti-DoS: ETag + If-None-Match -> 304 (and that a matching conditional
#      request is NOT rate-limited), then a bare repeat -> 429.
#   6. Vault soft-delete propagation: soft-delete a Vault record and confirm the next differential
#      sync (since=<last_synced_at>&include_deleted=true) removes it from the feed.
#   7. Hot-reload of endpoint configuration: flip filter_rfc1918 via a signed PUT and confirm the
#      very next feed request reflects it, with no exporter restart.
#   8. Client IP restriction (bound_ips): a dedicated endpoint scoped to 10.10.0.0/16 serves an
#      in-range simulated client and 403s an out-of-range one.
#   9. Restart & persistence recovery: SIGTERM simply_ip_exporter, restart it against the same
#      SQLite file, and confirm the Master key, a Daughter key minted before the restart (proving
#      its encrypted-at-rest signing_secret round-trips through EXPORTER_ENCRYPTION_KEY), and the
#      original endpoint all survive — then confirm the in-memory IP cache re-hydrates from Vault.
#  10. Wrong encryption key at startup: SIGTERM simply_ip_exporter again, attempt to restart it
#      against the SAME database with a different (but syntactically valid) EXPORTER_ENCRYPTION_KEY,
#      and confirm it exits non-zero with an explicit error rather than starting up with every
#      stored secret silently unreadable. Then restart it correctly so the suite can continue.
#  11. HMAC anti-replay: timestamp skew rejection: a validly-signed request timestamped +301s and
#      -301s from server time is rejected with 401, not accepted or silently ignored.
#  12. Real-time Daughter key rotation/revocation: rotate one Daughter key and delete another via
#      the Master key, and confirm each one's OLD credentials are rejected on the very next request
#      — no restart, no propagation delay.
#  13. Vault disruption & resilience: kill simply_ip_vault, confirm simply_ip_exporter keeps
#      serving the same in-memory cached feed without interruption.
#  14. Audit log traversal: fetch GET /api/audit-logs as Master and confirm every administrative
#      action performed during this run is present, correctly attributed, and timestamped.
#  15. Cleanup: terminate both processes and remove every temporary file.
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq, cargo, openssl. Needs example/simply_ip_vault present (a reference checkout;
# see AGENT.MD) and two free ports (defaults below; override with VAULT_PORT/EXPORTER_PORT).
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail
# Not `set -e`: several checks deliberately expect a non-2xx response (401/403/404/429), so a
# non-zero curl/jq exit inside a check must not abort the whole run.

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VAULT_DIR="$PROJECT_ROOT/example/simply_ip_vault"

VAULT_PORT="${VAULT_PORT:-13000}"
EXPORTER_PORT="${EXPORTER_PORT:-13002}"
VAULT_URL="http://127.0.0.1:$VAULT_PORT"
EXPORTER_URL="http://127.0.0.1:$EXPORTER_PORT"

# Deterministic bootstrap credentials — fixed rather than scraped from a (buffered) log, for both
# instances. Both services require INITIAL_MASTER_KEY to be exactly 64 hex characters (the same
# shape each generates for itself), so these are hex; the signing secrets have no such constraint.
# Distinct per service so a copy-paste mistake between the two is loud, not silent.
# How many records §2 seeds into pfBlocker_Pagination_Test, and §4b expects to survive intact.
# Must stay > Vault's default page (50) for the truncation guard to mean anything, and is chosen at
# 3214 to span exactly four pages at VaultClient's PAGE_SIZE of 1000 (1000+1000+1000+214) — so the
# bounded-parallel envelope path is exercised at its real page size, not a shrunken test one.
PAGINATION_RECORD_COUNT=3214
# 500 IPv6 records seeded into the same group, so the large-scale fixture exercises both
# families through one multi-page parallel fetch rather than proving IPv4 only.
PAGINATION_IPV6_COUNT=500
PAGINATION_TOTAL_COUNT=$((PAGINATION_RECORD_COUNT + PAGINATION_IPV6_COUNT))
PAGINATION_PAGE_SIZE=1000
PAGINATION_EXPECTED_PAGES=4

VAULT_MASTER_KEY="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
VAULT_MASTER_SECRET="e2e_vault_master_signing_secret_for_testing"
EXPORTER_MASTER_KEY="b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
EXPORTER_MASTER_SECRET="e2e_exporter_master_signing_secret_for_testing"
# 64 hex characters, as `openssl rand -hex 32` would produce. Fixed rather than random so a
# failed run leaves databases an operator can still open with the same value.
E2E_ENCRYPTION_KEY="0f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a6978"

# Maps a plaintext API key -> its HMAC signing secret, keyed by which service it belongs to
# (vault/exporter share nothing, but a key string collision is not a concern in practice).
declare -A SIGNING_SECRETS=()
SIGNING_SECRETS["$VAULT_MASTER_KEY"]="$VAULT_MASTER_SECRET"
SIGNING_SECRETS["$EXPORTER_MASTER_KEY"]="$EXPORTER_MASTER_SECRET"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simply_ip_exporter_e2e.XXXXXX")"
VAULT_DB_PATH="$WORK_DIR/vault.db"
EXPORTER_DB_PATH="$WORK_DIR/exporter.db"
VAULT_LOG="$WORK_DIR/vault.log"
EXPORTER_LOG="$WORK_DIR/exporter.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"
# Request bodies are handed to curl via `--data-binary @file`, never as a command-line argument:
# Linux caps a *single* argv entry at MAX_ARG_STRLEN (128 KiB), and §2's multi-thousand-record batch
# payloads run past that. Passing one inline made execve fail with E2BIG, which surfaced as an empty
# HTTP status rather than any error curl could report.
REQ_BODY_FILE="$WORK_DIR/req_body"
VAULT_PID=""
EXPORTER_PID=""

PASS_COUNT=0
FAIL_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────
#
# Every diagnostic/progress function writes to STDERR, never STDOUT: several helpers below hand a
# value back to the caller via plain globals, read via `$(...)` command substitution, which
# captures only stdout. Keeping stdout pristine is what keeps that robust.

ts() { date +"%H:%M:%S.%3N"; }
log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }
log_section() {
    echo "" >&2
    echo -e "$(ts) ${BOLD}${MAGENTA}=== $* ===${RESET}" >&2
}

status_color() {
    case "$1" in
        2??) echo -n "$GREEN" ;;
        401|403|404|409|429) echo -n "$YELLOW" ;;
        4??) echo -n "$YELLOW" ;;
        5??) echo -n "$RED" ;;
        *) echo -n "$RESET" ;;
    esac
}

print_response_body() {
    if [ -z "$RESP_BODY" ]; then
        echo -e "$(ts)          ${DIM}(empty body)${RESET}" >&2
        return
    fi
    local formatted
    if formatted=$(echo "$RESP_BODY" | jq . 2>/dev/null); then
        while IFS= read -r line; do
            echo -e "$(ts)          ${DIM}${line}${RESET}" >&2
        done <<< "$formatted"
    else
        while IFS= read -r line; do
            echo -e "$(ts)          ${DIM}${line}${RESET}" >&2
        done <<< "$RESP_BODY"
    fi
}

# Computes the full X-Signature-256 header value: `sha256=<hex>` over the CANONICAL_V1 string
# METHOD\nTARGET\nTIMESTAMP\nRAW_BODY (single LFs, no trailing newline). `printf` with an explicit
# format (rather than `echo`) is what keeps the delimiters real newlines and the message byte-exact.
# Usage: hmac_sign SECRET METHOD TARGET TIMESTAMP BODY
hmac_sign() {
    local secret="$1" method="$2" target="$3" timestamp="$4" body="${5:-}"
    printf 'sha256=%s' "$(printf '%s\n%s\n%s\n%s' "$method" "$target" "$timestamp" "$body" \
        | openssl dgst -sha256 -hmac "$secret" \
        | sed 's/^.*= //')"
}

# Last X-Timestamp used per distinct request identity, so a repeated identical call inside the
# same wall-clock second (which would otherwise reproduce a signature the server has already
# accepted, and be refused as a replay) gets a fresh one instead — exactly what elapsed time would
# have given a real caller.
declare -A LAST_SIGNED_AT
next_timestamp() {
    local identity="$1"
    local now; now=$(date -u +%s)
    local previous="${LAST_SIGNED_AT[$identity]:-0}"
    if [ "$now" -le "$previous" ]; then
        now=$((previous + 1))
    fi
    LAST_SIGNED_AT["$identity"]=$now
    SIGNED_TS=$now
}

register_key_secret() {
    local key="$1" secret="$2"
    if [ -z "$key" ] || [ "$key" == "null" ] || [ -z "$secret" ] || [ "$secret" == "null" ]; then
        err "register_key_secret called with an empty key/secret — the API response was malformed"
        return 1
    fi
    SIGNING_SECRETS["$key"]="$secret"
}

# Performs a signed HTTP request against a service base URL, leaving the outcome in
# $RESP_STATUS / $RESP_BODY. Usage: api_call BASE_URL METHOD PATH [API_KEY] [JSON_BODY] [X-Forwarded-For]
api_call() {
    local base="$1" method="$2" path="$3" api_key="${4:-}" data="${5:-}" xff="${6:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")

    if [ -n "$api_key" ]; then
        next_timestamp "$base|$method|$path|$api_key|$data"
        local timestamp="$SIGNED_TS"
        local secret="${SIGNING_SECRETS[$api_key]:-unregistered-key-has-no-signing-secret}"
        args+=(-H "X-API-Key: $api_key")
        args+=(-H "X-Timestamp: $timestamp")
        args+=(-H "X-Signature-256: $(hmac_sign "$secret" "$method" "$path" "$timestamp" "$data")")
    fi

    [ -n "$xff" ] && args+=(-H "X-Forwarded-For: $xff")
    if [ -n "$data" ]; then
        # `--data-binary`, not `-d`: `-d` strips newlines, and the HMAC signature above is computed
        # over the exact bytes, so any transformation curl applied would invalidate it.
        printf '%s' "$data" > "$REQ_BODY_FILE"
        args+=(-H "Content-Type: application/json" --data-binary "@$REQ_BODY_FILE")
    fi
    RESP_STATUS=$(curl "${args[@]}" "$base$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$base$path" >&2
    print_response_body
}

# As api_call, but for requests the signing helper cannot express (custom/extra headers such as
# If-None-Match). Usage: raw_call METHOD URL [curl args...]
raw_call() {
    local method="$1" url="$2"; shift 2
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" "$@" "$url")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$url" >&2
    print_response_body
}

check() {
    local expected="$1" description="$2"
    if [ "$RESP_STATUS" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    fi
}

check_jq() {
    local filter="$1" expected="$2" description="$3"
    local actual
    actual=$(echo "$RESP_BODY" | jq -r "$filter" 2>/dev/null)
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

check_local() {
    local actual="$1" expected="$2" description="$3"
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

check_contains() {
    local haystack="$1" needle="$2" description="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (did not find '$needle')" >&2
    fi
}

check_not_contains() {
    local haystack="$1" needle="$2" description="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (unexpectedly found '$needle')" >&2
    fi
}

cleanup() {
    if [ -n "$EXPORTER_PID" ] && kill -0 "$EXPORTER_PID" 2>/dev/null; then
        log "Stopping simply_ip_exporter (pid $EXPORTER_PID)..."
        kill "$EXPORTER_PID" 2>/dev/null || true
        wait "$EXPORTER_PID" 2>/dev/null || true
    fi
    if [ -n "$VAULT_PID" ] && kill -0 "$VAULT_PID" 2>/dev/null; then
        log "Stopping simply_ip_vault (pid $VAULT_PID)..."
        kill "$VAULT_PID" 2>/dev/null || true
        wait "$VAULT_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

wait_ready() {
    local name="$1" url="$2" pid="$3" logfile="$4"
    for _ in $(seq 1 60); do
        if ! kill -0 "$pid" 2>/dev/null; then
            err "$name exited during startup. Log:"
            cat "$logfile" >&2
            exit 1
        fi
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url/ready" 2>/dev/null)
        [ "$code" == "200" ] && return 0
        sleep 0.5
    done
    err "$name did not become ready in time. Log:"
    cat "$logfile" >&2
    exit 1
}

# ── Preflight ────────────────────────────────────────────────────────────────

log_section "Preflight"

for bin in curl jq cargo openssl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        err "$bin is required but not found on PATH"
        exit 1
    fi
    log "Found $bin: $(command -v "$bin")"
done

if [ ! -d "$VAULT_DIR" ]; then
    err "$VAULT_DIR not found. This suite needs the reference simply_ip_vault checkout under example/ (see AGENT.MD)."
    exit 1
fi

for port in "$VAULT_PORT" "$EXPORTER_PORT"; do
    if command -v fuser >/dev/null 2>&1 && fuser "$port/tcp" >/dev/null 2>&1; then
        err "Port $port is already in use. Stop whatever is bound to it, or override VAULT_PORT/EXPORTER_PORT."
        exit 1
    fi
done

# ── Build ────────────────────────────────────────────────────────────────────

log_section "Build"

log "Building simply_ip_vault in $VAULT_DIR ..."
if ! (cd "$VAULT_DIR" && cargo build --quiet 2>"$WORK_DIR/vault_build.log"); then
    err "simply_ip_vault build failed:"
    cat "$WORK_DIR/vault_build.log" >&2
    exit 1
fi
log "simply_ip_vault build succeeded."

log "Building simply_ip_exporter in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo build --quiet 2>"$WORK_DIR/exporter_build.log"); then
    err "simply_ip_exporter build failed:"
    cat "$WORK_DIR/exporter_build.log" >&2
    exit 1
fi
log "simply_ip_exporter build succeeded."

# ── 1. Environment setup ─────────────────────────────────────────────────────

log_section "1. Environment Setup"

log "Starting simply_ip_vault on port $VAULT_PORT against a fresh database at $VAULT_DB_PATH"
DATABASE_URL="sqlite://$VAULT_DB_PATH?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$VAULT_MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$VAULT_MASTER_SECRET" \
    VAULT_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    PORT="$VAULT_PORT" \
    "$VAULT_DIR/target/debug/simply_ip_vault" >"$VAULT_LOG" 2>&1 &
VAULT_PID=$!
log "Waiting for simply_ip_vault to become ready (pid $VAULT_PID)..."
wait_ready "simply_ip_vault" "$VAULT_URL" "$VAULT_PID" "$VAULT_LOG"
log "simply_ip_vault is up."

api_call "$VAULT_URL" GET "/api/auth/me" "$VAULT_MASTER_KEY"
check "200" "the deterministic Vault INITIAL_MASTER_KEY authenticates"
check_jq ".is_master" "true" "Vault master key reports is_master=true"

# ── 2. Vault provisioning ───────────────────────────────────────────────────

log_section "2. Vault Provisioning"

log "Creating banlist group pfBlocker_Blacklist..."
api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" '{"name":"pfBlocker_Blacklist"}'
check "200" "pfBlocker_Blacklist group is created"
BLACKLIST_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# A dedicated whitelist group for the RFC 1918 test address: simply_ip_vault's /api/ban refuses to
# store a private or link-local IPv4 address in a banlist group (it makes no sense to "ban" one),
# so the private address this suite needs simply_ip_exporter to filter is registered here instead.
# simply_ip_exporter does not care about Vault's ban/whitelist distinction — it just aggregates
# whatever addresses live in the groups it's told to read.
log "Creating whitelist group pfBlocker_Private_Test (for a RFC1918 address /ban would refuse)..."
api_call "$VAULT_URL" POST "/api/white" "$VAULT_MASTER_KEY" '{"target_address":"192.168.1.50/32","group_name":"pfBlocker_Private_Test","cause":"rfc1918 filter test"}'
check "200" "192.168.1.50/32 is registered into a fresh whitelist group"
api_call "$VAULT_URL" GET "/api/ips?groups=pfBlocker_Private_Test&format=iplist" "$VAULT_MASTER_KEY"
# Vault canonicalizes a bare host address without a stored /32 suffix (a bare address and its
# /32 form are the same record); simply_ip_exporter's own parser accepts both shapes regardless.
check_jq ".ip_list[0]" "192.168.1.50" "the private address round-trips through Vault"
# Resolve the whitelist group's id for the permission grant below.
api_call "$VAULT_URL" GET "/api/groups" "$VAULT_MASTER_KEY"
PRIVATE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.name=="pfBlocker_Private_Test") | .id')

# A THIRD, entirely distinct group — proves simply_ip_exporter actually reads and combines
# multiple Vault groups, rather than the §4 aggregation check coincidentally passing off content
# that all happened to come from a single group (pfBlocker_Private_Test's own address is RFC1918
# and gets filtered back out downstream, so it alone never demonstrates a second group's content
# surviving into the aggregated feed). 9.9.9.0/24 (Quad9's real public anycast range) is used
# instead of another 8.8.8.0/8 or 10.0.0.0/8 address specifically so it cannot be confused with, or
# accidentally aggregated adjacent to, the pfBlocker_Blacklist fixtures above.
log "Creating a third banlist group pfBlocker_Secondary_Test (proves multi-group aggregation, not just multi-group presence)..."
api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" '{"name":"pfBlocker_Secondary_Test"}'
check "200" "pfBlocker_Secondary_Test group is created"
SECONDARY_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"9.9.9.0/24","group_name":"pfBlocker_Secondary_Test","cause":"cross-group aggregation test"}'
check "200" "9.9.9.0/24 added to the secondary group"

# ── Pagination fixture (§4b) ────────────────────────────────────────────────
# simply_ip_vault's GET /api/ips defaults to limit=50 (src/api/records.rs::list_ips,
# `filters.limit.unwrap_or(50)`) and imposes no cap. simply_ip_exporter's VaultClient used to send
# no `limit` at all, so every sync silently received the 50 most recently updated records and
# treated that page as the whole dataset — the exact production symptom this fixture now guards.
# 250 is chosen to be comfortably over that default (5 full pages at the mock/probe page size)
# while staying fast to seed.
#
# Each address is a lone host in its own /24 (51.<i/256>.<i%256>.1), which makes the count assertion
# in §4b exact: no two are adjacent, so ipnet::IpNet::aggregate() cannot merge any of them, and none
# fall in an RFC1918/bogon/loopback range that a filter could remove.
log "Creating pfBlocker_Pagination_Test and seeding it with $PAGINATION_RECORD_COUNT records (Vault's default page is 50)..."
api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" '{"name":"pfBlocker_Pagination_Test"}'
check "200" "pfBlocker_Pagination_Test group is created"
PAGINATION_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# Seeded through POST /api/records/batch (transactional, up to 10k records) rather than 250
# individual POST /api/ban calls — 250 signed round-trips would dominate this script's runtime.
PAGINATION_BATCH=$(python3 - "$PAGINATION_RECORD_COUNT" <<'PY'
import json, sys
n = int(sys.argv[1])
records = [
    {"target_address": "51.%d.%d.1" % (i // 256, i % 256), "cause": "pagination fixture"}
    for i in range(n)
]
print(json.dumps({
    "group_name": "pfBlocker_Pagination_Test",
    "mode": "upsert",
    "records": records,
    "skip_webhooks": True,
}))
PY
)
api_call "$VAULT_URL" POST "/api/records/batch" "$VAULT_MASTER_KEY" "$PAGINATION_BATCH"
check "200" "$PAGINATION_RECORD_COUNT records are batch-seeded into pfBlocker_Pagination_Test"
check_jq ".created" "$PAGINATION_RECORD_COUNT" "Vault reports all $PAGINATION_RECORD_COUNT records created"

# IPv6 half of the fixture, into the same group so one feed spans both families.
#
# `2a01:4f8::/32` is global unicast, deliberately NOT the `2001:db8::/32` documentation range:
# that range is on simply_ip_exporter's own bogon list (src/ipfilter.rs), so a fixture built
# from it would vanish from any feed with filter_bogons enabled and would prove IPv6 works only
# where filtering happens to be off. Consecutive addresses differ in the third hextet, so —
# exactly like the IPv4 half — none can be aggregated away and the line count stays the record
# count.
log "Seeding $PAGINATION_IPV6_COUNT IPv6 records into the same group (total now $PAGINATION_TOTAL_COUNT)..."
PAGINATION_V6_BATCH=$(python3 - "$PAGINATION_IPV6_COUNT" <<'PYV6'
import json, sys
n = int(sys.argv[1])
records = [
    {"target_address": "2a01:4f8:%x::1" % (i + 1), "cause": "pagination fixture (ipv6)"}
    for i in range(n)
]
print(json.dumps({
    "group_name": "pfBlocker_Pagination_Test",
    "mode": "upsert",
    "records": records,
    "skip_webhooks": True,
}))
PYV6
)
api_call "$VAULT_URL" POST "/api/records/batch" "$VAULT_MASTER_KEY" "$PAGINATION_V6_BATCH"
check "200" "$PAGINATION_IPV6_COUNT IPv6 records are batch-seeded into pfBlocker_Pagination_Test"
check_jq ".created" "$PAGINATION_IPV6_COUNT" "Vault reports all $PAGINATION_IPV6_COUNT IPv6 records created"

# Proves the premise rather than assuming it: Vault really does truncate to 50 when no `limit` is
# sent. If Vault ever changes that default, this check fails loudly and §4b's guard becomes moot —
# far better than the guard quietly testing nothing.
api_call "$VAULT_URL" GET "/api/ips?groups=pfBlocker_Pagination_Test" "$VAULT_MASTER_KEY"
check "200" "Vault serves the pagination group"
check_jq "length" "50" "Vault truncates to its default limit=50 when no limit is supplied (the bug's root cause)"

# The include_total envelope contract this Exporter's parallel paging is built on, asserted against
# the live daemon rather than assumed from the reference: if Vault ever stops reporting total_pages,
# the Exporter silently falls back to sequential paging and §4b would still pass — so the envelope
# itself needs its own check.
api_call "$VAULT_URL" GET "/api/ips?groups=pfBlocker_Pagination_Test&include_total=true&limit=$PAGINATION_PAGE_SIZE" "$VAULT_MASTER_KEY"
check "200" "Vault answers include_total=true"
check_jq ".total" "$PAGINATION_TOTAL_COUNT" "the envelope reports total=$PAGINATION_TOTAL_COUNT (IPv4 + IPv6) across all pages"
check_jq ".total_pages" "$PAGINATION_EXPECTED_PAGES" "the envelope reports total_pages=$PAGINATION_EXPECTED_PAGES at limit=$PAGINATION_PAGE_SIZE"
check_jq ".data | length" "$PAGINATION_PAGE_SIZE" "page one carries exactly $PAGINATION_PAGE_SIZE records under .data"

# ── Restricted-key multi-group fixture (§4d) ────────────────────────────────
# 500 records across three groups, with the Exporter's Vault key granted can_read on only two of
# them. This is the production shape: the Exporter authenticates to Vault with a restricted,
# non-Master key, and must publish exactly what that key may read — no more, and without erroring on
# the group it may not.
#
# Vault's "restrict-not-reject" rule (API_REFERENCE.md §GET /api/ips) is what makes the negative
# assertion meaningful: naming an unreadable group is NOT an error, it simply contributes nothing.
# So the Exporter asks for all three groups and must silently receive only two groups' worth —
# proving the exclusion happens in Vault's scoping rather than by the Exporter guessing.
log "Creating Group_Alpha/Beta/Gamma and seeding 500 records across them..."
for g in Group_Alpha Group_Beta Group_Gamma; do
    api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" "{\"name\":\"$g\"}"
    check "200" "$g is created"
    eval "${g}_ID=\$(echo \"\$RESP_BODY\" | jq -r '.id')"
done

# 167 + 167 + 166 = 500. Distinct /8s per group and a lone host per /24, so nothing aggregates
# within or across groups and each group's contribution is countable on its own.
seed_group() { # group_name octet count
    local batch
    batch=$(python3 - "$1" "$2" "$3" <<'PY'
import json, sys
group, octet, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
records = [
    {"target_address": "%d.0.%d.1" % (octet, i), "cause": "restricted-key fixture"}
    for i in range(count)
]
print(json.dumps({"group_name": group, "mode": "upsert", "records": records, "skip_webhooks": True}))
PY
)
    api_call "$VAULT_URL" POST "/api/records/batch" "$VAULT_MASTER_KEY" "$batch"
    check "200" "$3 records seeded into $1"
    check_jq ".created" "$3" "Vault reports all $3 records created in $1"
}
seed_group Group_Alpha 61 167
seed_group Group_Beta 62 167
seed_group Group_Gamma 63 166

# ── Retention-window fixture (§4c) ──────────────────────────────────────────
# Two records in one group, differing only in age, so `max_age_seconds` is the single variable
# distinguishing what the three §4c feeds publish. Vault's batch API accepts an explicit
# `updated_at` per record, which makes "stale" deterministic — no sleeping, no wall-clock racing.
# Both are lone hosts in distinct /24s, so neither aggregates and a line count is a record count.
log "Creating pfBlocker_Age_Test with one fresh and one deliberately stale record..."
api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" '{"name":"pfBlocker_Age_Test"}'
check "200" "pfBlocker_Age_Test group is created"
AGE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

AGE_BATCH=$(python3 <<'PY'
import datetime, json
now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
stale = now - datetime.timedelta(hours=2)
fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S")
print(json.dumps({
    "group_name": "pfBlocker_Age_Test",
    "mode": "upsert",
    "skip_webhooks": True,
    "records": [
        {"target_address": "52.0.0.1", "cause": "fresh", "updated_at": fmt(now)},
        {"target_address": "52.0.1.1", "cause": "stale (2h old)", "updated_at": fmt(stale)},
    ],
}))
PY
)
api_call "$VAULT_URL" POST "/api/records/batch" "$VAULT_MASTER_KEY" "$AGE_BATCH"
check "200" "the fresh + stale record pair is seeded into pfBlocker_Age_Test"
check_jq ".created" "2" "Vault reports both age-fixture records created"

log "Seeding pfBlocker_Blacklist with a contiguous/overlapping pair and a CGN (bogon) address..."
# 8.8.8.0/24 + 8.8.8.1/32 (a host fully inside that block) is the aggregation fixture: a
# spec-compliant ipnet::IpNet::aggregate() must collapse them into the single block 8.8.8.0/24.
# Deliberately NOT the 10.0.0.0/24 + 10.0.0.1/32 pair suggested as an example elsewhere: 10.0.0.0/8
# is itself RFC 1918, and 203.0.113.0/24 is IANA's TEST-NET-3 — i.e. a documented "bogon" range by
# definition. This endpoint enables both filter_rfc1918 AND filter_bogons, so seeding either would
# make the aggregation/public-survival assertions self-defeating against a correct implementation.
# 8.8.8.0/24 is real public space, clear of every filter list, so it isolates what §4 actually
# tests: aggregation, independent of filtering.
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"8.8.8.0/24","group_name":"pfBlocker_Blacklist","cause":"aggregation base"}'
check "200" "8.8.8.0/24 added to the blacklist group"
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"8.8.8.1/32","group_name":"pfBlocker_Blacklist","cause":"aggregation partner (contained in 8.8.8.0/24)"}'
check "200" "8.8.8.1/32 added to the blacklist group"
# 100.64.0.0/10 (Carrier-Grade NAT / RFC 6598) is not "private" per std::net::Ipv4Addr::is_private()
# (which only recognizes the three classic RFC 1918 ranges), so Vault's /api/ban accepts it — but
# it IS in simply_ip_exporter's bogon list, which is what this address exercises.
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"100.64.0.5/32","group_name":"pfBlocker_Blacklist","cause":"bogon (CGN) filter test"}'
check "200" "100.64.0.5/32 (CGN bogon) added to the blacklist group"
# A dedicated, otherwise-untouched public address for §6's soft-delete propagation test — kept
# distinct from the aggregation/filter fixtures above so deleting it later can't be confused with
# (or accidentally break) any other section's assertions.
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"8.8.4.4/32","group_name":"pfBlocker_Blacklist","cause":"soft-delete propagation test"}'
check "200" "8.8.4.4/32 (soft-delete test fixture) added to the blacklist group"

log "Creating a scoped, read-only key for the Exporter..."
api_call "$VAULT_URL" POST "/api/keys" "$VAULT_MASTER_KEY" '{"name":"simply_ip_exporter sync key","bound_ips":"0.0.0.0/0,::/0"}'
check "200" "Exporter sync key is created in Vault"
EXPORTER_VAULT_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
EXPORTER_VAULT_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
EXPORTER_VAULT_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$EXPORTER_VAULT_KEY" "$EXPORTER_VAULT_SECRET"

log "Granting can_read on both groups to the Exporter's Vault key..."
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$BLACKLIST_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on pfBlocker_Blacklist"
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$PRIVATE_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on pfBlocker_Private_Test"
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$SECONDARY_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on pfBlocker_Secondary_Test"
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$PAGINATION_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on pfBlocker_Pagination_Test"
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$AGE_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on pfBlocker_Age_Test"

log "Granting the Exporter's restricted Vault key can_read on Alpha and Beta ONLY (Gamma denied)..."
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$Group_Alpha_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on Group_Alpha"
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$Group_Beta_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on Group_Beta"
log "Group_Gamma is deliberately NOT granted — its 166 records must never reach the feed."

# Proves the restriction is real at the Vault boundary before the Exporter is even involved: the
# same query that a Master answers with all 500 returns only the readable 334 for this key.
api_call "$VAULT_URL" GET "/api/ips?groups=Group_Alpha,Group_Beta,Group_Gamma&limit=100000" "$EXPORTER_VAULT_KEY"
check "200" "the restricted key may query all three groups without a 403 (restrict-not-reject)"
check_jq "length" "334" "Vault returns only Alpha+Beta's 334 records to the restricted key, silently omitting Gamma's 166"


api_call "$VAULT_URL" GET "/api/ips?groups=pfBlocker_Blacklist,pfBlocker_Private_Test,pfBlocker_Secondary_Test" "$EXPORTER_VAULT_KEY"
check "200" "the scoped Exporter key can read across all three groups"
check_jq "length" "6" "sees all 6 seeded records (restrict-not-reject: no group is silently rejected)"

# ── 3. Exporter configuration ───────────────────────────────────────────────

log_section "3. Exporter Configuration"

log "Starting simply_ip_exporter on port $EXPORTER_PORT against a fresh database at $EXPORTER_DB_PATH"
# TRUSTED_PROXIES=127.0.0.1: every request in this script originates from loopback, so declaring
# it trusted is what lets X-Forwarded-For stand in for distinct simulated client addresses below —
# exactly as a real reverse proxy would, and exactly how §5/§6 isolate one another's rate-limit
# buckets without needing several real source machines.
DATABASE_URL="sqlite://$EXPORTER_DB_PATH?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$EXPORTER_MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$EXPORTER_MASTER_SECRET" \
    EXPORTER_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    VAULT_BASE_URL="$VAULT_URL" \
    VAULT_API_KEY="$EXPORTER_VAULT_KEY" \
    VAULT_SIGNING_SECRET="$EXPORTER_VAULT_SECRET" \
    TRUSTED_PROXIES="127.0.0.1" \
    PORT="$EXPORTER_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_exporter" >"$EXPORTER_LOG" 2>&1 &
EXPORTER_PID=$!
log "Waiting for simply_ip_exporter to become ready (pid $EXPORTER_PID)..."
wait_ready "simply_ip_exporter" "$EXPORTER_URL" "$EXPORTER_PID" "$EXPORTER_LOG"
log "simply_ip_exporter is up."

api_call "$EXPORTER_URL" GET "/health"
check "200" "Exporter /health is 200 with no credentials"
check_jq ".service" "simply_ip_exporter" "/health reports the correct service name"

api_call "$EXPORTER_URL" GET "/api/auth/me" "$EXPORTER_MASTER_KEY"
check "200" "the deterministic Exporter INITIAL_MASTER_KEY authenticates"
check_jq ".is_master" "true" "Exporter master key reports is_master=true"

raw_call GET "$EXPORTER_URL/api/auth/me"
check "401" "an unsigned admin API request is rejected"

log "Listing Vault groups via Exporter's GET /api/vault-groups (live Vault call)..."
api_call "$EXPORTER_URL" GET "/api/vault-groups" "$EXPORTER_MASTER_KEY"
check "200" "GET /api/vault-groups returns 200 OK against live Vault"
check_jq "length" "7" "sees the 7 Vault groups this key may read at this point (Blacklist, Private, Secondary, Pagination, Age, Group_Alpha, Group_Beta) — Group_Gamma is ungranted and correctly absent; §4e adds an eighth later"
check_contains "$RESP_BODY" "pfBlocker_Blacklist" "pfBlocker_Blacklist is returned by live Vault group listing"
check_contains "$RESP_BODY" "pfBlocker_Private_Test" "pfBlocker_Private_Test is returned by live Vault group listing"
check_contains "$RESP_BODY" "pfBlocker_Secondary_Test" "pfBlocker_Secondary_Test is returned by live Vault group listing"

log "Minting a Daughter key to test Vault-group permission grants and endpoint creation with group selection..."
api_call "$EXPORTER_URL" POST "/api/keys" "$EXPORTER_MASTER_KEY" '{"name":"Group Selection Daughter"}'
check "200" "Group Selection Daughter key created"
GSD_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
GSD_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
GSD_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$GSD_KEY" "$GSD_SECRET"

log "Granting read access on live Vault group pfBlocker_Blacklist to the Daughter key..."
api_call "$EXPORTER_URL" POST "/api/keys/$GSD_ID/groups" "$EXPORTER_MASTER_KEY" "{\"vault_group_id\":\"$BLACKLIST_GROUP_ID\"}"
check "200" "Vault group grant for pfBlocker_Blacklist succeeded"

log "Creating an endpoint using selected Vault group pfBlocker_Blacklist via the Daughter key..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$GSD_KEY" \
    '{"name":"Daughter Blacklist Feed","vault_groups":"pfBlocker_Blacklist","ttl_seconds":2}'
check "200" "endpoint created using selected Vault group by Daughter key"

log "Attempting to create an endpoint using an ungranted Vault group as Daughter key..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$GSD_KEY" \
    '{"name":"Forbidden Group Feed","vault_groups":"pfBlocker_Secondary_Test","ttl_seconds":2}'
check "403" "endpoint creation refused when Daughter key lacks grant for selected Vault group"

log "Testing live background cleanup setup: creating a temp Vault group, granting it locally, then deleting it in Vault..."
api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" '{"name":"pfBlocker_Temp_Cleanup"}'
check "200" "temp Vault group created"
TEMP_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$TEMP_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "Exporter Vault key granted read on temp Vault group"

api_call "$EXPORTER_URL" POST "/api/keys/$GSD_ID/groups" "$EXPORTER_MASTER_KEY" "{\"vault_group_id\":\"$TEMP_GROUP_ID\"}"
check "200" "Daughter key granted read access to temp Vault group"

api_call "$EXPORTER_URL" GET "/api/keys/$GSD_ID/groups" "$EXPORTER_MASTER_KEY"
check_jq "length" "2" "Daughter key initially has 2 group grants"

log "Deleting the temp group in live Vault..."
api_call "$VAULT_URL" DELETE "/api/groups/$TEMP_GROUP_ID" "$VAULT_MASTER_KEY"
check "204" "temp group deleted in Vault"


log "Creating the public feed endpoint (ttl_seconds=2, filter_rfc1918=true, filter_bogons=true), spanning all three Vault groups..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"pfBlockerNG DMZ Feed","vault_groups":"pfBlocker_Blacklist,pfBlocker_Private_Test,pfBlocker_Secondary_Test","ttl_seconds":2,"filter_rfc1918":true,"filter_bogons":true}'
check "200" "the feed endpoint is created"
check_jq ".filter_rfc1918" "true" "filter_rfc1918 is set as configured"
check_jq ".filter_bogons" "true" "filter_bogons is set as configured"
FEED_TOKEN=$(echo "$RESP_BODY" | jq -r '.token_secret')
FEED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')
FEED_ENDPOINT_ID=$(echo "$RESP_BODY" | jq -r '.id')
log "Feed path: $FEED_PATH (endpoint id: $FEED_ENDPOINT_ID)"

# A second endpoint scoped to ONLY pfBlocker_Secondary_Test — the group-scoping counterpart to the
# combined feed above. Proves simply_ip_exporter actually restricts a feed's content to the groups
# named in its own vault_groups, rather than exposing every group its Vault key happens to be able
# to read regardless of configuration (which the combined-feed check alone couldn't distinguish
# from correct behavior, since it deliberately spans every group).
log "Creating a second feed endpoint scoped to ONLY pfBlocker_Secondary_Test (group-scoping test)..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Secondary Group Only Feed","vault_groups":"pfBlocker_Secondary_Test","ttl_seconds":2}'
check "200" "the secondary-group-only feed endpoint is created"
SECONDARY_FEED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')
log "Secondary feed path: $SECONDARY_FEED_PATH"

# Created here, alongside the others, specifically so it becomes due in the same background-sync
# pass the `sleep 20` below already waits for — §4b then asserts against it without costing the
# script a second 20-second wait. No filters are enabled: the §2 fixture addresses are public,
# non-adjacent hosts, so the feed's line count is exactly the record count.
log "Creating the large-dataset feed endpoint over pfBlocker_Pagination_Test ($PAGINATION_RECORD_COUNT records)..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Pagination Feed","vault_groups":"pfBlocker_Pagination_Test","ttl_seconds":2}'
check "200" "the large-dataset feed endpoint is created"
PAGINATION_FEED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')
log "Pagination feed path: $PAGINATION_FEED_PATH"

# Three endpoints over the SAME group, differing only in max_age_seconds — so §4c's differing
# results can only be attributable to the retention window. Created here so they sync in the same
# background pass the wait below already covers.
log "Creating three retention-window feeds over pfBlocker_Age_Test (max_age_seconds 0 / 3600 / 10)..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Age Unlimited Feed","vault_groups":"pfBlocker_Age_Test","ttl_seconds":2,"max_age_seconds":0}'
check "200" "the unlimited-retention feed is created"
AGE_UNLIMITED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')
check_jq ".max_age_seconds" "0" "it reports max_age_seconds=0 (unlimited)"

api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Age Windowed Feed","vault_groups":"pfBlocker_Age_Test","ttl_seconds":2,"max_age_seconds":3600}'
check "200" "the 1-hour-window feed is created"
AGE_WINDOWED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')
check_jq ".max_age_seconds" "3600" "it reports max_age_seconds=3600"

api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Age Tight Feed","vault_groups":"pfBlocker_Age_Test","ttl_seconds":2,"max_age_seconds":10}'
check "200" "the 10-second-window feed is created"
AGE_TIGHT_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')

api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Rejected Age Feed","vault_groups":"pfBlocker_Age_Test","max_age_seconds":-1}'
check "400" "a negative max_age_seconds is refused at creation" 

# Deliberately names all three groups, including the one the Exporter's Vault key cannot read.
# Vault answers such a request normally and simply contributes nothing for Gamma, so a correct
# Exporter publishes 334 records and never sees a 403.
log "Creating the restricted multi-group feed over Alpha+Beta+Gamma (Gamma is denied to our key)..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Restricted Multi-Group Feed","vault_groups":"Group_Alpha,Group_Beta,Group_Gamma","ttl_seconds":2}'
check "200" "the restricted multi-group feed is created"
RESTRICTED_MULTI_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')

# sync_all_endpoints() (src/sync.rs) syncs every due endpoint sequentially within one 15s tick,
# each a real HTTP round-trip to Vault — two endpoints due at once (as here) take measurably
# longer than one, so the old 18s margin (15s tick + 3s slack, sized for a single endpoint) was
# occasionally too tight under load. 20s leaves more headroom for both to complete in one pass.
log "Waiting for the background sync worker (15s tick interval, both endpoints are due for an immediate full sync)..."
sleep 20

# ── 4. Feed verification & aggregation ──────────────────────────────────────

log_section "4. Feed Verification & Aggregation"

# A dedicated simulated client address for this section's checks, isolated from every other
# section's rate-limit bucket via X-Forwarded-For (see the TRUSTED_PROXIES note above).
raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.11" -D "$WORK_DIR/headers_4"
check "200" "the feed is served"
CONTENT_TYPE=$(grep -i '^content-type:' "$WORK_DIR/headers_4" | tr -d '\r' | awk -F': ' '{print $2}')
check_local "$CONTENT_TYPE" "text/plain; charset=utf-8" "the feed is served as text/plain"

check_contains "$RESP_BODY" "8.8.8.0/24" "8.8.8.0/24 and 8.8.8.1/32 were aggregated into 8.8.8.0/24"
check_not_contains "$RESP_BODY" "8.8.8.1" "the host-route 8.8.8.1/32 no longer appears on its own (proves aggregation, not just filtering)"
check_contains "$RESP_BODY" "8.8.4.4/32" "8.8.4.4/32 (the §6 soft-delete fixture) is present and unaggregated (not adjacent to the 8.8.8.0/24 block)"
check_not_contains "$RESP_BODY" "192.168.1.50" "the RFC1918 address is filtered out (filter_rfc1918=true)"
check_not_contains "$RESP_BODY" "100.64.0.5" "the CGN bogon address is filtered out (filter_bogons=true)"
# 9.9.9.0/24 comes from pfBlocker_Secondary_Test — a THIRD, distinct Vault group named in this
# endpoint's vault_groups alongside pfBlocker_Blacklist/pfBlocker_Private_Test. Its presence here
# is the actual proof that simply_ip_exporter reads and combines multiple Vault groups into one
# aggregated feed, not merely that a multi-group vault_groups value is accepted at creation time.
check_contains "$RESP_BODY" "9.9.9.0/24" "9.9.9.0/24 from the third, distinct Vault group (pfBlocker_Secondary_Test) is present — proves cross-group aggregation, not just a single group's content"
LINE_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$LINE_COUNT" "3" "exactly three lines remain after aggregation and filtering (8.8.8.0/24, 8.8.4.4/32, 9.9.9.0/24 — one per surviving group)"

# Group-scoping counterpart: a feed whose vault_groups names ONLY pfBlocker_Secondary_Test must
# see 9.9.9.0/24 and NOTHING from the other two groups, even though the same underlying Vault key
# can read all three. If simply_ip_exporter ever regressed to ignoring vault_groups and just
# returning everything its Vault key is scoped to, this is the check that would catch it — the
# combined feed above spans every group, so it alone can't distinguish "grouped correctly" from
# "returns everything regardless of vault_groups".
raw_call GET "$EXPORTER_URL$SECONDARY_FEED_PATH" -H "X-Forwarded-For: 198.51.100.13"
check "200" "the secondary-group-only feed is served"
check_contains "$RESP_BODY" "9.9.9.0/24" "the secondary-group-only feed contains its own group's address"
check_not_contains "$RESP_BODY" "8.8.8.0/24" "the secondary-group-only feed does NOT leak pfBlocker_Blacklist's content"
check_not_contains "$RESP_BODY" "8.8.4.4" "the secondary-group-only feed does NOT leak pfBlocker_Blacklist's content"
SECONDARY_LINE_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$SECONDARY_LINE_COUNT" "1" "exactly one line — only this endpoint's own group's content"

# ── 4b. Large-dataset pagination ────────────────────────────────────────────

log_section "4b. Large-Dataset Pagination ($PAGINATION_RECORD_COUNT records, $PAGINATION_EXPECTED_PAGES parallel pages)"

# The regression guard for the production defect where simply_ip_exporter published only ~50 IPs
# regardless of how many Vault held. Vault paginates GET /api/ips with limit/offset and defaults to
# limit=50; VaultClient::fetch_ips sent no limit, so it read one page and treated it as the entire
# dataset. On a full sync that is actively destructive, since apply_full has replace semantics —
# everything past the 50th was dropped from the cache and vanished from the published feed.
#
# §2 already asserted Vault itself truncates at 50 without a limit, so this section isolates the
# exporter's half: given a group Vault serves 50-at-a-time, does the published feed carry all
# $PAGINATION_RECORD_COUNT?
PAGINATION_FETCH_START=$(date +%s%3N)
raw_call GET "$EXPORTER_URL$PAGINATION_FEED_PATH" -H "X-Forwarded-For: 198.51.100.51"
check "200" "the large-dataset feed is served"
PAGINATION_FETCH_MS=$(( $(date +%s%3N) - PAGINATION_FETCH_START ))
log "Feed of $PAGINATION_TOTAL_COUNT records ($PAGINATION_RECORD_COUNT IPv4 + $PAGINATION_IPV6_COUNT IPv6) served in ${PAGINATION_FETCH_MS}ms (served from the in-memory cache, so this measures serving, not syncing)."


PAGINATION_LINE_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$PAGINATION_LINE_COUNT" "$PAGINATION_TOTAL_COUNT" \
    "all $PAGINATION_TOTAL_COUNT records (IPv4 + IPv6) survive the sync — not truncated to Vault's 50-record default page"

# Spot-checks at and beyond the old truncation boundary. A count alone could in principle be met by
# the wrong 250 records; these name specific addresses that only a complete multi-page walk reaches.
check_contains "$RESP_BODY" "51.0.0.1/32" "the first seeded record is present"
check_contains "$RESP_BODY" "51.0.49.1/32" "the 50th record (the last of Vault's default first page) is present"
check_contains "$RESP_BODY" "51.0.50.1/32" "the 51st record is present — the first one the old single-page fetch always lost"

# Every boundary between the four 1000-record pages, checked on both sides. A parallel walk that
# miscomputed an offset, or dropped a page entirely, shows up here as a specific missing address
# rather than only as a wrong total — and the pairs straddling each seam are exactly where an
# off-by-one in the offset arithmetic would land.
check_contains "$RESP_BODY" "51.3.231.1/32" "record 1000 — the last of parallel page 1"
check_contains "$RESP_BODY" "51.3.232.1/32" "record 1001 — the first of parallel page 2"
check_contains "$RESP_BODY" "51.7.207.1/32" "record 2000 — the last of parallel page 2"
check_contains "$RESP_BODY" "51.7.208.1/32" "record 2001 — the first of parallel page 3"
check_contains "$RESP_BODY" "51.11.183.1/32" "record 3000 — the last of parallel page 3"
check_contains "$RESP_BODY" "51.11.184.1/32" "record 3001 — the first of parallel page 4 (the short 214-record tail)"
check_contains "$RESP_BODY" "51.12.141.1/32" "record 3214 — the very last, so the short final page arrived complete"

# ── IPv6 ─────────────────────────────────────────────────────────────────────
# The same multi-page parallel fetch must carry IPv6 intact. These are counted and spot-checked
# separately from IPv4 because a family-specific parsing or serialization fault would otherwise be
# invisible: the totals above would still balance if IPv6 records were silently dropped and IPv4
# over-counted, and vice versa.
PAGINATION_V6_LINES=$(echo "$RESP_BODY" | grep -c ":" || true)
check_local "$PAGINATION_V6_LINES" "$PAGINATION_IPV6_COUNT" "exactly $PAGINATION_IPV6_COUNT IPv6 lines in the feed — none dropped in pagination or aggregation"
PAGINATION_V4_LINES=$(echo "$RESP_BODY" | grep -c "^51\\." || true)
check_local "$PAGINATION_V4_LINES" "$PAGINATION_RECORD_COUNT" "and all $PAGINATION_RECORD_COUNT IPv4 lines alongside them"

# Spot-checks spread across the IPv6 sequence, so a truncation at any page boundary is named rather
# than only showing up as a wrong count. Emitted in canonical /128 form by ipnet.
check_contains "$RESP_BODY" "2a01:4f8:1::1/128" "the first IPv6 record is present"
check_contains "$RESP_BODY" "2a01:4f8:64::1/128" "IPv6 record 100 is present"
check_contains "$RESP_BODY" "2a01:4f8:fa::1/128" "IPv6 record 250 is present"
check_contains "$RESP_BODY" "2a01:4f8:12c::1/128" "IPv6 record 300 is present"
check_contains "$RESP_BODY" "2a01:4f8:1f4::1/128" "the 500th and final IPv6 record is present"

# Serialization sanity: every IPv6 line must be a well-formed /128, not a corrupted or bare address.
PAGINATION_V6_MALFORMED=$(echo "$RESP_BODY" | grep ":" | grep -cv "^2a01:4f8:[0-9a-f]\\{1,3\\}::1/128$" || true)
check_local "$PAGINATION_V6_MALFORMED" "0" "every IPv6 line is a well-formed canonical /128 — none corrupted in transit"

# Duplicates would inflate the count while every spot-check still passed, so the line count above is
# only meaningful alongside this: no address may appear twice after a concurrent merge.
PAGINATION_DISTINCT=$(echo "$RESP_BODY" | sort -u | grep -c . || true)
check_local "$PAGINATION_DISTINCT" "$PAGINATION_TOTAL_COUNT" "all $PAGINATION_TOTAL_COUNT lines are distinct — concurrent pages merged without duplicating a record"

# Concurrency must not have produced errors of its own, and no page may have been refused.
if grep -qE "403 Forbidden|panicked|concurrency" "$EXPORTER_LOG"; then
    check_local "found" "none" "no 403, panic, or concurrency error in the Exporter log during the large-dataset sync"
else
    check_local "none" "none" "no 403, panic, or concurrency error in the Exporter log during the large-dataset sync"
fi

# ── 4c. Retention window (max_age_seconds) ──────────────────────────────────

log_section "4c. Retention Window (max_age_seconds)"

# All three feeds below read the SAME Vault group, holding exactly two records that differ only in
# age (one fresh, one stamped 2h old at seed time). Any difference in what they publish is therefore
# attributable to max_age_seconds alone.

log "max_age_seconds=0 — unlimited, the default: both records must appear..."
raw_call GET "$EXPORTER_URL$AGE_UNLIMITED_PATH" -H "X-Forwarded-For: 198.51.100.61"
check "200" "the unlimited-retention feed is served"
check_contains "$RESP_BODY" "52.0.0.1/32" "the fresh record is present"
check_contains "$RESP_BODY" "52.0.1.1/32" "the 2h-old record is present too — 0 means no age cutoff at all"
AGE_UNLIMITED_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$AGE_UNLIMITED_COUNT" "2" "exactly two lines — nothing was filtered by age"

log "max_age_seconds=3600 — the 2h-old record falls outside the window..."
raw_call GET "$EXPORTER_URL$AGE_WINDOWED_PATH" -H "X-Forwarded-For: 198.51.100.62"
check "200" "the 1-hour-window feed is served"
check_contains "$RESP_BODY" "52.0.0.1/32" "the fresh record is still published"
check_not_contains "$RESP_BODY" "52.0.1.1" "the 2h-old record is excluded — older than the 1h window"
AGE_WINDOWED_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$AGE_WINDOWED_COUNT" "1" "exactly one line survives the retention window"

# The "fresh" record was stamped at seed time in §2; by the time this runs, the §3 sync wait alone
# has put well over 10 seconds between then and now, so a 10-second window excludes even it. This is
# the boundary case that proves the cutoff is evaluated against *now* at every feed generation
# rather than frozen at sync time — a sync-time filter would still be publishing it.
log "max_age_seconds=10 — a window tighter than the elapsed test runtime empties the feed..."
raw_call GET "$EXPORTER_URL$AGE_TIGHT_PATH" -H "X-Forwarded-For: 198.51.100.63"
check "200" "the 10-second-window feed is still served (an empty feed is not an error)"
check_not_contains "$RESP_BODY" "52.0.0.1" "even the fresher record has aged out of a 10s window"
check_not_contains "$RESP_BODY" "52.0.1.1" "the older record is likewise absent"
AGE_TIGHT_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$AGE_TIGHT_COUNT" "0" "the feed is empty — every record is older than 10 seconds"

# Non-destructive by design: the cache still holds both records, so widening the window back out
# republishes them immediately, with no re-sync required. This is the property that makes the
# window a view over the cache rather than a filter applied during sync.
log "Widening the tight feed's window back to unlimited must restore both records with no re-sync..."
AGE_TIGHT_ID=$(echo "$RESP_BODY" >/dev/null; api_call "$EXPORTER_URL" GET "/api/endpoints" "$EXPORTER_MASTER_KEY" >/dev/null; echo "$RESP_BODY" | jq -r '.[] | select(.name == "Age Tight Feed") | .id')
api_call "$EXPORTER_URL" PUT "/api/endpoints/$AGE_TIGHT_ID" "$EXPORTER_MASTER_KEY" '{"max_age_seconds":0}'
check "200" "the retention window is widened back to unlimited"
raw_call GET "$EXPORTER_URL$AGE_TIGHT_PATH" -H "X-Forwarded-For: 198.51.100.64"
check "200" "the widened feed is served"
AGE_RESTORED_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$AGE_RESTORED_COUNT" "2" "both records are back immediately — the window is a view, not a destructive filter"

# ── 4d. Restricted Vault key across granted and denied groups ───────────────

log_section "4d. Restricted Vault Key: Granted vs Denied Groups (500 records)"

# The production shape end-to-end: the Exporter holds a non-Master Vault key granted can_read on
# Group_Alpha and Group_Beta but not Group_Gamma, and its endpoint names all three. §2 already
# proved Vault hands that key exactly 334 of the 500 records; this proves the Exporter publishes
# precisely those and nothing from Gamma.
raw_call GET "$EXPORTER_URL$RESTRICTED_MULTI_PATH" -H "X-Forwarded-For: 198.51.100.71"
check "200" "the restricted multi-group feed is served"

RESTRICTED_MULTI_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$RESTRICTED_MULTI_COUNT" "334" "exactly 334 lines — every record from the two granted groups, and only those"

check_contains "$RESP_BODY" "61.0.0.1/32" "Group_Alpha's first record is published"
check_contains "$RESP_BODY" "61.0.166.1/32" "Group_Alpha's last record is published (all 167, not a truncated page)"
check_contains "$RESP_BODY" "62.0.0.1/32" "Group_Beta's first record is published"
check_contains "$RESP_BODY" "62.0.166.1/32" "Group_Beta's last record is published"

# The security-relevant half: nothing from the group this key was never granted.
check_not_contains "$RESP_BODY" "63.0." "NOT ONE of Group_Gamma's 166 records leaked into the feed"

# And the Exporter's own group listing reflects the same scoping — Gamma is absent rather than the
# call failing, which is what distinguishes correct scoping from a swallowed error.
api_call "$EXPORTER_URL" GET "/api/vault-groups" "$EXPORTER_MASTER_KEY"
check "200" "GET /api/vault-groups still returns 200 with a restricted key (no 403)"
check_contains "$RESP_BODY" "Group_Alpha" "the granted Group_Alpha is listed"
check_contains "$RESP_BODY" "Group_Beta" "the granted Group_Beta is listed"
check_not_contains "$RESP_BODY" "Group_Gamma" "the ungranted Group_Gamma is NOT listed"

# No 403 may have been logged against Vault during the whole run — a silent 403 that the Exporter
# merely tolerated would still mean the integration is misconfigured.
if grep -q "403 Forbidden" "$EXPORTER_LOG"; then
    check_local "found" "none" "the Exporter logged no Vault 403 Forbidden during the run"
else
    check_local "none" "none" "the Exporter logged no Vault 403 Forbidden during the run"
fi

# ── 4e. Progressive sync lifecycle & concurrent availability ────────────────

log_section "4e. Progressive Sync Lifecycle & Concurrent Feed Availability"

# Stages A→C walk one endpoint through the hybrid refresh lifecycle against the live Vault, then
# hold the public feed under concurrent load while the background worker keeps resyncing.

# ── Stage A: initial sync ────────────────────────────────────────────────────
log "Stage A: seeding a dedicated progressive group and syncing it..."
api_call "$VAULT_URL" POST "/api/groups" "$VAULT_MASTER_KEY" '{"name":"pfBlocker_Progressive_Test"}'
check "200" "pfBlocker_Progressive_Test group is created"
PROGRESSIVE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
api_call "$VAULT_URL" POST "/api/keys/$EXPORTER_VAULT_KEY_ID/groups" "$VAULT_MASTER_KEY" \
    "{\"group_id\":\"$PROGRESSIVE_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "can_read granted on pfBlocker_Progressive_Test"

# Non-adjacent hosts on purpose: ipnet::IpNet::aggregate() collapses an even-aligned /32 pair into a
# /31, which would make these per-address assertions test the aggregator rather than the sync delta.
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"81.0.0.10/32","group_name":"pfBlocker_Progressive_Test","cause":"stage A"}'
check "200" "IP_A (81.0.0.10) seeded"
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"81.0.0.20/32","group_name":"pfBlocker_Progressive_Test","cause":"stage A"}'
check "200" "IP_B (81.0.0.20) seeded"

api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Progressive Feed","vault_groups":"pfBlocker_Progressive_Test","ttl_seconds":2}'
check "200" "the progressive feed endpoint is created"
PROGRESSIVE_FEED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')

log "Waiting for the worker's next tick to perform this endpoint's initial full sync..."
sleep 18

raw_call GET "$EXPORTER_URL$PROGRESSIVE_FEED_PATH" -H "X-Forwarded-For: 198.51.100.101"
check "200" "Stage A: the progressive feed is served"
check_contains "$RESP_BODY" "81.0.0.10/32" "Stage A: IP_A is published"
check_contains "$RESP_BODY" "81.0.0.20/32" "Stage A: IP_B is published"
STAGE_A_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$STAGE_A_COUNT" "2" "Stage A: exactly the two seeded records"

# ── Stage B: mutate Vault, then cross the TTL boundary ───────────────────────
# The addition and the soft delete together exercise both halves of a differential pass: `since=`
# carries the new record in, and `include_deleted=true` carries the tombstone that must remove the
# old one. A merge that ignored tombstones would keep publishing a de-listed address forever.
log "Stage B: adding IP_C and soft-deleting IP_A in the live Vault..."
api_call "$VAULT_URL" POST "/api/ban" "$VAULT_MASTER_KEY" '{"target_address":"81.0.0.30/32","group_name":"pfBlocker_Progressive_Test","cause":"stage B addition"}'
check "200" "IP_C (81.0.0.30) added to Vault"

api_call "$VAULT_URL" GET "/api/ips?ip=81.0.0.10" "$VAULT_MASTER_KEY"
check "200" "IP_A is looked up for deletion"
PROGRESSIVE_DELETE_ID=$(echo "$RESP_BODY" | jq -r '.[0].id')
api_call "$VAULT_URL" DELETE "/api/ips/$PROGRESSIVE_DELETE_ID" "$VAULT_MASTER_KEY"
check "200" "IP_A is soft-deleted in Vault"
check_jq ".deleted" "soft" "the deletion is soft, so a tombstone exists for the differential pass to replicate"

log "Waiting for the TTL (2s) to expire and the worker to run a differential sync..."
sleep 18

raw_call GET "$EXPORTER_URL$PROGRESSIVE_FEED_PATH" -H "X-Forwarded-For: 198.51.100.102"
check "200" "Stage B: the progressive feed is still served"
check_contains "$RESP_BODY" "81.0.0.20/32" "Stage B: IP_B was untouched and is still published"
check_contains "$RESP_BODY" "81.0.0.30/32" "Stage B: IP_C was added and is now published"
check_not_contains "$RESP_BODY" "81.0.0.10" "Stage B: the soft-deleted IP_A is purged from the feed"
STAGE_B_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$STAGE_B_COUNT" "2" "Stage B: exactly IP_B and IP_C remain"

# ── Stage C: concurrent load while the worker keeps resyncing ────────────────
# Aimed at the large 3,714-record pagination feed rather than the tiny one above, so each background
# resync is a genuine multi-page parallel fetch rather than a trivial one. Three rounds spaced over
# ~24s guarantee the flood spans at least one full 15s worker tick, so reads and a sync really do
# overlap. Every request uses a distinct X-Forwarded-For: the feed throttles one full body per
# source IP per 2 minutes, so reusing an address would measure the rate limiter, not availability.
log "Stage C: flooding the $PAGINATION_TOTAL_COUNT-record feed with concurrent reads across worker sync ticks..."
FLOOD_RESULTS="$WORK_DIR/flood_results"
: > "$FLOOD_RESULTS"
export EXPORTER_URL PAGINATION_FEED_PATH WORK_DIR FLOOD_RESULTS

for round in 1 2 3; do
    export round
    seq 1 40 | xargs -P 8 -I{} sh -c '
        body="$WORK_DIR/flood_body_${round}_{}"
        code=$(curl -s -o "$body" -w "%{http_code}" --max-time 20 \
            -H "X-Forwarded-For: 10.20.${round}.{}" \
            "$EXPORTER_URL$PAGINATION_FEED_PATH")
        printf "%s %s\n" "$code" "$(wc -c < "$body")" >> "$FLOOD_RESULTS"
        rm -f "$body"
    '
    [ "$round" -lt 3 ] && sleep 8
done

FLOOD_TOTAL=$(grep -c . "$FLOOD_RESULTS" || true)
check_local "$FLOOD_TOTAL" "120" "Stage C: all 120 concurrent feed requests completed"

# A non-200, a 5xx, or a zero-byte body are each independently disqualifying: an empty 200 is the
# specific glitch a reader admitted mid-`apply_full` (which clears before it refills) would observe,
# and pfBlockerNG would install it as an empty alias.
FLOOD_NOT_200=$(awk '$1 != "200"' "$FLOOD_RESULTS" | wc -l)
check_local "$FLOOD_NOT_200" "0" "Stage C: zero non-200 responses under concurrent load during resyncs"
FLOOD_EMPTY=$(awk '$2 == "0"' "$FLOOD_RESULTS" | wc -l)
check_local "$FLOOD_EMPTY" "0" "Stage C: zero empty-body responses — no reader ever saw a mid-resync empty cache"

# Every body must be the full feed, not a partial one truncated by a concurrent cache swap.
FLOOD_MIN_BYTES=$(awk '{print $2}' "$FLOOD_RESULTS" | sort -n | head -1)
FLOOD_MAX_BYTES=$(awk '{print $2}' "$FLOOD_RESULTS" | sort -n | tail -1)
check_local "$FLOOD_MIN_BYTES" "$FLOOD_MAX_BYTES" "Stage C: every response carried an identical full-length body (min == max bytes) — no partial reads"

# ── 5. HTTP optimizations & anti-DoS ────────────────────────────────────────

log_section "5. HTTP Optimizations (ETag/304) & Anti-DoS (429)"

# A fresh simulated client, isolated from §4's bucket.
raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.12" -D "$WORK_DIR/headers_5"
check "200" "first request from this client is served in full"
ETAG=$(grep -i '^etag:' "$WORK_DIR/headers_5" | tr -d '\r' | awk -F': ' '{print $2}')
if [ -z "$ETAG" ]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    err "no ETag header was returned — cannot continue §5"
else
    PASS_COUNT=$((PASS_COUNT + 1))
    log "Captured ETag: $ETAG"

    raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.12" -H "If-None-Match: $ETAG"
    check "304" "a matching If-None-Match returns 304 Not Modified"

    raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.12"
    check "429" "an immediate unconditional repeat from the same source IP is rate-limited"

    raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.12" -H "If-None-Match: $ETAG"
    check "304" "a matching conditional request is STILL free even though this IP is currently throttled"
fi

# ── 6. Vault soft-delete propagation ────────────────────────────────────────

log_section "6. Vault Soft-Delete Propagation"

raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.21"
check "200" "feed is served before the soft-delete"
check_contains "$RESP_BODY" "8.8.4.4" "8.8.4.4/32 is present in the feed (synced during §3's wait)"

log "Looking up 8.8.4.4/32's Vault record id..."
api_call "$VAULT_URL" GET "/api/ips?ip=8.8.4.4" "$VAULT_MASTER_KEY"
check "200" "the record lookup succeeds"
check_jq "length" "1" "exactly one matching record"
SOFT_DELETE_RECORD_ID=$(echo "$RESP_BODY" | jq -r '.[0].id')

log "Soft-deleting 8.8.4.4/32 in Vault (DELETE /api/ips/<id>, no ?hard=true)..."
api_call "$VAULT_URL" DELETE "/api/ips/$SOFT_DELETE_RECORD_ID" "$VAULT_MASTER_KEY"
check "200" "the soft-delete request succeeds"
check_jq ".deleted" "soft" "the deletion is soft (deleted_at set), not permanent"

# Both the DMZ feed and §4's secondary-group-only feed have ttl_seconds=2, so both are due and
# sync sequentially in the same pass here too — same margin reasoning as §3/§4's wait above.
log "Waiting for the next differential sync (ttl_seconds=2, tick interval 15s) to observe it via \
    since=<last_synced_at>&include_deleted=true..."
sleep 19

raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.22"
check "200" "feed is served after the soft-delete"
check_not_contains "$RESP_BODY" "8.8.4.4" "8.8.4.4/32 is gone from the feed — the differential sync picked up the soft-delete and evicted it from the in-memory cache"
check_contains "$RESP_BODY" "8.8.8.0/24" "unrelated cached content survives the differential merge untouched"

# ── 7. Hot-reload of endpoint configuration ─────────────────────────────────

log_section "7. Hot-Reload of Endpoint Configuration"

raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.31"
check "200" "feed served before the hot-reload"
check_not_contains "$RESP_BODY" "192.168.1.50" "the private IP stays hidden while filter_rfc1918=true"

log "Disabling filter_rfc1918 via a signed PUT /api/endpoints/$FEED_ENDPOINT_ID..."
api_call "$EXPORTER_URL" PUT "/api/endpoints/$FEED_ENDPOINT_ID" "$EXPORTER_MASTER_KEY" '{"filter_rfc1918":false}'
check "200" "the endpoint update succeeds"
check_jq ".filter_rfc1918" "false" "filter_rfc1918 now reads false"

log "Re-querying the feed immediately — no exporter restart, no wait for a sync tick..."
raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.32"
check "200" "feed served after the hot-reload"
check_contains "$RESP_BODY" "192.168.1.50" "the private IP now appears: the config change took effect on the very next request, live"

log "Restoring filter_rfc1918=true for the remainder of the run..."
api_call "$EXPORTER_URL" PUT "/api/endpoints/$FEED_ENDPOINT_ID" "$EXPORTER_MASTER_KEY" '{"filter_rfc1918":true}'
check "200" "filter_rfc1918 is restored"
raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.33"
check_not_contains "$RESP_BODY" "192.168.1.50" "the private IP is hidden again immediately after restoring the filter"

# ── 8. Client IP restriction (bound_ips) ────────────────────────────────────

log_section "8. Client IP Restriction (bound_ips)"

log "Creating an endpoint restricted to 10.10.0.0/16..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"Restricted Feed","vault_groups":"pfBlocker_Blacklist","bound_ips":"10.10.0.0/16"}'
check "200" "the restricted endpoint is created"
check_jq ".bound_ips" "10.10.0.0/16" "bound_ips is set as configured"
RESTRICTED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')

raw_call GET "$EXPORTER_URL$RESTRICTED_PATH" -H "X-Forwarded-For: 10.10.5.5"
check "200" "an authorized source IP (10.10.5.5, inside 10.10.0.0/16) is served"

raw_call GET "$EXPORTER_URL$RESTRICTED_PATH" -H "X-Forwarded-For: 203.0.113.99"
check "403" "an unauthorized source IP (203.0.113.99, outside the bound CIDR) is rejected"

# ── 9. Restart & persistence recovery (encrypted at rest) ──────────────────

log_section "9. Restart & Persistence Recovery (Encrypted at Rest)"

log "Creating a Daughter key whose signing_secret will be sealed with EXPORTER_ENCRYPTION_KEY..."
api_call "$EXPORTER_URL" POST "/api/keys" "$EXPORTER_MASTER_KEY" '{"name":"Persistence Test Daughter"}'
check "200" "the Daughter key is created"
DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
DAUGHTER_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$DAUGHTER_KEY" "$DAUGHTER_SECRET"

api_call "$EXPORTER_URL" GET "/api/auth/me" "$DAUGHTER_KEY"
check "200" "the Daughter key authenticates before the restart"

log "Sending SIGTERM to simply_ip_exporter (pid $EXPORTER_PID) for a graceful shutdown..."
kill -TERM "$EXPORTER_PID"
wait "$EXPORTER_PID" 2>/dev/null
EXPORTER_EXIT_CODE=$?
EXPORTER_PID=""
check_local "$EXPORTER_EXIT_CODE" "0" "simply_ip_exporter exited cleanly (code 0) on SIGTERM"

log "Restarting simply_ip_exporter against the SAME database file ($EXPORTER_DB_PATH)..."
# Deliberately no INITIAL_MASTER_KEY this time: the master row already exists, so this proves the
# persisted row (not a fresh bootstrap) is what authenticates after restart.
DATABASE_URL="sqlite://$EXPORTER_DB_PATH?mode=rwc" RUST_LOG=info \
    EXPORTER_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    VAULT_BASE_URL="$VAULT_URL" \
    VAULT_API_KEY="$EXPORTER_VAULT_KEY" \
    VAULT_SIGNING_SECRET="$EXPORTER_VAULT_SECRET" \
    TRUSTED_PROXIES="127.0.0.1" \
    PORT="$EXPORTER_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_exporter" >>"$EXPORTER_LOG" 2>&1 &
EXPORTER_PID=$!
log "Waiting for the restarted simply_ip_exporter to become ready (pid $EXPORTER_PID)..."
wait_ready "simply_ip_exporter" "$EXPORTER_URL" "$EXPORTER_PID" "$EXPORTER_LOG"
log "simply_ip_exporter is back up."

api_call "$EXPORTER_URL" GET "/api/auth/me" "$EXPORTER_MASTER_KEY"
check "200" "the Master key still authenticates after restart (the persisted row, not a re-bootstrap)"
check_jq ".is_master" "true" "still reports is_master=true"

api_call "$EXPORTER_URL" GET "/api/auth/me" "$DAUGHTER_KEY"
check "200" "the pre-restart Daughter key STILL authenticates: its signing_secret was sealed, persisted, and successfully decrypted again with the same EXPORTER_ENCRYPTION_KEY"

raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.41"
check "200" "the original feed endpoint's token still resolves after restart (the endpoint row persisted)"

# Three endpoints exist by this point (the DMZ feed, §4's secondary-group-only feed, and §8's
# bound_ips-restricted feed) and all sync sequentially in the same post-restart pass — same
# reasoning as the 20s margin above, just with a third endpoint added to the pass.
log "Waiting for the in-memory IP cache (cleared on restart) to re-hydrate from Vault via the sync worker's first tick..."
sleep 20

raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.42"
check "200" "feed served again after cache rehydration"
check_contains "$RESP_BODY" "8.8.8.0/24" "the rehydrated cache contains the expected aggregated content"
check_not_contains "$RESP_BODY" "8.8.4.4" "the soft-deleted address is NOT resurrected by the post-restart full sync"
check_not_contains "$RESP_BODY" "192.168.1.50" "filter_rfc1918 (restored to true in §7) is still enforced after restart"

log "Verifying live background cleanup removed the grant for the group deleted in Vault..."
api_call "$EXPORTER_URL" GET "/api/keys/$GSD_ID/groups" "$EXPORTER_MASTER_KEY"
check "200" "Daughter key groups list returns 200 OK after restart"
check_jq "length" "1" "background cleanup removed the stale grant for the deleted Vault group"
check_jq ".[0].vault_group_name" "pfBlocker_Blacklist" "valid grant for pfBlocker_Blacklist survived background cleanup"

# ── 10. Wrong encryption key at startup ─────────────────────────────────────

log_section "10. Wrong Encryption Key Rejected At Startup"

log "Stopping simply_ip_exporter (pid $EXPORTER_PID) for the wrong-key restart attempt..."
kill -TERM "$EXPORTER_PID"
wait "$EXPORTER_PID" 2>/dev/null
EXPORTER_EXIT_CODE=$?
EXPORTER_PID=""
check_local "$EXPORTER_EXIT_CODE" "0" "simply_ip_exporter exited cleanly (code 0) on SIGTERM, before the wrong-key attempt"

# 64 hex characters, same shape as E2E_ENCRYPTION_KEY (so it passes the format check that runs
# before the canary decrypt) but different bytes, so it cannot open what E2E_ENCRYPTION_KEY sealed.
# Built with printf rather than a literal: a hand-counted string of repeated characters is exactly
# the kind of off-by-one that silently changes what's under test instead of failing loudly.
WRONG_ENCRYPTION_KEY="$(printf 'f%.0s' $(seq 1 64))"
WRONGKEY_LOG="$WORK_DIR/exporter_wrongkey.log"
log "Attempting to start simply_ip_exporter against the SAME database ($EXPORTER_DB_PATH) with a different (syntactically valid) EXPORTER_ENCRYPTION_KEY..."
DATABASE_URL="sqlite://$EXPORTER_DB_PATH?mode=rwc" RUST_LOG=info \
    EXPORTER_ENCRYPTION_KEY="$WRONG_ENCRYPTION_KEY" \
    VAULT_BASE_URL="$VAULT_URL" \
    VAULT_API_KEY="$EXPORTER_VAULT_KEY" \
    VAULT_SIGNING_SECRET="$EXPORTER_VAULT_SECRET" \
    TRUSTED_PROXIES="127.0.0.1" \
    PORT="$EXPORTER_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_exporter" >"$WRONGKEY_LOG" 2>&1 &
WRONGKEY_PID=$!

log "Waiting for it to refuse to start (should exit quickly on its own, without ever answering /ready)..."
WRONGKEY_EXITED="false"
for _ in $(seq 1 40); do
    if ! kill -0 "$WRONGKEY_PID" 2>/dev/null; then
        WRONGKEY_EXITED="true"
        break
    fi
    sleep 0.25
done

if [ "$WRONGKEY_EXITED" == "true" ]; then
    wait "$WRONGKEY_PID" 2>/dev/null
    WRONGKEY_EXIT_CODE=$?
else
    warn "simply_ip_exporter did not exit on its own with the wrong key; killing it and failing this check."
    kill -9 "$WRONGKEY_PID" 2>/dev/null || true
    wait "$WRONGKEY_PID" 2>/dev/null || true
    WRONGKEY_EXIT_CODE=0 # the one value this check must NOT accept: it means startup never stopped
fi

if [ "$WRONGKEY_EXITED" == "true" ] && [ "$WRONGKEY_EXIT_CODE" -ne 0 ] 2>/dev/null; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} simply_ip_exporter terminated on its own (exit code $WRONGKEY_EXIT_CODE, non-zero) rather than starting with an undecryptable database" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} simply_ip_exporter did not cleanly refuse to start with the wrong key (exited on its own: $WRONGKEY_EXITED, code: $WRONGKEY_EXIT_CODE)" >&2
fi

WRONGKEY_LOG_CONTENTS=$(cat "$WRONGKEY_LOG" 2>/dev/null || true)
check_not_contains "$WRONGKEY_LOG_CONTENTS" "panicked at" "no Rust panic in the log — this is a handled error, not a crash"
check_contains "$WRONGKEY_LOG_CONTENTS" "EXPORTER_ENCRYPTION_KEY does not match" "the log names the actual problem, not a generic failure"

DOWN_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$EXPORTER_URL/ready" 2>/dev/null)
check_local "$DOWN_CODE" "000" "simply_ip_exporter with the wrong key never came up far enough to answer /ready — no silent partial startup"

log "Restarting simply_ip_exporter with the CORRECT EXPORTER_ENCRYPTION_KEY so the suite can continue..."
DATABASE_URL="sqlite://$EXPORTER_DB_PATH?mode=rwc" RUST_LOG=info \
    EXPORTER_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    VAULT_BASE_URL="$VAULT_URL" \
    VAULT_API_KEY="$EXPORTER_VAULT_KEY" \
    VAULT_SIGNING_SECRET="$EXPORTER_VAULT_SECRET" \
    TRUSTED_PROXIES="127.0.0.1" \
    PORT="$EXPORTER_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_exporter" >>"$EXPORTER_LOG" 2>&1 &
EXPORTER_PID=$!
log "Waiting for the restarted simply_ip_exporter to become ready (pid $EXPORTER_PID)..."
wait_ready "simply_ip_exporter" "$EXPORTER_URL" "$EXPORTER_PID" "$EXPORTER_LOG"
log "simply_ip_exporter is back up with the correct key."

api_call "$EXPORTER_URL" GET "/api/auth/me" "$EXPORTER_MASTER_KEY"
check "200" "the Master key still authenticates once restarted with the correct key (no DB corruption from the failed attempt)"

api_call "$EXPORTER_URL" GET "/api/auth/me" "$DAUGHTER_KEY"
check "200" "the pre-existing Daughter key still authenticates too, unaffected by the failed wrong-key attempt"

# ── 11. HMAC anti-replay: timestamp skew rejection ──────────────────────────

log_section "11. HMAC Anti-Replay: Timestamp Skew Rejection"

SKEW_TS_FUTURE=$(( $(date -u +%s) + 301 ))
SKEW_SIG_FUTURE=$(hmac_sign "$EXPORTER_MASTER_SECRET" GET "/api/auth/me" "$SKEW_TS_FUTURE" "")
log "Signing a request +301s ahead of server time..."
raw_call GET "$EXPORTER_URL/api/auth/me" \
    -H "X-API-Key: $EXPORTER_MASTER_KEY" \
    -H "X-Timestamp: $SKEW_TS_FUTURE" \
    -H "X-Signature-256: $SKEW_SIG_FUTURE"
check "401" "a validly-signed request timestamped +301s in the future is rejected"
check_contains "$RESP_BODY" "outside the permitted" "the error names the timestamp window, not a generic auth failure"

SKEW_TS_PAST=$(( $(date -u +%s) - 301 ))
SKEW_SIG_PAST=$(hmac_sign "$EXPORTER_MASTER_SECRET" GET "/api/auth/me" "$SKEW_TS_PAST" "")
log "Signing a request -301s behind server time..."
raw_call GET "$EXPORTER_URL/api/auth/me" \
    -H "X-API-Key: $EXPORTER_MASTER_KEY" \
    -H "X-Timestamp: $SKEW_TS_PAST" \
    -H "X-Signature-256: $SKEW_SIG_PAST"
check "401" "a validly-signed request timestamped -301s in the past is rejected"
check_contains "$RESP_BODY" "outside the permitted" "the error names the timestamp window here too"

log "Confirming the key itself is still fine — only the timestamp was the problem..."
api_call "$EXPORTER_URL" GET "/api/auth/me" "$EXPORTER_MASTER_KEY"
check "200" "a freshly-timestamped request from the same key succeeds"

# ── 12. Real-time Daughter key rotation/revocation ──────────────────────────

log_section "12. Real-Time Daughter Key Rotation/Revocation"

log "Confirming the pre-existing Daughter key (from §9) still works before rotating it..."
api_call "$EXPORTER_URL" GET "/api/auth/me" "$DAUGHTER_KEY"
check "200" "the Daughter key authenticates before rotation"
OLD_DAUGHTER_KEY="$DAUGHTER_KEY"

log "Rotating it via the Master key (POST /api/keys/\$id/rotate)..."
api_call "$EXPORTER_URL" POST "/api/keys/$DAUGHTER_ID/rotate" "$EXPORTER_MASTER_KEY"
check "200" "the rotation request succeeds"
NEW_DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
NEW_DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$NEW_DAUGHTER_KEY" "$NEW_DAUGHTER_SECRET"

log "Immediately retrying with the OLD (pre-rotation) credentials — no restart, no delay..."
api_call "$EXPORTER_URL" GET "/api/auth/me" "$OLD_DAUGHTER_KEY"
check "401" "the old credentials are rejected on the very next request after rotation"

log "Confirming the NEW credentials work immediately..."
api_call "$EXPORTER_URL" GET "/api/auth/me" "$NEW_DAUGHTER_KEY"
check "200" "the newly rotated credentials authenticate right away"
DAUGHTER_KEY="$NEW_DAUGHTER_KEY"

log "Minting a throwaway Daughter key to exercise instant revocation via DELETE..."
api_call "$EXPORTER_URL" POST "/api/keys" "$EXPORTER_MASTER_KEY" '{"name":"Revocation Test Daughter"}'
check "200" "the throwaway Daughter key is created"
DOOMED_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
DOOMED_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
DOOMED_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$DOOMED_KEY" "$DOOMED_SECRET"

api_call "$EXPORTER_URL" GET "/api/auth/me" "$DOOMED_KEY"
check "200" "the throwaway key authenticates before deletion"

log "Deleting it via the Master key..."
api_call "$EXPORTER_URL" DELETE "/api/keys/$DOOMED_ID" "$EXPORTER_MASTER_KEY"
check "204" "the delete request succeeds"

log "Immediately retrying with the deleted key's credentials — no restart, no delay..."
api_call "$EXPORTER_URL" GET "/api/auth/me" "$DOOMED_KEY"
check "401" "the deleted key's credentials are rejected on the very next request"

# ── 13. Vault disruption & resilience ───────────────────────────────────────

log_section "13. Vault Disruption & Resilience"

log "Terminating simply_ip_vault (pid $VAULT_PID)..."
kill "$VAULT_PID" 2>/dev/null || true
wait "$VAULT_PID" 2>/dev/null || true
VAULT_PID=""

if command -v fuser >/dev/null 2>&1; then
    for _ in $(seq 1 20); do
        fuser "$VAULT_PORT/tcp" >/dev/null 2>&1 || break
        sleep 0.2
    done
fi
log "simply_ip_vault is down. Confirming it no longer answers..."
# curl already writes "000" via -w on a failed connection (refused/timeout), so no `|| echo`
# fallback is needed — appending one would double the captured output ("000" + "000").
DOWN_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$VAULT_URL/ready" 2>/dev/null)
check_local "$DOWN_CODE" "000" "simply_ip_vault no longer responds"

# A third simulated client, isolated from §5's throttled bucket, proving this is a fresh request
# being served from cache rather than an artifact of an unexpired earlier response.
raw_call GET "$EXPORTER_URL$FEED_PATH" -H "X-Forwarded-For: 198.51.100.13"
check "200" "simply_ip_exporter keeps serving the feed with Vault offline"
check_contains "$RESP_BODY" "8.8.8.0/24" "the cached, aggregated content is unchanged with Vault offline"

api_call "$EXPORTER_URL" GET "/ready" "$EXPORTER_MASTER_KEY"
check "200" "simply_ip_exporter's own /ready is unaffected by Vault being unreachable"

# ── 14. Audit log traversal ─────────────────────────────────────────────────

log_section "14. Audit Log Traversal"

log "Fetching the full audit trail from simply_ip_exporter as Master..."
api_call "$EXPORTER_URL" GET "/api/audit-logs?limit=500" "$EXPORTER_MASTER_KEY"
check "200" "the audit log is readable by Master"

for expected_action in KEY_CREATE ENDPOINT_CREATE ENDPOINT_UPDATE; do
    COUNT=$(echo "$RESP_BODY" | jq --arg a "$expected_action" '[.[] | select(.action == $a)] | length')
    if [ -n "$COUNT" ] && [ "$COUNT" -ge 1 ] 2>/dev/null; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the audit trail contains at least one $expected_action entry (found $COUNT)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} the audit trail is missing an entry for $expected_action" >&2
    fi
done

log "Checking attribution and timestamp accuracy on the Daughter key's own KEY_CREATE entry..."
DAUGHTER_ENTRY=$(echo "$RESP_BODY" | jq --arg id "$DAUGHTER_ID" \
    '[.[] | select(.action == "KEY_CREATE" and (.target_resource // "" | contains($id)))] | .[0]')
check_local "$(echo "$DAUGHTER_ENTRY" | jq -r '.api_key_name')" "System Master" \
    "the Daughter key's own KEY_CREATE entry is attributed to the ACTOR who created it (Master), not the new key itself"
check_local "$(echo "$DAUGHTER_ENTRY" | jq -r '.action')" "KEY_CREATE" "the entry's action is exactly KEY_CREATE"

ENTRY_TIMESTAMP=$(echo "$DAUGHTER_ENTRY" | jq -r '.timestamp')
ENTRY_EPOCH=$(date -u -d "$ENTRY_TIMESTAMP" +%s 2>/dev/null || echo "")
NOW_EPOCH=$(date -u +%s)
if [ -n "$ENTRY_EPOCH" ]; then
    AGE=$((NOW_EPOCH - ENTRY_EPOCH))
else
    AGE=-1
fi
if [ "$AGE" -ge 0 ] && [ "$AGE" -lt 300 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the entry's timestamp ($ENTRY_TIMESTAMP) is accurate — ${AGE}s old, well inside this run" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} the entry's timestamp ($ENTRY_TIMESTAMP) looks wrong — ${AGE}s old" >&2
fi

# The audit trail is written to the same SQLite database as everything else, so it must have
# survived §9's restart intact — entries from both before and after the restart should be present.
# Ten endpoints are created before the restart: the main DMZ feed, §4's group-scoping "Secondary
# Group Only Feed", §4b's large-dataset "Pagination Feed", §4c's three retention-window feeds,
# Daughter Blacklist Feed, and §8's bound_ips-restricted "Restricted Feed". (The negative
# max_age_seconds attempt in §3 was refused, so it writes no audit entry — which this count
# incidentally confirms.)
PRE_RESTART_COUNT=$(echo "$RESP_BODY" | jq --arg a "ENDPOINT_CREATE" '[.[] | select(.action == $a)] | length')
check_local "$PRE_RESTART_COUNT" "10" "all ten ENDPOINT_CREATE entries (created before the restart) survived it"

log "Confirming a Daughter key cannot read the audit log..."
api_call "$EXPORTER_URL" GET "/api/audit-logs" "$DAUGHTER_KEY"
check "403" "a Daughter key is forbidden from GET /api/audit-logs"

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo -e "$(ts) ${BOLD}Results: ${GREEN}$PASS_COUNT passed${RESET}${BOLD}, ${RED}$FAIL_COUNT failed${RESET}${BOLD} (of $TOTAL checks)${RESET}" >&2

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "$(ts) ${GREEN}${BOLD}ALL CHECKS PASSED${RESET}" >&2
    exit 0
else
    echo -e "$(ts) ${RED}${BOLD}$FAIL_COUNT CHECK(S) FAILED${RESET}" >&2
    exit 1
fi
