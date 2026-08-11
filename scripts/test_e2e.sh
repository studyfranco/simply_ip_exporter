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
#      overlapping pair of public addresses, a CGN "bogon" address, and (via a whitelist group,
#      since simply_ip_vault refuses to /ban a private address) an RFC 1918 address.
#   3. Exporter configuration: an HMAC CANONICAL_V1-signed POST /api/endpoints wired to those Vault
#      groups with ttl_seconds=2, filter_rfc1918=true, filter_bogons=true.
#   4. Feed verification: text/plain output, ipnet::IpNet::aggregate() merging the overlapping
#      pair, and both filters actually removing what they claim to.
#   5. HTTP optimizations & anti-DoS: ETag + If-None-Match -> 304 (and that a matching conditional
#      request is NOT rate-limited), then a bare repeat -> 429.
#   6. Resilience: kill simply_ip_vault, confirm simply_ip_exporter keeps serving the same
#      in-memory cached feed without interruption.
#   7. Cleanup: terminate both processes and remove every temporary file.
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
        args+=(-H "Content-Type: application/json" -d "$data")
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

api_call "$VAULT_URL" GET "/api/ips?groups=pfBlocker_Blacklist,pfBlocker_Private_Test" "$EXPORTER_VAULT_KEY"
check "200" "the scoped Exporter key can read across both groups"
check_jq "length" "4" "sees all 4 seeded records (restrict-not-reject: no group is silently rejected)"

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

log "Creating the public feed endpoint (ttl_seconds=2, filter_rfc1918=true, filter_bogons=true)..."
api_call "$EXPORTER_URL" POST "/api/endpoints" "$EXPORTER_MASTER_KEY" \
    '{"name":"pfBlockerNG DMZ Feed","vault_groups":"pfBlocker_Blacklist,pfBlocker_Private_Test","ttl_seconds":2,"filter_rfc1918":true,"filter_bogons":true}'
check "200" "the feed endpoint is created"
check_jq ".filter_rfc1918" "true" "filter_rfc1918 is set as configured"
check_jq ".filter_bogons" "true" "filter_bogons is set as configured"
FEED_TOKEN=$(echo "$RESP_BODY" | jq -r '.token_secret')
FEED_PATH=$(echo "$RESP_BODY" | jq -r '.feed_path')
log "Feed path: $FEED_PATH"

log "Waiting for the background sync worker (15s tick interval, endpoint is due for an immediate full sync)..."
sleep 18

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
check_not_contains "$RESP_BODY" "192.168.1.50" "the RFC1918 address is filtered out (filter_rfc1918=true)"
check_not_contains "$RESP_BODY" "100.64.0.5" "the CGN bogon address is filtered out (filter_bogons=true)"
LINE_COUNT=$(echo "$RESP_BODY" | grep -c . || true)
check_local "$LINE_COUNT" "1" "exactly one line remains after aggregation and filtering"

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

# ── 6. Vault disruption & resilience ────────────────────────────────────────

log_section "6. Vault Disruption & Resilience"

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
