#!/usr/bin/env bash
#
# Convergence gate for simply_ip_exporter: source hygiene, lint, and the full test suite, per
# AGENT.MD. Source hygiene specifically means:
#
#   1. Zero raw SQL outside src/db.rs and src/migration/ (pragmas in db.rs are the documented
#      exception; everything else must go through SeaORM's query builder).
#   2. Zero `.unwrap()`/`.expect()` in production code (test code is exempt).
#   3. static/app.js parses as valid JavaScript and every element id it looks up via el(...)
#      actually exists in static/index.html.
#
# Before any of that, it synchronizes every peer repository checked out under example/ (see
# AGENT.MD's "Peer Repository Synchronization" section) so a convergence/security comparison never
# runs unknowingly against a stale checkout. That step is best-effort: offline runs, or a peer
# whose remote is unreachable, log a warning and fall through to whatever is on disk rather than
# failing the whole gate over a network hiccup.
#
# The source-hygiene analysis itself lives in tests/source_hygiene.rs (a real Rust file scanner plus
# an oxc-based JS parser for the JS check — a shell script cannot reliably parse either). This
# script is the single, memorable entry point `./scripts/verify_convergence.sh` the validation
# checklist expects, and adds one thing the bare `cargo test` invocation doesn't: a pass/fail
# summary per named check rather than an undifferentiated test list. `cargo clippy -D warnings` and
# `cargo test` run afterwards as two more named checks in the same summary, so a single invocation
# of this script is a complete pre-commit gate rather than one piece of a checklist run by hand.
#
# Usage: ./scripts/verify_convergence.sh
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ts() { date +"%H:%M:%S.%3N"; }
log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }

if ! command -v cargo >/dev/null 2>&1; then
    err "cargo is required but not found on PATH"
    exit 1
fi

cd "$PROJECT_ROOT"

# ── Peer repository synchronization ─────────────────────────────────────────
#
# See AGENT.MD's "Peer Repository Synchronization" section: analysis against a peer checked out
# under example/ must reflect its current upstream HEAD, not whatever happened to be on disk from
# whenever that checkout was last updated. `nullglob` makes the loop below a silent no-op when
# example/ doesn't exist or holds no git checkouts, rather than iterating over a literal, unmatched
# glob pattern.
shopt -s nullglob
PEER_GIT_DIRS=("$PROJECT_ROOT"/example/*/.git)
shopt -u nullglob

if [ "${#PEER_GIT_DIRS[@]}" -eq 0 ]; then
    log "No peer repositories found under example/ — skipping sync."
else
    log "Synchronizing ${#PEER_GIT_DIRS[@]} peer repository/ies under example/ ..."
    for git_dir in "${PEER_GIT_DIRS[@]}"; do
        peer_dir="$(dirname "$git_dir")"
        peer_name="$(basename "$peer_dir")"
        # Bounded so an unreachable remote degrades to a warning within seconds rather than
        # hanging the whole convergence gate on a stalled network connection.
        if PULL_OUTPUT=$(timeout 15 git -C "$peer_dir" pull --quiet 2>&1); then
            log "  $peer_name: synchronized"
        else
            warn "⚠️ Warning: Could not pull peer repository '$peer_name', continuing with local version..."
            [ -n "$PULL_OUTPUT" ] && warn "  $(echo "$PULL_OUTPUT" | head -1)"
        fi
    done
fi

# Each check is run as its own named test, so a failure names exactly which convention was
# violated (and where) rather than reporting one undifferentiated "tests failed".
declare -A CHECKS=(
    ["Zero raw SQL outside the documented exceptions"]="no_raw_sql_outside_the_documented_exceptions"
    ["Zero hand-written DML string literals outside the documented exceptions"]="no_dml_keyword_is_hand_written_outside_the_exceptions"
    ["No request handler ever holds a raw-SQL exemption"]="no_raw_sql_handler_is_ever_exempted"
    ["Every raw-SQL allowlist entry still exists and is still needed"]="every_allowlisted_raw_sql_exception_still_exists_and_is_still_needed"
    ["...and the raw-SQL scanner actually detects what it looks for"]="the_raw_sql_scanner_detects_what_it_is_looking_for"
    ["Zero .unwrap()/.expect() in production code"]="no_unwrap_or_expect_in_production_code"
    ["Production/test-code boundary detection is sound"]="every_source_file_places_its_test_module_last"
    ["static/app.js parses as valid JavaScript"]="app_js_has_no_syntax_errors"
    ["...and the parser actually rejects broken input"]="the_syntax_check_rejects_broken_javascript"
    ["Every el(...) id in app.js exists in index.html"]="every_dom_id_referenced_in_app_js_exists_in_index_html"
    ["...and the DOM-reference check actually rejects a missing id"]="the_dom_id_check_rejects_a_reference_to_a_nonexistent_id"
)

log "Building the source_hygiene test binary..."
BUILD_LOG="$(mktemp)"
if ! cargo test --test source_hygiene --no-run --quiet 2>"$BUILD_LOG"; then
    err "Build failed:"
    cat "$BUILD_LOG" >&2
    rm -f "$BUILD_LOG"
    exit 1
fi
rm -f "$BUILD_LOG"

FAIL_COUNT=0
echo "" >&2
for description in "${!CHECKS[@]}"; do
    test_name="${CHECKS[$description]}"
    OUTPUT="$(cargo test --test source_hygiene --quiet -- --exact "$test_name" 2>&1)"
    if echo "$OUTPUT" | grep -q "test result: ok. 1 passed"; then
        echo -e "$(ts) ${GREEN}✓ PASS${RESET} $description" >&2
    else
        echo -e "$(ts) ${RED}✗ FAIL${RESET} $description" >&2
        echo "$OUTPUT" | sed 's/^/          /' >&2
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

# ── Lint and the full test suite ────────────────────────────────────────────
#
# Named checks in the same summary as the hygiene scans above, not separate scripts to run by
# hand — a passing `verify_convergence.sh` is meant to mean the whole pre-commit gate is green, not
# just the source-hygiene third of it.
echo "" >&2
log "Running cargo clippy --all-targets -- -D warnings ..."
CLIPPY_OUTPUT="$(cargo clippy --all-targets --quiet -- -D warnings 2>&1)"
if [ $? -eq 0 ]; then
    echo -e "$(ts) ${GREEN}✓ PASS${RESET} cargo clippy --all-targets -- -D warnings" >&2
else
    echo -e "$(ts) ${RED}✗ FAIL${RESET} cargo clippy --all-targets -- -D warnings" >&2
    echo "$CLIPPY_OUTPUT" | sed 's/^/          /' >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

log "Running cargo test (unit + integration + source-hygiene) ..."
TEST_OUTPUT="$(cargo test --quiet 2>&1)"
if [ $? -eq 0 ]; then
    echo -e "$(ts) ${GREEN}✓ PASS${RESET} cargo test" >&2
else
    echo -e "$(ts) ${RED}✗ FAIL${RESET} cargo test" >&2
    echo "$TEST_OUTPUT" | sed 's/^/          /' >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo "" >&2
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "$(ts) ${GREEN}${BOLD}ALL CONVERGENCE CHECKS PASSED${RESET}" >&2
    exit 0
else
    echo -e "$(ts) ${RED}${BOLD}$FAIL_COUNT CONVERGENCE CHECK(S) FAILED${RESET}" >&2
    exit 1
fi
