#!/usr/bin/env bash
#
# Source hygiene / convergence checks for simply_ip_exporter, per AGENT.MD:
#
#   1. Zero raw SQL outside src/db.rs and src/migration/ (pragmas in db.rs are the documented
#      exception; everything else must go through SeaORM's query builder).
#   2. Zero `.unwrap()`/`.expect()` in production code (test code is exempt).
#   3. static/app.js parses as valid JavaScript and every element id it looks up via el(...)
#      actually exists in static/index.html.
#
# The actual analysis lives in tests/source_hygiene.rs (a real Rust file scanner plus an oxc-based
# JS parser for the JS check — a shell script cannot reliably parse either). This script is the
# single, memorable entry point `./scripts/verify_convergence.sh` the validation checklist expects,
# and adds one thing the bare `cargo test` invocation doesn't: a pass/fail summary per named check
# rather than an undifferentiated test list.
#
# Usage: ./scripts/verify_convergence.sh
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ts() { date +"%H:%M:%S.%3N"; }
log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }

if ! command -v cargo >/dev/null 2>&1; then
    err "cargo is required but not found on PATH"
    exit 1
fi

cd "$PROJECT_ROOT"

# Each check is run as its own named test, so a failure names exactly which convention was
# violated (and where) rather than reporting one undifferentiated "tests failed".
declare -A CHECKS=(
    ["Zero raw SQL outside src/db.rs and src/migration/"]="no_raw_sql_outside_db_rs_and_migrations"
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

echo "" >&2
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "$(ts) ${GREEN}${BOLD}ALL CONVERGENCE CHECKS PASSED${RESET}" >&2
    exit 0
else
    echo -e "$(ts) ${RED}${BOLD}$FAIL_COUNT CONVERGENCE CHECK(S) FAILED${RESET}" >&2
    exit 1
fi
