#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test | awk '
    { print }
    /^test result:/ {
        summaries++
        if ($0 !~ /; 0 failed; 0 ignored;/) failed = 1
    }
    END {
        if (!summaries || failed) {
            print "Expected test summaries with zero failed and zero ignored tests." > "/dev/stderr"
            exit 1
        }
    }
'
cargo audit --deny warnings
bash -n scripts/test_e2e.sh
