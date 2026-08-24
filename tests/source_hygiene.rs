//! Static source-hygiene checks that nothing else in the build enforces: `AGENT.MD`'s "zero raw
//! SQL outside `src/db.rs`/migrations" and "zero `.unwrap()`/`.expect()` in production code"
//! rules, and that the embedded dashboard (`static/`) is actually loadable in a browser.
//!
//! `cargo check`/`clippy`/`test` compile and exercise Rust; none of them can see a raw SQL string
//! literal (as opposed to a SeaORM query builder call) or a syntax error in a file that is served
//! straight off disk and never compiled. `scripts/verify_convergence.sh` wraps this test suite for
//! a single `./scripts/verify_convergence.sh` entry point.

use std::path::{Path, PathBuf};

/// Resolves a path relative to the crate root, independent of `cargo test`'s working directory.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Every `.rs` file under `src/`, relative to the crate root, in a stable (sorted) order.
fn src_files() -> Vec<String> {
    let mut out = Vec::new();
    collect_rs_files(&repo_path("src"), &mut out);
    out.sort();
    out
}

fn collect_rs_files(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let relative = path
                .strip_prefix(repo_path("."))
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push(relative);
        }
    }
}

/// Byte offset of the `#[cfg(test)]\nmod tests` declaration, if the file has one.
///
/// Deliberately **not** just the first `#[cfg(test)]` occurrence: `src/ratelimit.rs` and
/// `src/replay.rs` each carry a small `#[cfg(test)] fn tracked(...)` test-only accessor *inside*
/// their production `impl` block, ahead of the real test module. Cutting at that inner attribute
/// would silently exclude the rest of the `impl` block — including, in principle, any production
/// code placed after it — from every check below. Only the attribute directly guarding the `mod
/// tests` item marks the real boundary.
fn test_module_offset(contents: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(rel) = contents[search_from..].find("#[cfg(test)]") {
        let attr_start = search_from + rel;
        let after_attr = &contents[attr_start + "#[cfg(test)]".len()..];
        if after_attr.trim_start().starts_with("mod tests") {
            return Some(attr_start);
        }
        search_from = attr_start + "#[cfg(test)]".len();
    }
    None
}

/// The production-code portion of a file: everything before its `#[cfg(test)] mod tests { ... }`
/// block. See [`test_module_offset`] for why that boundary, specifically, is what is located.
fn production_code_lines(contents: &str) -> &str {
    match test_module_offset(contents) {
        Some(offset) => &contents[..offset],
        None => contents,
    }
}

/// Lines of `text`, paired with 1-indexed line numbers, excluding `//`-comment-only lines.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line))
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// APIs that mean "this line executes raw SQL", per `AGENT.MD`: "Never write vendor-specific raw
/// SQL queries. Zero raw SQL for DML in `src/`." `Expr::cust` is included even though it sits
/// inside the query builder: it splices an uninterpreted fragment into a statement, so it carries
/// exactly the injection risk the builder otherwise removes.
///
/// Ported and strengthened from `example/simply_ip_vault`'s `tests/source_hygiene.rs` (2026-08-17
/// peer test-harness audit — see `AGENT_NOTES.MD`): the original version here matched only the
/// bare marker list. Vault's version additionally scans for the *shape* of hand-written DML inside
/// string literals (below) and pins the allowlist to a documented, freshness-checked reason per
/// entry, after its own predecessors shipped broken twice — see vault's module doc comment.
const RAW_SQL_MARKERS: &[&str] = &[
    "Statement::from_string",
    "Statement::from_sql_and_values",
    "execute_raw(",
    "query_one_raw(",
    "query_all_raw(",
    "execute_unprepared(",
    "Expr::cust",
];

/// The **shape** of a DML statement: a leading keyword and the structural word that must follow
/// it. Matching the pair rather than the bare keyword is what makes this usable — a bare-keyword
/// version flags ordinary English error messages ("Cannot delete this endpoint", "no delete
/// access") as violations; a statement has a grammar English almost never reproduces by accident.
const DML_SHAPES: &[(&str, &str)] =
    &[("SELECT ", " FROM "), ("INSERT ", " INTO "), ("UPDATE ", " SET "), ("DELETE ", " FROM ")];

/// The paths permitted to contain raw SQL, each for a reason the query builder cannot address, and
/// each checked by [`every_source_file_places_its_test_module_last`]'s sibling checks below for
/// staying both present and actually still needed.
const RAW_SQL_ALLOWED: &[(&str, &str)] = &[
    (
        "src/db.rs",
        "SQLite `PRAGMA` statements and their readback. A pragma is not a query — it configures how \
         the engine behaves, not what it is asked — and SeaORM's builders cannot express one. \
         Backend-gated to SQLite and issued once at startup.",
    ),
    (
        "src/migration/",
        "DDL. SeaQuery's schema builder has no representation for it, and migrations run once at \
         startup, before the listener binds, interpolating no caller-supplied value.",
    ),
];

/// Whether `relative` is covered by a `(path, reason)` allowlist entry. A trailing `/` matches a
/// whole directory; otherwise the match is exact.
fn matches_allowed(relative: &str, allowed: &str) -> bool {
    match allowed.strip_suffix('/') {
        Some(dir) => relative.starts_with(dir),
        None => relative == allowed,
    }
}

#[test]
fn no_raw_sql_outside_the_documented_exceptions() {
    let mut violations = Vec::new();
    for path in src_files() {
        if RAW_SQL_ALLOWED.iter().any(|(allowed, _)| matches_allowed(&path, allowed)) {
            continue;
        }
        let contents = std::fs::read_to_string(repo_path(&path))
            .unwrap_or_else(|e| panic!("{path} must be readable: {e}"));
        let production = production_code_lines(&contents);
        for (line_no, line) in code_lines(production) {
            if let Some(marker) = RAW_SQL_MARKERS.iter().find(|m| line.contains(**m)) {
                violations.push(format!("{path}:{line_no}: contains {marker:?}\n    {line}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "raw SQL found outside the documented exceptions (AGENT.MD forbids this). If genuinely \
         unavoidable, add it to RAW_SQL_ALLOWED with the reason and record it in AGENT_NOTES.MD:\n{}",
        violations.join("\n")
    );
}

/// The marker scan above catches the SeaORM constructs that carry raw SQL. This catches the
/// string itself — a future helper with a different name, or a `format!`-assembled statement
/// passed to something not on the marker list.
#[test]
fn no_dml_keyword_is_hand_written_outside_the_exceptions() {
    let mut violations = Vec::new();
    for path in src_files() {
        if RAW_SQL_ALLOWED.iter().any(|(allowed, _)| matches_allowed(&path, allowed)) {
            continue;
        }
        let contents = std::fs::read_to_string(repo_path(&path))
            .unwrap_or_else(|e| panic!("{path} must be readable: {e}"));
        let production = production_code_lines(&contents);
        for (line_no, line) in code_lines(production) {
            let Some(open) = line.find('"') else { continue };
            let literal = line[open..].to_uppercase();
            for (keyword, follower) in DML_SHAPES {
                let Some(at) = literal.find(keyword) else { continue };
                if literal[at..].contains(follower) {
                    violations.push(format!(
                        "{path}:{line_no}: string literal contains `{}{}`",
                        keyword.trim_end(),
                        follower.trim_end()
                    ));
                    break;
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "hand-written DML found outside the documented exceptions:\n{}",
        violations.join("\n")
    );
}

/// **No request handler is ever exempted**, whatever the allowlist says — the allowlist is a proxy
/// for "not reachable from a request", and this is the invariant it stands in for. Encoded as a
/// test so the rule survives a future edit to `RAW_SQL_ALLOWED` made by someone who has not read
/// the comment above it.
#[test]
fn no_raw_sql_handler_is_ever_exempted() {
    for (allowed, _) in RAW_SQL_ALLOWED {
        assert!(
            !allowed.starts_with("src/api/"),
            "{allowed} is a request-reachable module and must never hold a raw-SQL exemption. Move \
             the statement into a migration, or express it through SeaORM."
        );
    }
}

/// The allowlist must not outlive its justification: an entry naming a path that no longer exists,
/// or that no longer contains raw SQL, is an exemption nobody is checking, and the next file to
/// land there inherits it silently.
#[test]
fn every_allowlisted_raw_sql_exception_still_exists_and_is_still_needed() {
    let all_paths = src_files();
    for (relative, reason) in RAW_SQL_ALLOWED {
        let bare = relative.trim_end_matches('/');
        assert!(repo_path(bare).exists(), "allowlisted path {relative} no longer exists — drop it");

        let still_needed = all_paths.iter().filter(|p| p.starts_with(bare)).any(|p| {
            let contents = std::fs::read_to_string(repo_path(p)).unwrap_or_default();
            RAW_SQL_MARKERS.iter().any(|m| contents.contains(m))
        });
        assert!(
            still_needed,
            "{relative} is allowlisted for raw SQL but no longer contains any — drop the entry \
             rather than leaving a standing exemption. Recorded reason: {reason}"
        );
    }
}

/// The scanners have to be able to see a violation, or the tests above prove nothing — this is the
/// check vault's own shell-script predecessors of this idea did not have, and both reported CLEAN
/// against a deliberately planted violation (see vault's module doc comment for the history).
#[test]
fn the_raw_sql_scanner_detects_what_it_is_looking_for() {
    let marker_hit = |line: &str| RAW_SQL_MARKERS.iter().any(|m| line.contains(m));
    let dml_hit = |line: &str| {
        line.find('"').is_some_and(|open| {
            let literal = line[open..].to_uppercase();
            DML_SHAPES
                .iter()
                .any(|(keyword, follower)| literal.find(keyword).is_some_and(|at| literal[at..].contains(follower)))
        })
    };

    assert!(marker_hit(r#"    db.execute_unprepared("DROP TABLE api_keys").await?;"#), "missed a real call");
    assert!(dml_hit(r#"    let sql = format!("DELETE FROM api_keys WHERE id = {id}");"#), "missed a hand-built statement");
    for prose in [
        r#"    return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));"#,
        r#"        "The Master key cannot be deleted through the API".to_owned(),"#,
        r#"    let msg = "Deleted the endpoint";"#,
    ] {
        assert!(!dml_hit(prose), "flagged prose: {prose}");
    }
    assert!(dml_hit(r#"    let sql = "update api_keys set is_master = 1";"#), "missed a lowercase statement");
}

#[test]
fn no_unwrap_or_expect_in_production_code() {
    let mut violations = Vec::new();
    for path in src_files() {
        let contents = std::fs::read_to_string(repo_path(&path))
            .unwrap_or_else(|e| panic!("{path} must be readable: {e}"));
        let production = production_code_lines(&contents);
        for (line_no, line) in code_lines(production) {
            if line.contains(".unwrap(") || line.contains(".expect(") {
                violations.push(format!("{path}:{line_no}: {}", line.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "`.unwrap()`/`.expect()` found in production code (AGENT.MD requires structured AppError \
         handling instead):\n{}",
        violations.join("\n")
    );
}

/// Pins the convention [`production_code_lines`] depends on: every file that has a `mod tests`
/// keeps its `#[cfg(test)] mod tests { ... }` block as the very last item, so cutting the file at
/// that boundary is a sound proxy for "production code" without needing a real Rust parser to
/// track module boundaries. Verified independently of [`test_module_offset`]'s own logic (this
/// test does its own boundary search) so a bug shared between the two could not hide from both.
#[test]
fn every_source_file_places_its_test_module_last() {
    let mut violations = Vec::new();
    for path in src_files() {
        let contents = std::fs::read_to_string(repo_path(&path))
            .unwrap_or_else(|e| panic!("{path} must be readable: {e}"));
        // The real module boundary, not merely the first `#[cfg(test)]` attribute — a file may
        // carry an earlier `#[cfg(test)] fn ...` test-only helper inside its production `impl`
        // block (src/ratelimit.rs, src/replay.rs), which is not the boundary this test checks.
        // Independently re-derived (a small forward scan, tolerant of any whitespace between the
        // attribute and `mod tests`) rather than calling `test_module_offset` directly, so a bug
        // in that function's own logic could not evade both it and its own verification.
        let mut offset = None;
        let mut search_from = 0;
        while let Some(rel) = contents[search_from..].find("#[cfg(test)]") {
            let attr_start = search_from + rel;
            let after = &contents[attr_start + "#[cfg(test)]".len()..];
            if after.trim_start().starts_with("mod tests") {
                offset = Some(attr_start);
                break;
            }
            search_from = attr_start + "#[cfg(test)]".len();
        }
        let Some(offset) = offset else { continue };

        // From that point onward, the file must be exactly one well-formed `mod tests { ... }`
        // block (plus whatever trails the marker itself): brace-depth returns to zero exactly
        // once, at the very last non-whitespace character of the file.
        let tail = &contents[offset..];
        let mod_start = tail.find('{').unwrap_or(tail.len());
        let mut depth = 0i32;
        let mut closed_at = None;
        for (i, ch) in tail[mod_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        closed_at = Some(mod_start + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let ends_the_file = match closed_at {
            Some(end) => tail[end + 1..].trim().is_empty(),
            None => false,
        };
        if !ends_the_file {
            violations.push(path);
        }
    }
    assert!(
        violations.is_empty(),
        "these files have code after their #[cfg(test)] module, which would be silently excluded \
         from the production-code hygiene checks above: {violations:?}"
    );
}

// ── Frontend: syntax and DOM-reference validity ─────────────────────────────

/// Parses one file and returns its syntax errors, each rendered as `path:line:col message`.
fn js_syntax_errors(relative: &str) -> Vec<String> {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    let path = repo_path(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{relative} must be readable: {e}"));

    let allocator = Allocator::default();
    // `cjs`, not `mjs`: app.js is loaded with a plain <script> tag (a classic script), and module
    // source would silently accept `import`/`export` that the browser would reject in this context.
    let parsed = Parser::new(&allocator, &source, SourceType::cjs()).parse();

    parsed
        .diagnostics
        .iter()
        .map(|err| {
            let offset =
                (err.labels.first().map_or(0, |span| span.offset()) as usize).min(source.len());
            let line = source[..offset].matches('\n').count() + 1;
            let column = offset - source[..offset].rfind('\n').map_or(0, |i| i + 1) + 1;
            format!("{relative}:{line}:{column}  {}", err.message)
        })
        .collect()
}

#[test]
fn app_js_has_no_syntax_errors() {
    let errors = js_syntax_errors("static/app.js");
    assert!(
        errors.is_empty(),
        "static/app.js has {} syntax error(s) and will not load in a browser:\n  {}",
        errors.len(),
        errors.join("\n  ")
    );
}

/// A syntax check that has never been shown to fail is not evidence of anything: this feeds it a
/// deliberately broken fixture (an unterminated template literal) and asserts it is caught.
#[test]
fn the_syntax_check_rejects_broken_javascript() {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    let broken = r#"
        function render(rows) {
            return rows.map(r => `
                <span title="${r.address}">${r.address}
            `).join('');
        }
        const x = ;
    "#;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, broken, SourceType::cjs()).parse();
    assert!(!parsed.diagnostics.is_empty(), "the fixture is not valid JavaScript and must be rejected");
}

/// Every `el('some-id')` lookup in `app.js` must resolve to a real `id="some-id"` in `index.html`
/// — a mismatch here is a runtime `TypeError: Cannot read properties of null`, invisible to a JS
/// parser (which only checks syntax) and to every other gate in this repository.
#[test]
fn every_dom_id_referenced_in_app_js_exists_in_index_html() {
    let app_js = std::fs::read_to_string(repo_path("static/app.js")).expect("static/app.js must be readable");
    let index_html =
        std::fs::read_to_string(repo_path("static/index.html")).expect("static/index.html must be readable");

    let referenced = extract_el_ids(&app_js);
    assert!(!referenced.is_empty(), "expected app.js to reference at least one element id via el(...)");

    let defined = extract_html_ids(&index_html);

    let missing: Vec<&str> =
        referenced.iter().filter(|id| !defined.contains(*id)).copied().collect();
    assert!(
        missing.is_empty(),
        "app.js calls el(...) with id(s) not present in index.html: {missing:?}"
    );
}

/// Extracts every `el('...')` / `el("...")` argument from a JS source string.
fn extract_el_ids(source: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("el(") {
        let after = &rest[start + 3..];
        let quote = after.chars().next();
        if let Some(q) = quote.filter(|c| *c == '\'' || *c == '"')
            && let Some(end) = after[1..].find(q)
        {
            ids.push(&after[1..1 + end]);
        }
        rest = after;
    }
    ids
}

/// Extracts every `id="..."` attribute value from an HTML source string.
fn extract_html_ids(source: &str) -> std::collections::HashSet<&str> {
    let mut ids = std::collections::HashSet::new();
    let mut rest = source;
    while let Some(start) = rest.find("id=\"") {
        let after = &rest[start + 4..];
        if let Some(end) = after.find('"') {
            ids.insert(&after[..end]);
        }
        rest = after;
    }
    ids
}

#[test]
fn the_dom_id_check_rejects_a_reference_to_a_nonexistent_id() {
    let js = "document.addEventListener('DOMContentLoaded', () => { el('totally-made-up-id'); });";
    let ids = extract_el_ids(js);
    assert_eq!(ids, vec!["totally-made-up-id"]);
    let html = "<div id=\"something-else\"></div>";
    let defined = extract_html_ids(html);
    assert!(!defined.contains("totally-made-up-id"), "the fixture must not accidentally define it");
}

/// Every `fetch(...)` call whose first argument is a string/template literal starting with `/`
/// bypasses `REQUEST_BASE` (see the "Proxy-aware base paths" section of `app.js`) and hardcodes a
/// root-relative URL — exactly the bug that breaks this dashboard when it's mounted behind a
/// reverse proxy under a subpath. `apiCall`'s own `fetch(requestUrl, ...)` call is fine (its
/// argument is a variable, not a literal); this only flags a *literal* absolute path.
fn hardcoded_absolute_fetch_calls(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let mut rest = source;
    let mut consumed = 0usize;
    while let Some(start) = rest.find("fetch(") {
        let after = &rest[start + "fetch(".len()..];
        let trimmed = after.trim_start();
        let quote = trimmed.chars().next();
        if let Some(q) = quote.filter(|c| *c == '\'' || *c == '"' || *c == '`') {
            let arg = &trimmed[1..];
            if arg.starts_with('/') {
                let offset = consumed + start;
                let line = source[..offset].matches('\n').count() + 1;
                let snippet: String = arg.chars().take(30).collect();
                violations.push(format!("{line}: fetch({q}{snippet}..."));
            }
        }
        consumed += start + "fetch(".len();
        rest = after;
    }
    violations
}

#[test]
fn no_hardcoded_absolute_path_bypasses_the_subpath_request_base() {
    let app_js = std::fs::read_to_string(repo_path("static/app.js")).expect("static/app.js must be readable");
    let violations = hardcoded_absolute_fetch_calls(&app_js);
    assert!(
        violations.is_empty(),
        "static/app.js calls fetch() with a hardcoded absolute path, bypassing REQUEST_BASE \
         and breaking reverse-proxy subpath deployments: {violations:?}"
    );
}

/// A check that has never been shown to fail is not evidence of anything: this feeds it a
/// deliberately hardcoded `fetch('/api/...')` call and asserts it is caught.
#[test]
fn the_hardcoded_fetch_check_rejects_a_literal_absolute_path() {
    let js = "async function bad() { return fetch('/api/auth/me'); }";
    let violations = hardcoded_absolute_fetch_calls(js);
    assert_eq!(violations.len(), 1, "must flag the literal absolute fetch() call");

    let ok = "async function good() { return fetch(requestUrl, opts); }";
    assert!(
        hardcoded_absolute_fetch_calls(ok).is_empty(),
        "must not flag a fetch() call whose argument is a variable"
    );
}
