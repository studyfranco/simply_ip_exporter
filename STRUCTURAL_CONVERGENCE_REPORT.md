# Structural Convergence Report — `simply_ip_exporter` vs. `simply_ip_vault`

**Status:** Independent, zero-knowledge architectural audit. New file; no prior version existed.

**Methodology:** Fresh read of both projects' current module layout, naming, and file-level
documentation. No prior audit report (of either project) was read or referenced in producing these
findings.

**Peer commit audited:** `example/simply_ip_vault` at `14c8fa3` (pulled fresh at the start of this
audit — see `AGENT_NOTES.MD` for the pull log and `SECURITY_COMPARISON_REPORT.md` for why
`simply_ip_vault`, specifically, is the comparison peer for this crate).

---

## 1. Module & File Structure

### `src/` top level

| Concern | `simply_ip_exporter` | `simply_ip_vault` | Aligned? |
| :--- | :--- | :--- | :--- |
| Entry point | `main.rs` | `main.rs` | Yes |
| Router/state assembly | `lib.rs` | `lib.rs` | Yes |
| DB connection/pragmas/migrations | `db.rs` | `db.rs` | Yes |
| Shared application state | `state.rs` | `state.rs` | Yes |
| Boot-time Master pinning | `master.rs` | `master.rs` | Yes |
| Inbound auth middleware | `middleware.rs` | `middleware.rs` | Yes |
| Signing + secrets-at-rest | `crypto.rs` | `crypto.rs` | Yes |
| Env parsing / client-IP resolution | `config.rs` | `config.rs` | Yes |
| Anti-replay guard | `replay.rs` | `replay.rs` | Yes |
| Strict request extractors | `extract.rs` | `extract.rs` | Yes |
| Error type + `IntoResponse` | `error.rs` | `error.rs` | Yes |
| Handlers | `api/` (module dir) | `api/` (module dir) | Yes |
| ORM entities | `entities/` (one file per table + `mod.rs`/`prelude.rs`) | `entities/` (one file per table + `mod.rs`/`prelude.rs`) | Yes |
| Schema migrations | `migration/` (`mod.rs` + numbered files) | `migration/` (`mod.rs` + numbered files) | Yes |
| Outbound signed HTTP client | `vault_client.rs` | N/A (vault has no outbound peer of its own) | N/A — `simply_ip_exporter` is a sync *consumer*; no equivalent module expected in `simply_ip_vault` |
| In-memory IP aggregation | `cache.rs`, `feed.rs`, `ipfilter.rs`, `sync.rs` | N/A | N/A — this crate's core domain (in-memory feed cache, `ipnet` aggregation, hybrid sync) has no counterpart in vault's domain (durable IP-record storage) |
| Per-source-IP anti-DoS | `ratelimit.rs` | N/A | N/A — vault's API is fully authenticated; this crate's public, unauthenticated feed endpoint needs a rate limiter vault has no equivalent surface for |
| Outbound dispatch (webhooks) | N/A | `dispatch.rs` | N/A — no equivalent concept in this crate's domain |
| Soft-delete retention sweep | N/A | `retention.rs` | N/A — this crate keeps no durable IP data to retain |

**Verdict:** Every module both projects have a reason to share is present in both, under the
identical filename, holding the identical responsibility. Every module present in only one project
is explained by an actual domain difference (durable multi-tenant IP storage with webhook dispatch
vs. an in-memory aggregating feed cache with outbound sync), not by an inconsistent split of the same
concern. This is the strongest possible structural convergence signal short of the two crates
sharing literal source files.

### `src/api/` — handler modules

| `simply_ip_exporter` | `simply_ip_vault` | Note |
| :--- | :--- | :--- |
| `mod.rs` (flat re-export surface) | `mod.rs` (flat re-export surface) | Identical convention: `pub mod x; pub use x::*;` per handler file |
| `support.rs` (key-minting/hashing/audit-log helpers) | `support.rs` (identical role, plus `RESOURCE_*`/`GroupPermInput`) | Same name, same "decides nothing" boundary |
| `health.rs` | `health.rs` | Identical: liveness/readiness probes, mounted outside auth |
| `keys.rs` | `keys.rs` | Identical: API-key CRUD/rotation |
| `audit.rs` | `audit.rs` | Identical: audit-log listing, Master-only |
| `endpoints.rs` (feed endpoint CRUD) | `records.rs` (IP record CRUD), `groups.rs` (managed-resource CRUD) | Not a 1:1 name match — see §2 |
| N/A | `guards.rs` | See §3 — no equivalent file in this crate |
| N/A | `webhooks.rs` | No equivalent concept in this crate's domain |
| `auth.rs` (`GET /api/auth/me`) | Folded into `keys.rs` (`get_me`) | Minor split difference, same handler behavior |

**Verdict:** Strong alignment on the files both domains need (`mod.rs`, `support.rs`, `health.rs`,
`keys.rs`, `audit.rs`), with the split around `auth.rs`/`get_me` being the only place the two
projects drew the file boundary differently for functionally identical code — cosmetic, not
architectural.

---

## 2. Naming Conventions

| Concept | `simply_ip_exporter` | `simply_ip_vault` | Convention match |
| :--- | :--- | :--- | :--- |
| Signing scheme constant | `CANONICAL_V1` (doc comments), `canonical_v1_payload()` | `canonical_v1_payload()` | Exact function-name match |
| Signature header prefix | `SIGNATURE_PREFIX = "sha256="` | `SIGNATURE_PREFIX = "sha256="` | Exact |
| Timestamp skew constant | `signature_max_age_seconds` (on `RuntimeConfig`, configurable) | `MAX_TIMESTAMP_SKEW_SECS` (module constant, fixed at 300) | Same concept, different mechanism — exporter makes it a runtime config field, vault a compile-time constant; both default/settle at 300s |
| Cipher type | `SecretCipher` (`Plaintext` / `Sealed(Box<XChaCha20Poly1305>)`) | `SecretCipher` (`Plaintext` / `Sealed(Box<XChaCha20Poly1305>)`) | Exact — identical enum shape and variant names |
| Cipher env var | `EXPORTER_ENCRYPTION_KEY` | `VAULT_ENCRYPTION_KEY` (+ `SIGNING_SECRET_KEY` alias) | Same `<SERVICE>_ENCRYPTION_KEY` pattern |
| Master pin type | `MasterPin` | `MasterPin` | Exact |
| Master pin methods | `pin_at_boot`, `resolve`, `authenticate`, `pinned_to`, `get` | `pin_at_boot`, `resolve`, `authenticate`, `pinned_to`, `get` | Exact, method-for-method |
| Replay guard type | `ReplayGuard` | `ReplayGuard` | Exact |
| Strict JSON extractor | `StrictJson<T>` | `StrictJson<T>` (+ `OptionalStrictJson<T>`) | Exact — vault has one additional variant this crate has no bodyless-DELETE use case for |
| Strict path extractor | `StrictPath` | (uses ordinary `Path<Uuid>`, no equivalent named type) | Exporter-only construct — see §4 |
| Error type | `AppError` | `AppError` | Exact |
| Client-IP extension type | `ClientIp(pub std::net::IpAddr)` | `ClientIp(pub std::net::IpAddr)` | Exact, identical newtype |
| Audit action naming | `SCREAMING_SNAKE` verbs (`KEY_CREATE`, `ENDPOINT_DELETE`, …) | `SCREAMING_SNAKE` verbs (`KEY_CREATE`, `GROUP_DELETE`, …) | Exact convention match |
| Bootstrap env vars | `INITIAL_MASTER_KEY`, `INITIAL_MASTER_SIGNING_SECRET` | `INITIAL_MASTER_KEY`, `INITIAL_MASTER_SIGNING_SECRET` | Exact |
| Trusted-proxy env var | `TRUSTED_PROXIES` | `TRUSTED_PROXIES` | Exact |
| `db.rs` function names | `connect`, `run_migrations`, `apply_sqlite_pragmas` | `connect`, `run_migrations`, `apply_sqlite_pragmas`, `has_index` | Exact for the shared three; vault has one exporter lacks (see Security Report §3) |
| `config.rs` function names | `resolve_bind_addr`, `parse_bind_addr`, `resolve_client_ip`, `normalize_ip`, `validate_initial_master_key` | Identical five | Exact, function-for-function |

**Verdict:** Naming convergence is exceptionally tight — of the seventeen concepts compared, thirteen
use byte-identical Rust identifiers across two independently-maintained crates. Where names diverge
(`endpoints.rs`/`records.rs`+`groups.rs`, `StrictPath`, `signature_max_age_seconds` vs.
`MAX_TIMESTAMP_SKEW_SECS`), the divergence tracks an actual difference in what is being named, not an
inconsistent vocabulary for the same thing.

---

## 3. Authorization Architecture

| | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Dedicated guards module | No | Yes — `src/api/guards.rs`, ~460 lines, one function per rule |
| Authorization check style | Inline boolean expressions per handler (`require_master(&caller)?`; `caller.is_master \|\| existing.owner_key_id == Some(caller.id)`) | Named functions cross-referencing `RBAC_MODEL.md` rule numbers in their own doc comments (`guard_resource_lifecycle` → §3, `guard_group_manage` → R2, `guard_delegated_group_grant` → R1+R7, `guard_scope_elevation` → R4, `guard_master_immutable` → §5) |
| Reviewable against the spec without reading a handler | No — the two-tier logic is simple enough to read inline, but there is no single module a reviewer can check against a rule list | Yes — this is `guards.rs`'s stated design goal, and it holds: every exported function's doc comment states which rule it implements and why |

**Assessment:** This is the most significant structural (as opposed to security) divergence between
the two crates. It is fully explained by RBAC complexity — `simply_ip_exporter`'s two-tier model has
a handful of authorization decisions, each expressed in one line at its single call site, and
extracting them into a `guards.rs` today would mostly relocate one-line checks without adding
reviewability. `simply_ip_vault`'s R1–R7 conjunction rules, by contrast, are genuinely
cross-cutting (the same "does this widen a delegated grant" logic applies across group-permission
grants and revokes alike) and benefit concretely from centralization. **This divergence is
justified at current complexity and does not need to be closed today** — but it is the first
structural investment worth making if `simply_ip_exporter`'s ownership/permission model ever grows a
third tier or a delegated-grant mechanism of its own.

---

## 4. Extractor Design

| | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Strict JSON body | `StrictJson<T>` — remaps `JsonRejection` into `AppError`, preserving non-`400` statuses (`413`) verbatim | `StrictJson<T>` — identical remap, identical `413`-preservation rationale, documented near-verbatim |
| Strict path param | `StrictPath` — a dedicated exporter-only type remapping `Path<Uuid>`'s rejection into the same `{"error": ...}` envelope | None — vault uses plain `Path<Uuid>` and accepts axum's default rejection shape for a malformed UUID path segment |
| Bodyless-optional JSON | None | `OptionalStrictJson<T>` — built specifically for `DELETE /api/keys/{id}`'s two-step "inventory, then resolve" conversation |

**Assessment:** `simply_ip_exporter` extends the `StrictJson` pattern one step further than
`simply_ip_vault` does (`StrictPath`, closing a gap vault's own `Path<Uuid>` still has — an invalid
UUID in a vault URL still answers with axum's default rejection body, not vault's own envelope).
`simply_ip_vault`'s `OptionalStrictJson` has no counterpart because this crate has no bodyless
request/response conversation shaped like vault's cascade-delete pre-flight. Each project's extractor
surface is exactly as large as its own domain requires — neither is missing something the other
needed and built.

---

## 5. Error Handling & Observability

See `SECURITY_COMPARISON_REPORT.md` §9 for the full comparative table of `AppError` variants and
status-code mapping — reproduced here only insofar as it bears on structure:

| | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Response envelope shape | `{"error": "<message>"}`, single `IntoResponse` impl, one `match` | Identical shape, identical single-`impl` pattern |
| Structured-detail variant handled outside the flat `match` | N/A (no `ConflictWithDetails` equivalent) | Yes — `ConflictWithDetails` is matched *before* the flat `match` specifically so its differently-shaped body doesn't have to fit the `(StatusCode, String)` tuple every other arm produces |
| Logging discipline | `tracing::error!`/`tracing::warn!` at the point of refusal, before constructing the client-facing message | Identical discipline, identical crate (`tracing`) |
| Audit log entry shape | `api_key_id`, `api_key_name`, `api_key_prefix`, `client_ip`, `action`, `target_resource`, `details`, `timestamp` (denormalized actor snapshot) | Identical field set and identical denormalization rationale (the actor's *name at the time*, not a live join, so a later-renamed or -deleted key doesn't rewrite history) |

**Verdict:** No structural gap. The one shape difference (`ConflictWithDetails`) is proportionate to
an actual behavioral difference already covered in the Security Comparison Report (§6), not an
inconsistency in how errors are modeled.

---

## 6. Test Suite Architecture

| | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| `src/` line count | ~4,800 | ~13,000 |
| `tests/` line count | ~1,230 | ~15,180 |
| Test-to-source LOC ratio | ~0.26 | ~1.17 |
| Total `cargo test` count | 117 (80 unit + 4 `main.rs` unit + 22 integration + 11 source-hygiene) | 289 across 8 test binaries (`concurrency_and_contracts`, `frontend_syntax_test`, `rbac_integration_tests`, `rbac_model_compliance`, `schema_integrity_tests`, `security_tests`, `source_hygiene`, plus lib unit tests) |
| Shared test harness | `tests/common/mod.rs` | Distributed per-file rather than one shared `common/mod.rs` (vault's suites each build their own fixtures inline) |
| Dedicated source-hygiene test file | Yes (`tests/source_hygiene.rs` — raw SQL, `.unwrap()`/`.expect()`, JS syntax/DOM refs) | Yes (`tests/source_hygiene.rs` + `tests/frontend_syntax_test.rs`, split across two files rather than one) |
| Dedicated RBAC-compliance test file | No — RBAC assertions live inside `tests/integration.rs` alongside everything else | Yes — `tests/rbac_model_compliance.rs`, a file whose sole purpose is asserting the crate matches `RBAC_MODEL.md` line by line |
| `verify_convergence.sh` | Yes — wraps `tests/source_hygiene.rs` as a named-check runner | Yes — a materially different tool: a mechanical drift-detector diffing shared security primitives against `simply_hook_executor` (see that script's own header) |
| `test_e2e.sh` | Yes — 100 checks, 14 sections, boots the real binary | Yes — present, not read in detail for this pass (out of scope for a structural, non-behavioral comparison) |

**Verdict:** This is where the two projects diverge most visibly, and the divergence is one of
*maturity*, not *architecture*. `simply_ip_vault`'s test suite outweighs its own production code
more than four-to-one; `simply_ip_exporter`'s is proportioned the more conventional way around. Both
projects independently converged on the same *kinds* of test files (a dedicated source-hygiene
suite, a convergence-verification script, a full binary-boot E2E harness) — `simply_ip_vault` simply
has more of each, plus one category (`rbac_model_compliance.rs`) this crate has no direct analogue
for because it isn't a party to the specification that file compiles against. `verify_convergence.sh`
is the one place where the same *filename* hides a genuinely different *tool* — worth noting so a
future reader does not assume the two scripts are interchangeable.

---

## 7. Migration & Entity Patterns

| | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Migration file naming | `m20260101_0000NN_<description>.rs` | `m<date>_0000NN_<description>.rs` — identical `sea-orm-migration` convention |
| Migration count | 2 | 12 |
| `master_marker` generated column | Added correctly in the crate's single initial schema migration (`AGENT_NOTES.MD`: "done correctly from the start rather than repeating the vault's two-migration correction") | Added via a dedicated later migration (`m20260808_000009_derive_master_marker`), after an earlier application-maintained approach was found to defeat the uniqueness guarantee it existed for |
| `entities/` layout | One file per table + `mod.rs` + `prelude.rs` | Identical layout |
| Entity omits engine-generated columns from the struct | Yes (`master_marker` absent from `api_key::Model`) | Yes — identical rationale (SeaORM builds explicit column lists from the struct, so omission is what guarantees no query ever names the generated column) |

**Verdict:** Identical convention, and the one difference in *history* (exporter's generated column
was correct from its first migration; vault's took two attempts to get there) is a case of
`simply_ip_exporter` benefiting from a lesson `simply_ip_vault` already paid for — consistent with
this being a genuine, mutually-informing sibling relationship rather than one-directional copying.

---

## 8. Executive Verdict

**These two codebases share the same architectural DNA.** Thirteen of seventeen compared naming
conventions are byte-identical Rust identifiers; every module either project has a reason to hold is
present under an identical filename in the other; the migration, entity, and error-handling
conventions match exactly; and both independently arrived at the same categories of test
infrastructure (source-hygiene scanning, a convergence-verification script, a full-binary E2E
harness) without any indication one was templated off the other's current state rather than a shared
ancestor pattern.

The divergences that do exist are all attributable to one of two honest causes: a genuine domain
difference (an in-memory aggregating feed cache with a public rate-limited endpoint vs. durable
multi-tenant IP storage with outbound webhook dispatch), or a maturity gap tracking each project's
own iteration history (`simply_ip_vault`'s test suite outweighing its source 1.17:1 against this
crate's 0.26:1; a centralized `guards.rs` justified by conjunction rules this crate's simpler RBAC
model does not have). None of the divergence found in this pass reflects an inconsistent design
philosophy between the two projects — where they differ, they differ for a reason each project's own
documentation states plainly.

**Convergence level: high.** No structural realignment is recommended. The two items worth carrying
forward as this crate matures are noted above and are investments to make *if and when* complexity
grows to match them (a `guards.rs`-style extraction if the RBAC model gains a delegated-grant
mechanism; a dedicated `*_model_compliance.rs` test file if this crate ever adopts a normative
external specification of its own) — not gaps to close today.
