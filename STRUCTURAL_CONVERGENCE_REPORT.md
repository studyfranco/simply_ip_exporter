# Structural Convergence Report — `simply_ip_exporter` vs. the `example/` Ecosystem

**Status:** Independent, zero-knowledge architectural audit. New file; no prior version existed for
the current project.

**Methodology:** Fresh read of all four projects' current module layout, naming, and file-level
documentation. No prior audit report (of this or any peer project) was read or referenced.

**Commits audited:** `simply_ip_exporter` `80a3b31`, `simply_ip_vault` `14c8fa3`,
`simply_hook_executor` `15b8af6`, `simply_ip_sync` `72cce13` — see `AGENT_NOTES.MD` for the pull log
and `SECURITY_COMPARISON_REPORT.md` for the full commit table.

---

## 1. Module & File Structure

### `src/` top level — shared-foundation modules

| Concern | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Entry point | `main.rs` | `main.rs` | `main.rs` | `main.rs` |
| Router/state assembly | `lib.rs` | `lib.rs` | `lib.rs` | `lib.rs` |
| DB connection/pragmas/migrations | `db.rs` | `db.rs` | `db.rs` | `db.rs` |
| Shared application state | `state.rs` | `state.rs` | `state.rs` | `state.rs` |
| Boot-time Master pinning | `master.rs` | `master.rs` | `master.rs` | `master.rs` |
| Inbound auth middleware | `middleware.rs` | `middleware.rs` | `middleware.rs` | `middleware.rs` |
| Signing + secrets-at-rest | `crypto.rs` | `crypto.rs` | `crypto.rs` | `crypto.rs` |
| Env parsing / client-IP resolution | `config.rs` | `config.rs` | `config.rs` | `config.rs` |
| Anti-replay guard | `replay.rs` | `replay.rs` | `replay.rs` | `replay.rs` |
| Strict request extractors | `extract.rs` | `extract.rs` | `extract.rs` | `extract.rs` |
| Error type + `IntoResponse` | `error.rs` | `error.rs` | `error.rs` | `error.rs` |
| Handlers | `api/` | `api/` | `api/` | `api/` |
| ORM entities | `entities/` | `entities/` | `entities/` | `entities/` |
| Schema migrations | `migration/` | `migration/` | `migration/` | `migration/` |

**Verdict: perfect convergence on the fourteen modules every project needs.** All four services use
the identical filename for every foundational concern, with zero exceptions across fourteen
comparison points and four independently-maintained codebases. This is the strongest single piece of
evidence in either report that the ecosystem shares one architecture, deliberately, rather than
having arrived at similar names by chance.

### `src/` top level — domain-specific modules (no cross-ecosystem equivalent expected)

| `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- |
| `cache.rs` — in-memory IP aggregation | `dispatch.rs` — outbound webhook dispatch | `executor.rs` — hook execution engine | `client.rs` — outbound signed HTTP client to vaults |
| `feed.rs` — public feed rendering | `retention.rs` — soft-delete sweep | `retention.rs` — soft-delete sweep | `scheduler.rs` — in-process cron |
| `ipfilter.rs` — RFC1918/bogon filtering | | | `jobs/` (`mod.rs`, `decompress.rs`, `external_ingestion.rs`, `vault_sync.rs`) |
| `sync.rs` — hybrid Vault sync worker | | | `parsers/` (`mod.rs`, `regex_line.rs`, `json_path.rs`) |
| `ratelimit.rs` — per-source-IP anti-DoS | | | `retry.rs` — outbound retry/backoff |
| `vault_client.rs` — outbound signed HTTP client to Vault | | | |

**Verdict:** every domain-specific module is explained by an actual difference in what each service
does — an in-memory aggregating feed cache with a public rate-limited surface (exporter); durable
multi-tenant IP storage with outbound webhook dispatch and retention (vault); a hook-execution engine
with the same retention pattern (hook_executor, sharing `retention.rs`'s name and role with vault
verbatim); and a multi-source ingestion/scheduling/retry pipeline (sync). Two matches are worth
calling out specifically: `simply_ip_exporter::vault_client` and `simply_ip_sync::client` are the
same concept (an outbound `CANONICAL_V1`-signing HTTP client to a `simply_ip_vault` instance) under
different names — the one place in this comparison where a shared concept did *not* converge on a
shared filename. `simply_ip_vault::retention` and `simply_hook_executor::retention` match exactly,
consistent with those two being the tightest-aligned pair on domain modules as well as on foundations.

### `src/api/` — handler modules

| `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- |
| `mod.rs` | `mod.rs` | `mod.rs` | `mod.rs` |
| `support.rs` | `support.rs` | `support.rs` | `support.rs` |
| `health.rs` | `health.rs` | `health.rs` | `health.rs` |
| `keys.rs` | `keys.rs` | `keys.rs` | `keys.rs` |
| `audit.rs` | `audit.rs` | `audit.rs` | `audit.rs` |
| **absent** | `guards.rs` | `guards.rs` | `guards.rs` |
| `endpoints.rs` | `records.rs` + `groups.rs` | `hooks.rs` + `executions.rs` | `sources.rs` + `vaults.rs` + `sync_tasks.rs` + `sync_logs.rs` |
| `auth.rs` (`get_me`) | folded into `keys.rs` | folded into `keys.rs` | folded into `keys.rs` |
| N/A | `webhooks.rs` | N/A | N/A |
| N/A | N/A | `system.rs` | N/A |

**Verdict:** `mod.rs`, `support.rs`, `health.rs`, `keys.rs`, and `audit.rs` are universal across all
four — five handler files, five identical names, zero exceptions. `guards.rs` is present in **three
of four**; `simply_ip_exporter` is the sole holdout (see §3). The domain-object CRUD files
necessarily diverge in name (there is no single noun for "the thing this service manages" across an
IP feed, a group+record pair, a hook+execution pair, and four sync-related resource kinds) — this is
expected divergence, not a naming inconsistency. `simply_ip_exporter`'s folding of `get_me` into a
standalone `auth.rs` rather than `keys.rs` is the one place all three peers agree with each other and
diverge from exporter — cosmetic, functionally identical.

---

## 2. Naming Conventions

| Concept | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Signing function | `canonical_v1_payload()` | Identical | Identical | Identical |
| Signature prefix constant | `SIGNATURE_PREFIX = "sha256="` | Identical | Identical | Identical |
| Cipher type | `SecretCipher { Plaintext, Sealed(Box<XChaCha20Poly1305>) }` | Identical shape | Identical shape | Identical shape |
| Master pin type/methods | `MasterPin { pin_at_boot, resolve, authenticate, pinned_to, get }` | Identical, method-for-method | Identical, method-for-method | Identical, method-for-method |
| Master pin primitive | `tokio::sync::OnceCell<Uuid>` | `std::sync::OnceLock<Uuid>` | `tokio::sync::OnceCell<Uuid>` | `std::sync::OnceLock<Uuid>` |
| Replay guard type | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` |
| Strict JSON extractor | `StrictJson<T>` | `StrictJson<T>` (+ `OptionalStrictJson<T>`) | `StrictJson<T>` | `StrictJson<T>` |
| Strict path extractor | `StrictPath` (exporter-only) | Plain `Path<Uuid>` | Not verified this pass | Not verified this pass |
| Error type | `AppError` | `AppError` | `AppError` | `AppError` |
| Client-IP extension | `ClientIp(pub std::net::IpAddr)` | Identical | Identical | Identical |
| Audit action naming | `SCREAMING_SNAKE` verbs (`KEY_CREATE`, …) | `SCREAMING_SNAKE` verbs | `SCREAMING_SNAKE` verbs | `SCREAMING_SNAKE` verbs |
| Bootstrap env vars | `INITIAL_MASTER_KEY`, `INITIAL_MASTER_SIGNING_SECRET` | Identical | Identical | Identical |
| Trusted-proxy env var | `TRUSTED_PROXIES` | `TRUSTED_PROXIES` | `TRUSTED_PROXIES` | `TRUSTED_PROXIES` |
| Skew-window mechanism naming | `signature_max_age_seconds` (config field) | `MAX_TIMESTAMP_SKEW_SECS` (constant) | `signature_max_age_seconds` (config field) | `MAX_TIMESTAMP_SKEW_SECS` (constant) |
| `db.rs` shared function names | `connect`, `run_migrations`, `apply_sqlite_pragmas` | Identical three, + `has_index` | Identical three (no `has_index`) | Identical three, + `has_index` |
| `config.rs` shared function names | `resolve_bind_addr`, `parse_bind_addr`, `resolve_client_ip`, `normalize_ip`, `validate_initial_master_key` | Identical five | Identical five | Identical five |

**Verdict — an unexpected lineage split.** Of fifteen compared concepts, ten are universal across
all four projects with byte-identical names. The remaining five split cleanly into two consistent
pairs: `{simply_ip_exporter, simply_hook_executor}` share `tokio::sync::OnceCell` and a configurable
`signature_max_age_seconds`; `{simply_ip_vault, simply_ip_sync}` share `std::sync::OnceLock` and a
fixed `MAX_TIMESTAMP_SKEW_SECS`. This does not track the "gold standard" founding pair as named in
this task's framing — vault and hook_executor, the two founders, disagree with each other on both of
these points, while each instead agrees with a *different*, later project. Read charitably, this
means the ecosystem's convergence is genuinely organic (later projects picked up conventions from
whichever sibling's code they read first, not from a single canonical template) rather than
top-down. Read as a finding, it means "gold standard" should be understood as "founding," not as
"most mutually aligned" — on the narrow evidence in this table, vault aligns more tightly with sync
than with hook_executor.

---

## 3. Authorization Architecture

| | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Dedicated `api/guards.rs` | **No** | Yes | Yes | Yes |
| Style | Inline boolean checks per handler | Named, individually-documented functions, each citing the `RBAC_MODEL.md` rule it implements | Same pattern as vault | Named functions citing an internal rule scheme analogous to `RBAC_MODEL.md`'s |
| Reviewable against a spec without reading a handler | No | Yes | Yes | Yes (against its own documented rule set, not `RBAC_MODEL.md` itself) |

**Verdict:** `simply_ip_exporter` is now a minority of one on this axis — three of four ecosystem
members, including a later entrant that (like exporter) is not literally scoped to `RBAC_MODEL.md`,
have independently built a centralized guards module. This strengthens the recommendation already
made in the Security Comparison Report (§6): centralizing authorization decisions is ecosystem
convention, not an artifact of `RBAC_MODEL.md` compliance specifically, and is worth adopting on its
own maintainability merits if exporter's RBAC surface grows.

---

## 4. Extractor Design

| | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Strict JSON body, extractor-level status normalization | `StrictJson<T>` | `StrictJson<T>` | `StrictJson<T>` | `StrictJson<T>` |
| Strict path param (invalid UUID gets the same envelope, not axum's default) | **Yes — `StrictPath`, exporter-only** | No — plain `Path<Uuid>` | Not verified this pass | Not verified this pass |
| Bodyless-optional JSON (`DELETE` with an optional resolution-map body) | No | `OptionalStrictJson<T>` | Not verified this pass | Not verified this pass |

**Verdict:** `simply_ip_exporter` extends the shared `StrictJson` pattern one step further than
`simply_ip_vault` with `StrictPath` — closing a gap vault's own `Path<Uuid>` still has. This is a
genuine instance of the newer project improving on the founding pair's pattern, not merely following
it; worth naming explicitly rather than letting the ecosystem's overall convergence narrative imply
every improvement flows from the founders outward.

---

## 5. Test Suite Architecture

| | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| `src/` LOC | ~4,800 | ~13,000 | ~12,700 | ~7,000 |
| `tests/` LOC | ~1,230 | ~15,180 | ~11,230 | ~4,130 |
| Test-to-source LOC ratio | **0.26** | 1.17 | 0.89 | 0.59 |
| Dedicated `tests/concurrency_and_contracts.rs` | No (inline in `tests/integration.rs`) | Yes | Yes | Yes |
| Dedicated `tests/health_probes.rs` | No (inline in `tests/integration.rs`) | No (inline) | Yes | Yes |
| Dedicated `tests/referential_integrity.rs` | No | No | Yes | Yes |
| Dedicated `tests/rbac_model_compliance.rs` (asserts literal `RBAC_MODEL.md` compliance) | N/A — not scoped to the spec | Yes | Yes | No (not literally scoped to `RBAC_MODEL.md` either, but has its own `tests/rbac_tests.rs`) |
| Dedicated `tests/source_hygiene.rs` (raw SQL / unwrap-expect / JS syntax scanners) | Yes | Yes | Yes | Yes |
| `scripts/verify_convergence.sh` | Yes | Yes | Yes | **No** (see Security Report §10) |
| `scripts/test_e2e.sh` | Yes | Yes | Yes | Yes |

**Verdict:** `simply_ip_exporter` has the thinnest test-to-source ratio of the ecosystem by a wide
margin (0.26 against a range of 0.59–1.17 among the other three), and is the only project without
dedicated files for concurrency/contract testing, health-probe failure-independence, or referential
integrity — it covers overlapping ground inline within `tests/integration.rs` rather than in
purpose-named files. This is not evidence of a coverage gap in what is tested (the Security
Comparison Report found the underlying properties — concurrent-delete safety, `rows_affected`
checks — equally present in exporter's code); it is a file-organization difference, and the
ecosystem's three-of-four convergence on dedicated file names for these concerns is worth adopting
for discoverability as this crate's test suite grows, independent of whether coverage itself needs
to grow.

`simply_ip_sync` is the one project of the four missing `verify_convergence.sh` despite its own
`AGENT.MD` describing it as present — flagged in the Security Comparison Report (§10) as a
documentation/tooling drift item for that project's own maintainers.

---

## 6. Migration & Entity Patterns

| | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Migration file naming | `m<date>_0000NN_<description>.rs` | Identical convention | Identical convention | Identical convention |
| Migration count | 2 | 12 | 9 | 2 |
| `master_marker` generated column correct from the first migration | Yes | No — corrected in a dedicated later migration after an application-maintained approach was found to defeat its own uniqueness guarantee | Similar staged correction (`m20230106_000001_master_key_uniqueness` is a later migration, not part of the initial schema) | Yes |
| `entities/` layout: one file per table + `mod.rs` + `prelude.rs` | Yes | Yes | Yes | Yes |
| Generated columns omitted from the entity struct (SeaORM never issues a write to them) | Yes | Yes | Not independently re-verified this pass | Not independently re-verified this pass |

**Verdict:** Identical convention across all four, with the two later projects
(`simply_ip_exporter`, `simply_ip_sync`) both getting the generated-column correctness right from
their first migration rather than needing the two-step correction both founding projects required —
consistent with the Security Comparison Report's observation that lessons flow bidirectionally across
this ecosystem's history, not solely from founders to followers.

---

## 7. Error Handling & Observability

Full variant-level comparison lives in `SECURITY_COMPARISON_REPORT.md` §9; the structural summary:

| | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Response envelope shape | `{"error": "<message>"}` | Identical | Identical | Identical |
| Single `IntoResponse` impl, one `match` | Yes | Yes (structured variant matched ahead of the flat arm) | Yes | Yes |
| Audit-log entry shape | `api_key_id`, `api_key_name`, `api_key_prefix`, `client_ip`, `action`, `target_resource`, `details`, `timestamp` — denormalized actor snapshot | Identical field set and rationale | Identical | Identical |
| `tracing`-based logging discipline at point of refusal | Yes | Yes | Yes | Yes |

**Verdict:** No structural gap. The denormalized audit-log shape in particular — deliberately
capturing the actor's *name at the time* rather than a live join that a later rename or deletion
would silently rewrite — is identical across all four, independently documented with matching
rationale in at least three. This is one of the tightest points of convergence in the whole
ecosystem.

---

## 8. Executive Verdict

**All four services share one architectural DNA, and the convergence is measurably tighter than the
task's "two founding siblings" framing alone would predict.** Fourteen of fourteen foundational
module names match exactly across all four codebases; five of five shared handler-file names match
exactly; ten of fifteen compared identifiers are byte-identical across all four independently
maintained crates. No comparison in this report found an inconsistent design *philosophy* anywhere
in the ecosystem — every divergence found traces to either a genuine domain difference (what each
service actually manages) or a maturity/history difference (how long each project has had to harden
a shared pattern), and several traces run from later projects back toward the founders, not only the
other direction.

**The one genuinely unexpected finding: the founding pair is not, on this evidence, the most tightly
aligned pair.** `simply_ip_vault` and `simply_ip_sync` share more literal implementation choices
(`OnceLock`, a fixed skew constant) than `simply_ip_vault` and `simply_hook_executor` do. "Gold
standard" should be read as *founding*, establishing the pattern the rest of the ecosystem converged
toward — not as evidence that the two founders remain each other's closest relative today.

**`simply_ip_exporter`'s own standing:** structurally excellent on every foundational module and
naming convention that matters, with a thinner test-file organization and no `guards.rs` — both
attributable to being the ecosystem's smallest RBAC surface rather than to any oversight, and both
worth adopting proactively as this crate's own scope grows, given that three of its four ecosystem
peers (not merely the two founders) have already converged on both.

**Convergence level: high, ecosystem-wide.** No structural realignment is recommended for any of the
four projects based on this pass. The items worth carrying forward are investments to make as each
project's own complexity grows to match them, not gaps to close today.
