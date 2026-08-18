# Security Comparison Report — `simply_ip_exporter` vs. the `example/` Ecosystem

**Status:** Independent, zero-knowledge security audit. Supersedes and replaces any prior version of
this file in its entirety.

**Methodology:** Fresh read of all four projects' current `.rs` source under `src/`/`tests/`,
evaluated against `RBAC_MODEL.md` and each project's own `AGENT.MD`. No prior audit report (of this
or any peer project) was read or referenced in producing these findings.

**Commits audited** (all pulled fresh at the start of this pass — see `AGENT_NOTES.MD` for the full
pull log):

| Project | Commit | Pull outcome |
| :--- | :--- | :--- |
| `simply_ip_exporter` (current project) | `80a3b31` | — |
| `simply_ip_vault` | `14c8fa3` | Already up to date |
| `simply_hook_executor` | `15b8af6` | Updated (`968` insertions, `531` deletions across 12 files) |
| `simply_ip_sync` | `72cce13` | Updated (`2330` insertions across 22 files) |

**Why `RBAC_MODEL.md` does not gate every project equally.** Its own header scopes it to
`simply_ip_vault`/`simply_hook_executor` specifically — the two "gold standard" founding siblings
named in this task's own framing. `simply_ip_exporter` and `simply_ip_sync` are later ecosystem
members that each implement a *documented, deliberate subset or extension* of that model rather than
the model itself (exporter: two-tier Master/Daughter, no M:N groups; sync: a four-tier
Master/Parent/Daughter-with-scopes model closer to vault's shape but governing sync/ingestion
resources RBAC_MODEL.md never names). This report evaluates all four against the security
*properties* RBAC_MODEL.md exists to guarantee (uniqueness, non-escalation, fail-closed defaults),
not against its literal section numbers where a project was never scoped to them.

---

## 1. Executive Summary

All four services share one security foundation, and it shows: the `CANONICAL_V1` HMAC-SHA256
signing scheme, the XChaCha20-Poly1305 secrets-at-rest envelope, the `OnceLock`/`OnceCell`-pinned
Master identity, and the monotonic-clock anti-replay guard are behaviorally identical — often
down to identical design rationale, independently documented — across all four codebases. Two
consistent, non-obvious lineage clusters emerged from this pass: `{simply_ip_vault, simply_ip_sync}`
share `std::sync::OnceLock` and a fixed `MAX_TIMESTAMP_SKEW_SECS` constant, while
`{simply_ip_exporter, simply_hook_executor}` independently share `tokio::sync::OnceCell` and a
runtime-configurable `signature_max_age_seconds`. Neither cluster is more correct than the other;
both are noted because a "gold standard" pairing (vault + hook_executor) does not, on this evidence,
imply the tightest *implementation* pairing — it is vault + sync that share the more literal
convention here.

| | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| `#[serde(deny_unknown_fields)]` occurrences | **0** | 8 | 11 | 10 |
| `master.rs` uniqueness-index check | `SchemaManager::has_index` (bug) | Custom `db::has_index` (fixed) | `SchemaManager::has_index` (bug) | Custom `db::has_index` (fixed) |
| Wrong-encryption-key startup canary | **Yes** | **No** | **No** | Yes |
| `is_master` absent from mutating payload types | Yes | Yes | Yes | Yes |
| Concurrent-delete `rows_affected` checks present | Yes (2) | Yes (5) | Yes (4) | Yes (5) |
| Centralized `api/guards.rs` | **No** | Yes | Yes | Yes |
| `scripts/verify_convergence.sh` present | Yes | Yes | Yes | **No** |
| Master pin primitive | `tokio::sync::OnceCell` | `std::sync::OnceLock` | `tokio::sync::OnceCell` | `std::sync::OnceLock` |

**The single most significant finding of this pass:** the `SchemaManager::has_index` /
PostgreSQL-`BackendNotSupported` defect that `simply_ip_vault` discovered and fixed in its own
history (documented at length in its `master.rs`) is present, *right now*, in **`simply_hook_executor`
— vault's own gold-standard sibling** — whose `AGENT.MD` explicitly mandates "SQL-agnostic
(PostgreSQL-ready)" as a hard tech-stack requirement, making this a live, currently-applicable defect
there rather than a portability curiosity. `simply_ip_exporter` carries the identical bug under a
weaker (SQLite-only) deployment claim. `simply_ip_sync` already ported vault's fix.

---

## 2. Authentication & Request Signing (`CANONICAL_V1`)

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Signed string | `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY` | Identical | Identical | Identical |
| `TARGET` includes query string (via `OriginalUri`, correct under `.nest("/api", ...)`) | Yes | Yes | Yes | Yes |
| `sha256=` prefix mandatory on `X-Signature-256` | Yes | Yes | Yes | Yes |
| Comparison | `Mac::verify_slice` (constant-time) | Same | Same | Same |
| Skew window mechanism | `RuntimeConfig::signature_max_age_seconds` (configurable, defaults to 300) | `MAX_TIMESTAMP_SKEW_SECS = 300` (fixed constant) | `RuntimeConfig::signature_max_age_seconds` (configurable, defaults to 300) | `MAX_TIMESTAMP_SKEW_SECS = 300` (fixed constant) |
| Signing required unconditionally on every `/api/*` request | Yes | Yes | **No — per-key configurable**, bearer-only unless `REQUIRE_SIGNED_REQUESTS` is set (documented, intentional; vault's own `middleware.rs` explicitly contrasts itself against this) | Yes |
| Ordering: timestamp → key lookup → signature → replay → `bound_ips` | Yes | Yes | Not independently re-verified this pass (out of scope for a non-exhaustive pass; flagged as a follow-up) | Yes |

**Finding — informational, not a gap.** `simply_hook_executor`'s optional-signing posture is a
long-standing, explicitly documented divergence from vault (both projects' own source states this),
not an oversight this pass uncovered. It is included here because a reader assuming "gold standard
pair" means "identical enforcement" would be wrong, and the asymmetry is deliberate: hook_executor
serves lower-trust internal callers (shell-script webhook receivers) where vault does not.

---

## 3. Master Identity, Uniqueness, and Startup Integrity

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Identity pinned once, held behind `Arc` on `AppState` | Yes | Yes | Yes | Yes |
| Primitive | `tokio::sync::OnceCell<Uuid>` | `std::sync::OnceLock<Uuid>` | `tokio::sync::OnceCell<Uuid>` | `std::sync::OnceLock<Uuid>` |
| Impostor `is_master=true` demoted (not rejected) at a single choke point | Yes | Yes | Yes (same `authenticate()` pattern) | Yes |
| Uniqueness backed by a database-generated column + unique index | Yes (`master_marker`) | Yes | Yes | Yes |
| Index existence re-verified at every boot | Yes | Yes | Yes | Yes |
| **Index-check implementation** | `SchemaManager::has_index` | Custom `db::has_index` | `SchemaManager::has_index` | Custom `db::has_index` |
| Own `AGENT.MD` requires PostgreSQL readiness | No (SQLite stated "exclusively") | Yes (origin of the fix) | **Yes ("SQL-agnostic... PostgreSQL-ready")** | Yes |

**Finding — HIGH within the `simply_hook_executor` codebase specifically; MEDIUM for
`simply_ip_exporter`.** Both `simply_ip_exporter` and `simply_hook_executor` call
`sea_orm_migration::SchemaManager::has_index` in `master.rs::pin_at_boot`. `simply_ip_vault`'s own
source documents, in detail, why this is wrong: the method's catalog query is gated behind cargo
features vault does not enable for PostgreSQL, so it answers `BackendNotSupported` there —
*"the service could not start on Postgres at all... against a database whose index was present and
correct."* `simply_hook_executor`'s `AGENT.MD` makes an unqualified "PostgreSQL-ready" promise this
defect directly breaks: a hook_executor instance pointed at a correctly-migrated PostgreSQL database
would refuse to start, misreporting a missing constraint that is actually present. This is not
hypothetical or forward-looking for hook_executor the way it is for exporter — it is a defect in a
stated, current capability.

`simply_ip_exporter`'s exposure is lower (its own `AGENT.MD` claims SQLite "exclusively"), but the
same latent trap exists if that ever changes. `simply_ip_sync` has already independently ported
vault's `db::has_index` fix.

**Recommendation:** Port `simply_ip_vault`'s `db::has_index` into both `simply_ip_exporter` and
`simply_hook_executor`. For hook_executor this should be treated as a correctness bug against an
explicit, currently-claimed capability, not a nice-to-have.

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Wrong (syntactically valid) encryption key caught before serving traffic | **Yes** | **No** | **No** | **Yes** |

**Finding — MEDIUM, on `simply_ip_vault` and `simply_hook_executor`.** Both projects' bootstrap
functions only ever touch the cipher when the `api_keys` table is empty; on every subsequent boot
they return immediately without decrypting anything. A mismatched key (operator typo, wrong secret
restored from a vault) starts up looking healthy on both and then fails every authenticated request
with an opaque `401`, with nothing in the startup log naming the actual cause. This is the one
property in this report where the two later ecosystem members (`simply_ip_exporter`,
`simply_ip_sync`) are ahead of both founding siblings — each independently added a boot-time canary
decrypt of an already-sealed secret and refuses to start on mismatch with an explicit log line.
**Recommendation:** port the canary pattern into `simply_ip_vault::main.rs` and
`simply_hook_executor::main.rs`, immediately after their respective `bootstrap_master_key` calls.

---

## 4. Secrets at Rest (`SecretCipher`)

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Algorithm | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 |
| Envelope shapes | `v1.plain.`, `v1.xchacha20poly1305.` | Identical two | Identical two | Identical two |
| Unrecognized/unprefixed stored value | Fails closed | Fails closed (additionally retired a legacy `aesgcm256:` format and an unprefixed-verbatim fallback, both documented and tested) | Fails closed | Fails closed |
| Malformed key format | Hard startup error, no silent plaintext downgrade | Same | Same | Same |
| Cross-service env-var alias for provisioning | N/A (no sibling shares this crate's provisioning) | `VAULT_ENCRYPTION_KEY` / `SIGNING_SECRET_KEY` alias, for hook_executor interop | Presumably the mirror of vault's alias (not independently re-verified this pass) | N/A |
| `Debug` impl redacts key material | Yes | Yes | Yes | Yes |
| Fresh random nonce per seal | Yes | Yes | Yes | Yes |

**Finding:** No parity gap in the primitive itself across the ecosystem. `simply_ip_vault` carries
materially deeper defensive test coverage of malformed/legacy stored-value shapes than the other
three (see §7); this is a test-depth gap, not a behavioral one.

---

## 5. Anti-Replay Guard

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Keyed on `(key_id, raw digest bytes)` | Yes | Yes | Yes | Yes |
| Expiry clock | Monotonic `tokio::time::Instant` | Monotonic `tokio::time::Instant` | Monotonic `tokio::time::Instant` | Monotonic `tokio::time::Instant` |
| Recorded only after signature verification succeeds | Yes | Yes | Yes | Yes |
| Window | 300s | 300s | 300s | 300s |

**Finding:** No parity gap. All four replay guards are behaviorally identical, with the caller-clock
DoS/pre-emption rationale independently documented in at least three of the four.

---

## 6. Authorization Architecture

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Tier model | Two: Master, Daughter | Three + M:N groups: Master, Parent, Daughter, per-resource grants | Three + M:N: Master, Parent, Daughter, per-resource grants | Four scopes + M:N: Master, `can_manage_keys`, `can_manage_sources`, `can_manage_vaults`, per-resource `can_sync`/`can_manage`/`can_view_logs` |
| Centralized `api/guards.rs` | **No** — inline `require_master(&caller)?` / ownership checks | Yes | Yes | Yes |
| `is_master` unreachable via any API payload | Yes (absent from the type) | Yes (absent + `deny_unknown_fields`) | Yes (absent + `deny_unknown_fields`) | Yes (absent + `deny_unknown_fields`) |
| Master immutable via API except its own `bound_ips` | Yes (no rotate route exists at all) | Yes (`guard_master_immutable`, explicit) | Yes (equivalent guard) | Yes (`guard_master_immutable`, per `RBAC_MODEL.md`-adjacent naming) |
| Owned-resource handling on key deletion | `SET NULL` (endpoint silently orphaned to Master-only visibility) | Blocking `409` pre-flight inventory (`ConflictWithDetails`) | Blocking `409` pre-flight inventory | Blocking `409` pre-flight inventory |

**Finding — structural, not a vulnerability, but exporter is now the outlier of the ecosystem on
two counts.** `simply_ip_exporter` is the only one of the four services with no dedicated
`api/guards.rs`, and the only one that resolves owned-resource deletion by silent `SET NULL` rather
than a blocking, structured inventory. Both are explained by the same root cause: exporter's RBAC
surface is genuinely the smallest of the four (no M:N grants to reason about), so neither pattern
was ever strictly necessary. But three of four ecosystem members — including both later entrants,
not just the two "gold standard" founders — have independently converged on centralized guards and
blocking-conflict deletion. That is a majority-convergence signal worth treating as a soft
recommendation rather than a hard requirement: if exporter's ownership model gains a second
dimension (a Parent tier, or resource-level grants), building `guards.rs` and
`ConflictWithDetails` from the start would match the rest of the ecosystem rather than diverge
further from it.

---

## 7. Payload & Input Strictness

| Project | `#[serde(deny_unknown_fields)]` occurrences | Files carrying it |
| :--- | :--- | :--- |
| `simply_ip_exporter` | **0** | none |
| `simply_ip_vault` | 8 | `api/support.rs`, `api/keys.rs`, `api/records.rs`, `extract.rs` |
| `simply_hook_executor` | 11 | (highest in the ecosystem) |
| `simply_ip_sync` | 10 | |

**Finding — MEDIUM, confirmed, `simply_ip_exporter`-only.** `simply_ip_exporter` remains the sole
ecosystem member with zero `deny_unknown_fields` usage across its six mutating payload structs
(`CreateKeyPayload`, `UpdateKeyPayload`, `CreateEndpointPayload`, `UpdateEndpointPayload`,
`ReassignOwnerPayload`). The primary control — `is_master` absent from the payload type — holds
here, matching all three peers, so this is **not** a privilege-escalation path. It is the
second-order property `simply_ip_vault`'s own `extract.rs` module doc comment names explicitly
(quoting `RBAC_MODEL.md` §5): a struct without the field still silently *accepts and drops* a stray
`is_master` field today, rather than refusing the request and logging why. With three of four
ecosystem members now converged on this control — including both later entrants independently
adopting it, not merely the founding pair — `simply_ip_exporter`'s absence reads as a genuine gap
against ecosystem-wide practice, not an idiosyncrasy.

**Recommendation:** add `#[serde(deny_unknown_fields)]` to all five current mutating payload types
in `src/api/keys.rs` and `src/api/endpoints.rs`, and adopt it as a standing convention for any future
payload type — `StrictJson` (`src/extract.rs`) already normalizes the resulting rejection into this
crate's `{"error": ...}` envelope, so no extractor-level change is needed, only the struct attribute.

---

## 8. Concurrency & Race Conditions

| Project | `rows_affected`-checked delete handlers | Notes |
| :--- | :--- | :--- |
| `simply_ip_exporter` | 2 | `delete_endpoint`, `delete_api_key` — fixed 2026-08-16, regression-tested |
| `simply_ip_vault` | 5 | |
| `simply_hook_executor` | 4 | |
| `simply_ip_sync` | 5 | |

**Finding:** No gap identified. All four projects check `rows_affected` (or an equivalent) on their
delete paths rather than trusting a non-erroring `DeleteResult` against a possibly-already-deleted
row — the TOCTOU class of bug this guards against appears closed ecosystem-wide as of the commits
audited in this pass. A dedicated `tests/concurrency_and_contracts.rs` file now exists in three of
the four projects (`simply_ip_vault`, `simply_hook_executor`, `simply_ip_sync`) — `simply_ip_exporter`
covers the same property inline within `tests/integration.rs` rather than in a dedicated file; a
naming/organization difference, not a coverage gap (see the Structural Convergence Report §5 for the
test-suite-architecture comparison).

---

## 9. Error Response Envelope

| Property | `simply_ip_exporter` | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_sync` |
| :--- | :--- | :--- | :--- | :--- |
| Base shape | `{"error": "<message>"}` | Identical | Identical | Identical |
| Status mapping for shared variants | Identical across all four | — | — | — |
| `BodyRejected(StatusCode, String)` (extractor status passed through verbatim) | Yes | Yes | Yes | Yes |
| `ConflictWithDetails` (structured `409` inventory) | No | Yes | Yes | Yes |
| `TooManyRequests`/429 | Yes (public feed rate limiter) | No | Yes | No |

**Finding:** No gap in the shared envelope shape or status mapping across the ecosystem. Variant
differences track genuine structural differences (an unauthenticated public feed surface on exporter
and hook_executor needing 429; a blocking cascade-delete flow on vault, hook_executor, and sync that
exporter's simpler ownership model doesn't yet have) rather than inconsistency.

---

## 10. Ecosystem Convergence Tooling

| Project | `scripts/verify_convergence.sh` | `scripts/test_e2e.sh` |
| :--- | :--- | :--- |
| `simply_ip_exporter` | Present | Present |
| `simply_ip_vault` | Present | Present |
| `simply_hook_executor` | Present | Present |
| `simply_ip_sync` | **Absent** | Present |

**Finding — reported, not fixed (peer repository).** `simply_ip_sync`'s own `AGENT.MD` describes
`scripts/verify_convergence.sh` in its "Peer Repository Synchronization" section as though it exists
and runs automatically — it does not exist in the checkout audited at `72cce13`. This is the one
item from this class of finding that remains open in `simply_ip_sync` despite that project's
otherwise substantial convergence progress since the previous pass (payload strictness, the
encryption-key canary, and `db::has_index` have all since been adopted there). Recommendation for
that project's own maintainers: either author the script (mirroring vault's or hook_executor's, both
of which already exist and could serve as a direct template) or correct `AGENT.MD` to stop
describing a control that isn't there.

---

## 11. Findings Summary

| # | Finding | Affected | Severity | Status |
| :-- | :--- | :--- | :--- | :--- |
| 1 | `master.rs` uses `SchemaManager::has_index`, broken on PostgreSQL, against an `AGENT.MD` that explicitly mandates PostgreSQL readiness | `simply_hook_executor` | **High** (defect against a stated current capability) | Open — reported, not fixed (peer) |
| 2 | Same `SchemaManager::has_index` defect | `simply_ip_exporter` | Medium (SQLite-only deployment claim; latent, not currently exploitable) | Open |
| 3 | Zero `#[serde(deny_unknown_fields)]` usage across all mutating payloads, against an ecosystem-wide (3-of-4) convergence on the control | `simply_ip_exporter` | Medium | Open |
| 4 | No wrong-encryption-key startup canary | `simply_ip_vault`, `simply_hook_executor` | Medium | Open — reported, not fixed (peer) |
| 5 | No centralized `api/guards.rs`; owned-resource deletion is silent `SET NULL` rather than a blocking inventory, against 3-of-4 ecosystem convergence on both | `simply_ip_exporter` | Low (structural; justified at current RBAC complexity) | Open, soft recommendation only |
| 6 | `scripts/verify_convergence.sh` documented in `AGENT.MD` but not present | `simply_ip_sync` | Low (documentation/tooling drift) | Open — reported, not fixed (peer) |

No **Critical** findings — no authorization bypass, forgeable signature, plaintext-secret exposure,
or RBAC uniqueness-bypass was found in any of the four projects in this pass.

---

## 12. Executive Verdict

**The ecosystem's security foundation is genuinely shared, not superficially similar.** Across four
independently-maintained Rust services, the `CANONICAL_V1` signing scheme, the secrets-at-rest
envelope, the Master-pinning mechanism, and the anti-replay guard are behaviorally identical, several
times down to independently-documented, matching design rationale. That degree of convergence does
not happen by accident between unrelated codebases — it is the clearest evidence available that this
is one security architecture implemented four times, not four architectures that happen to agree by
coincidence.

Where the ecosystem's "gold standard" framing does not fully hold up under fresh inspection: this
pass's highest-severity finding sits inside `simply_hook_executor`, one of the two founding
projects, not one of the newer entrants — the `SchemaManager::has_index` defect there contradicts an
explicit, current `AGENT.MD` guarantee, where the equivalent defect in `simply_ip_exporter` is only
a latent risk against a narrower claim. Symmetrically, the two later projects
(`simply_ip_exporter`, `simply_ip_sync`) are each ahead of *both* founding siblings on the
wrong-encryption-key startup canary. **Maturity in this ecosystem is not strictly ordered by
founding sequence** — it is distributed unevenly across all four projects, and each has something the
others should adopt.

**`simply_ip_exporter`'s own standing:** solid on every property that matters most (signing,
replay, Master pinning, secrets at rest, ahead on the encryption-key canary) with two clear,
inexpensive items to close — `deny_unknown_fields` on its payload types, and the `has_index`
portability fix — plus one soft structural recommendation (`guards.rs`) to keep pace with, rather
than lag behind, the rest of the ecosystem's convergence trajectory.
