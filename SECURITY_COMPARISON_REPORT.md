# Security Comparison Report — `simply_ip_exporter` vs. `simply_ip_vault`

**Status:** Independent, zero-knowledge security audit. Supersedes and replaces any prior version of
this file in its entirety.

**Methodology:** Fresh read of both projects' current `.rs` source under `src/`/`tests/`, evaluated
against `RBAC_MODEL.md` and each project's own `AGENT.MD`. No prior audit report (of either project)
was read or referenced in producing these findings.

**Peer commit audited:** `example/simply_ip_vault` at `14c8fa3` (pulled fresh — `0c4eb7b..14c8fa3`,
fast-forward — at the start of this audit; see `AGENT_NOTES.MD` for the pull log).

**Current-project commit audited:** `simply_ip_exporter` at `HEAD` (working tree, pre-commit).

**Why `simply_ip_vault` and not `simply_hook_executor`.** `RBAC_MODEL.md`'s own header scopes it to
`simply_ip_vault`/`simply_hook_executor` specifically — `simply_ip_exporter` is not a party to it,
and `FILE_MAP.MD` already documents this crate as implementing a *deliberate two-tier subset* of
that model (no Parent tier, no M:N group permissions). Of `example/`'s two RBAC_MODEL.md signatories,
`simply_ip_vault` is the one this crate has an actual runtime relationship with (it is the sync
source for every feed endpoint, and the origin of the `CANONICAL_V1` scheme this crate speaks
outbound); `simply_hook_executor` shares no runtime relationship with this crate at all. This report
therefore compares `simply_ip_exporter` against `simply_ip_vault`, not against
`simply_hook_executor`, and does not attempt an `RBAC_MODEL.md` §-by-§ compliance check against
either project — that specification does not govern `simply_ip_exporter`, so grading it against
those section numbers would misrepresent what "compliant" means for this crate.

---

## 1. Executive Summary

Both services implement the same `CANONICAL_V1` HMAC-SHA256 request-signing scheme, the same
XChaCha20-Poly1305 secrets-at-rest envelope, the same boot-time Master-identity pinning pattern
(`OnceLock` + a database-generated uniqueness column), and the same monotonic-clock anti-replay
guard. Where they diverge in security posture, the divergence is mostly **`simply_ip_exporter`
lagging a maturity curve `simply_ip_vault` has already climbed** — most visibly in payload input
strictness — with one significant exception where the relationship inverts: `simply_ip_exporter`
already closes a startup-time encryption-key-mismatch gap that `simply_ip_vault` has not yet closed.

| | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| `#[serde(deny_unknown_fields)]` on mutating payloads | **0 of 6** structs | **8** occurrences across 4 files |
| Wrong-encryption-key caught at startup | **Yes** (`main.rs::verify_encryption_key`) | **No** |
| `is_master` absent from create/update payload types | Yes | Yes |
| Master uniqueness index existence re-checked at boot | Yes, via `SchemaManager::has_index` | Yes, via a custom `db::has_index` (`SchemaManager::has_index` was tried and found broken on PostgreSQL) |
| Query-string included in signed material | Yes | Yes |
| Anti-replay clock | Monotonic (`tokio::time::Instant`) | Monotonic (`tokio::time::Instant`) |
| Concurrent-delete (`rows_affected`) race | Fixed (2026-08-16) | Not independently re-verified in this pass; out of scope (see §7) |
| Centralized, named authorization guards (`api/guards.rs`) | No — inline `require_master`/ownership checks | Yes |

---

## 2. Authentication & Request Signing (`CANONICAL_V1`)

| Property | `simply_ip_exporter` (`src/middleware.rs`, `src/crypto.rs`) | `simply_ip_vault` (`src/middleware.rs`, `src/crypto.rs`) |
| :--- | :--- | :--- |
| Signed string | `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`, single `\n` | Identical |
| `TARGET` includes query string | Yes — via `OriginalUri` (correct even nested under `.nest("/api", ...)`) | Yes — via `OriginalUri`, same nesting rationale documented |
| `X-Signature-256` prefix (`sha256=`) mandatory | Yes, `SignatureRejection::MissingPrefix` on a bare digest | Yes, `strip_prefix` returns `None` on a bare digest — same refusal |
| Comparison | `Mac::verify_slice` (constant-time) | `Mac::verify_slice` (constant-time) — identical |
| Signing required on every `/api/*` request, no bearer-only fallback | Yes | Yes (vault explicitly contrasts itself with `simply_hook_executor`'s optional-signing mode here — `simply_ip_exporter` independently reaches the same "always signed" posture) |
| Ordering: timestamp → key lookup → signature → replay → `bound_ips` | Yes, in exactly this order (`middleware.rs` doc comment states the 401-vs-403 oracle rationale) | Yes, identical order and identical stated rationale |
| `bound_ips` enforced against the Master key too | Yes | Yes — both projects explicitly reject exempting Master from network binding |

**Finding:** No parity gap. Both implementations independently arrived at the same ordering,
the same oracle-avoidance rationale, and the same constant-time comparison discipline. This is the
strongest area of convergence between the two projects.

---

## 3. Master Identity, Uniqueness, and Startup Integrity (RBAC_MODEL.md §5-equivalent)

| Property | `simply_ip_exporter` (`src/master.rs`) | `simply_ip_vault` (`src/master.rs`) |
| :--- | :--- | :--- |
| Identity pinned once, `OnceLock<Uuid>`, held in `AppState` behind `Arc` | Yes | Yes |
| Impostor `is_master=true` row demoted (not rejected) at the single `authenticate()` choke point | Yes | Yes |
| Uniqueness backed by a database-generated column (`master_marker`) with a unique index | Yes (`idx_api_keys_master_marker`) | Yes (`idx-api_keys-master_marker`) |
| Index existence re-verified at every boot (not just asserted once by a migration) | Yes | Yes |
| Index-existence check implementation | `sea_orm_migration::SchemaManager::has_index` | Custom `crate::db::has_index`, a per-backend catalog query |
| **Why the implementations differ** | — | `SchemaManager::has_index` was tried first and found to return `BackendNotSupported` on PostgreSQL, gated behind cargo features this crate does not enable — see `db::has_index`'s own doc comment for the incident |

**Finding — MEDIUM, portability risk, not currently exploitable.** `simply_ip_exporter`'s
`master.rs::pin_at_boot` calls `SchemaManager::has_index`, the exact API `simply_ip_vault` replaced
after discovering it fails closed with `BackendNotSupported` against PostgreSQL rather than
correctly reporting the index's presence. `simply_ip_exporter`'s own `AGENT.MD` states SQLite is
used "exclusively" for this crate's configuration store (a stronger claim than `simply_ip_vault`'s,
which is explicitly required to interoperate with either backend), so this is not a live
vulnerability under the crate's documented deployment target. It is a latent trap for any future
attempt to run this crate against PostgreSQL: `pin_at_boot` would refuse to start with
`MissingConstraint` against a database whose index is actually present and correct, which is exactly
the failure `simply_ip_vault`'s own incident describes. Recommendation: if PostgreSQL support is ever
entertained for this crate, port `simply_ip_vault`'s `db::has_index` rather than rely on
`SchemaManager::has_index`.

| Property | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Wrong encryption key on restart caught before serving traffic | **Yes** — `main.rs::verify_encryption_key` decrypts the Master's own sealed `signing_secret` as a canary immediately after `bootstrap_master_key`, `exit(1)` with an explicit log line on mismatch | **No** — `bootstrap_master_key` only ever touches the cipher when the `api_keys` table is empty; on every later boot it returns immediately without decrypting anything |

**Finding — the relationship inverts here.** `simply_ip_vault`'s own `crypto.rs` documents at length
why a malformed `VAULT_ENCRYPTION_KEY` must be a hard startup error rather than a silent downgrade
("An operator who set the variable believes their secrets are encrypted... silently writing them in
the clear would betray that belief at exactly the wrong moment") — but that principle is applied
only to a *malformed* key (wrong format), not a *mismatched* one (correct format, wrong bytes,
e.g. an operator typo or a wrong secret restored from a vault). `SecretCipher::from_env()` cannot
distinguish the two by format alone, and `bootstrap_master_key`'s early return on an existing Master
row means the mismatch case is never exercised against real ciphertext at boot. The practical
consequence: on `simply_ip_vault`, a restart with the wrong (but syntactically valid) key starts up
looking healthy and then fails every authenticated request with an opaque `401`, with nothing in the
startup log pointing at the actual cause. `simply_ip_exporter` closed this exact gap on 2026-08-17
(see `AGENT_NOTES.MD`) using the Master's own sealed secret as a canary decrypt. Recommendation: port
the equivalent canary into `simply_ip_vault::main.rs`, immediately after `bootstrap_master_key`.

---

## 4. Secrets at Rest (`SecretCipher`)

| Property | `simply_ip_exporter` (`src/crypto.rs`) | `simply_ip_vault` (`src/crypto.rs`) |
| :--- | :--- | :--- |
| Algorithm | XChaCha20-Poly1305 | XChaCha20-Poly1305 |
| Stored envelope shapes | `v1.plain.<hex>`, `v1.xchacha20poly1305.<nonce>.<ct>` | Identical two shapes |
| Unrecognized/unprefixed stored value | Fails closed (`MalformedCiphertext`) | Fails closed (`MalformedCiphertext`) — and additionally documents, with a test, the retirement of a legacy `aesgcm256:` fallback and an unprefixed-verbatim fallback that both used to exist |
| Key format validation | 64 hex chars, hard error on anything else, no silent downgrade to plaintext | Identical |
| Cross-service key-variable alias (`VAULT_ENCRYPTION_KEY` / `SIGNING_SECRET_KEY`) | N/A — no equivalent alias; not needed, `simply_ip_exporter` has no sibling service sharing a provisioning system for this key | Yes (`ENCRYPTION_KEY_ENV_ALIAS`), for interoperability with `simply_hook_executor`'s provisioning |
| `Debug` impl redacts key material | Yes | Yes |
| Nonce | Fresh random 24 bytes per seal | Identical |

**Finding:** No parity gap in the cryptographic primitive itself. `simply_ip_vault`'s `crypto.rs`
carries substantially more defensive test coverage of *malformed/legacy stored-value shapes*
(retired AES-GCM format, unprefixed-verbatim fallback, blank-vs-unset env var distinction) than
`simply_ip_exporter`'s equivalent tests — see §8 for the concrete test-count comparison. This crate
has never had those legacy formats to retire, so the gap is in defensive-test depth rather than in
current behavior.

---

## 5. Anti-Replay Guard

| Property | `simply_ip_exporter` (`src/replay.rs`) | `simply_ip_vault` (`src/replay.rs`) |
| :--- | :--- | :--- |
| Keyed on | `(key_id, raw HMAC digest bytes)` | Identical |
| Expiry clock | Monotonic `tokio::time::Instant` | Monotonic `tokio::time::Instant` — `crypto.rs`'s own doc comment states the same rationale (a caller-controlled timestamp must not be able to shorten its own signature's memory) |
| Recorded only after signature verification succeeds | Yes | Yes — both document the same reasoning (recording unverified signatures would let an unauthenticated caller both exhaust memory and pre-empt a legitimate client's signature) |
| Window | 300s (`MAX_TIMESTAMP_SKEW_SECS`) | 300s (`MAX_TIMESTAMP_SKEW_SECS`) |

**Finding:** No parity gap. Both replay guards are structurally and behaviorally identical.

---

## 6. Authorization Model

`RBAC_MODEL.md` does not govern `simply_ip_exporter` (see header), so this section compares
*architecture and enforcement discipline*, not §-rule compliance.

| Property | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Tiers | Two: Master, Daughter (`can_manage_keys` exists on the schema but is not currently wired to a distinct Parent tier — see `AGENT_NOTES.MD`'s "deliberate deviation" note) | Three: Master, Parent (`can_manage_keys`), Daughter, plus per-resource `can_read`/`can_write`/`can_delete`/`can_manage` grants (M:N via `api_key_group_permissions`) |
| Authorization logic location | Inline per-handler (`require_master(&caller)?`, `caller.is_master \|\| existing.owner_key_id == Some(caller.id)`) | Centralized in `src/api/guards.rs` — one named, individually documented function per rule (`guard_resource_lifecycle`, `guard_group_manage`, `guard_delegated_group_grant`, `guard_scope_elevation`, `guard_master_target`, `guard_master_immutable`, …), each with an `RBAC_MODEL.md` rule citation in its doc comment |
| `is_master` settable via API payload | No — absent from `CreateKeyPayload`/`UpdateKeyPayload` by construction | No — absent from the equivalent payload types by construction, identical rationale |
| Master key immutable via API (except its own `bound_ips`) | Yes — delete refused (`Forbidden`), no rotation route exists for Master, `UpdateKeyPayload` applied to Master only ever changes `bound_ips` in practice | Yes — `guard_master_immutable`, explicit and centrally enforced with the identical `bound_ips`-only exception |
| Master rotation reachable via API | No route exists | No — explicitly refused by `guard_rotation_allowed`/`guard_master_immutable`, with the same stated rationale (rotation returns the new plaintext credential, so an API-reachable Master rotation would be an API-reachable full takeover) |
| Owned-resource orphaning on key deletion | `endpoints.owner_key_id` is `ON DELETE SET NULL` — deleting a Daughter key that owns endpoints silently orphans them to Master-only visibility; the endpoints keep serving | Refused outright with a structured `409` inventory (`AppError::ConflictWithDetails`, RBAC_MODEL.md §6) — the caller must explicitly reassign or delete owned resources first |

**Finding — structural, not a vulnerability.** `simply_ip_exporter`'s two-tier model has no R1–R7
conjunction rules to violate — those rules exist in `RBAC_MODEL.md` specifically to govern
*delegated* administration (a Parent granting a Daughter a bounded subset of its own rights across
an M:N permission table), a mechanism this crate's schema does not have. Comparing it against R1–R7
would be grading it against a specification it never opted into. The one point worth carrying
forward regardless of tier count: **`simply_ip_vault`'s centralization of authorization decisions
into a dedicated, individually-testable `guards.rs` module is a maintainability and auditability
practice independent of RBAC complexity** — see the Structural Convergence Report for a fuller
treatment. On the specific behavioral difference (`SET NULL` vs. a blocking pre-flight inventory):
`simply_ip_exporter`'s choice does not create a security hole (an orphaned endpoint is not
privilege-escalated, merely Master-supervised going forward, and nothing is destroyed), but it is a
materially more permissive interaction than `simply_ip_vault`'s, and worth a deliberate decision
rather than an implicit one if this crate's ownership model grows further.

---

## 7. Payload & Input Strictness

| File | `#[serde(deny_unknown_fields)]` payload structs | Count |
| :--- | :--- | :--- |
| `simply_ip_exporter/src/api/keys.rs` (`CreateKeyPayload`, `UpdateKeyPayload`) | **Absent from both** | 0 |
| `simply_ip_exporter/src/api/endpoints.rs` (`CreateEndpointPayload`, `UpdateEndpointPayload`, `ReassignOwnerPayload`) | **Absent from all three** | 0 |
| `simply_ip_vault/src/api/keys.rs`, `records.rs`, `support.rs`, `src/extract.rs` | Present | 8 occurrences |

**Finding — MEDIUM, confirmed, repo-wide.** `simply_ip_exporter` has **zero** uses of
`#[serde(deny_unknown_fields)]` anywhere in `src/`. `simply_ip_vault`'s own `src/extract.rs` states
the exact rationale this crate is missing, quoting `RBAC_MODEL.md` §5 directly: *"Removing the field
from the payload type is required; rejecting it at the handler is not sufficient... Serde's default
is to ignore unknown fields, so a struct without `is_master` accepts `{"is_master": true}` and
silently drops it — which is worse than the handler check it replaced, because nothing refuses and
nothing logs."*

`simply_ip_exporter`'s payload types do correctly omit `is_master` — the primary control the
vault's own reasoning is built around holds here too, so this is **not** a privilege-escalation
path. What is missing is the second-order property: today, a client that sends
`POST /api/keys {"name": "x", "is_master": true}` gets a silent `200` with the stray field dropped,
rather than a `400` naming the rejected field. That is a defense-in-depth and API-contract-strictness
gap, not an authorization bypass — but it is exactly the gap `simply_ip_vault`'s own module doc
comment for `extract.rs` was written to close, and every reason given there (silent client bugs,
future fields reintroduced without the same care, no signal that anything was refused) applies
identically to this crate's six mutating payload structs.

`StrictJson`/`StrictPath` (`src/extract.rs`) already exist in `simply_ip_exporter` and already
normalize extractor-level rejections (malformed JSON, oversized body) into the `{"error": ...}`
envelope — the missing piece is purely the `#[serde(deny_unknown_fields)]` attribute on
`CreateKeyPayload`, `UpdateKeyPayload`, `CreateEndpointPayload`, `UpdateEndpointPayload`, and
`ReassignOwnerPayload`. **Recommendation:** add the attribute to all five (and to any future mutating
payload type) as a standing convention, matching `simply_ip_vault`'s.

---

## 8. Concurrency & Race Conditions

| Property | `simply_ip_exporter` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Concurrent-delete `rows_affected` check (`delete_by_id` never errors on zero matched rows) | Fixed 2026-08-16 in `delete_endpoint` and `delete_api_key`; regression-tested (`two_concurrent_deletes_of_the_same_endpoint_do_not_both_succeed`) | Not independently re-verified in this pass — `example/simply_ip_vault/tests/concurrency_and_contracts.rs` (new in the commit pulled for this audit, `14c8fa3`) suggests this class of issue has recent, dedicated attention there too, but auditing its outcome is out of scope for a zero-knowledge pass that does not read prior reports; a follow-up pass should verify it directly against vault's `src/api/*.rs` |
| Replay-guard atomicity under two identical concurrent signed requests | Tested (`two_concurrent_identical_signed_requests_only_one_succeeds`) | Not independently re-verified in this pass |

**Finding:** No new gap identified on `simply_ip_exporter`'s side (the concurrent-delete race found
and fixed in this crate on 2026-08-16 remains fixed and regression-tested). A full concurrency audit
of `simply_ip_vault`'s own handlers was not performed as part of this pass — it would require reading
every `delete_by_id`/`delete_many` call site in `simply_ip_vault/src/api/`, which this report's scope
(a comparison against a fixed peer commit) does not extend to exhaustively. Flagged as a follow-up
item rather than a finding either way.

---

## 9. Error Response Envelope

| Property | `simply_ip_exporter` (`src/error.rs`) | `simply_ip_vault` (`src/error.rs`) |
| :--- | :--- | :--- |
| Base shape | `{"error": "<message>"}` | Identical |
| Status mapping (`DbError`→500, `InvalidInput`→400, `Unauthorized`→401, `Forbidden`→403, `NotFound`→404, `Conflict`→409, `Internal`→500) | Identical | Identical |
| `BodyRejected(StatusCode, String)` — extractor rejection status passed through verbatim, only the body shape normalized | Yes | Yes, identical rationale documented (a `413` must not collapse into an indistinguishable `400`) |
| `TooManyRequests` (429) | Yes — the public feed endpoint's anti-DoS rate limiter needs it | No equivalent variant — `simply_ip_vault`'s API is fully authenticated, with no unauthenticated public surface requiring a bare-metal rate limiter |
| `ConflictWithDetails` (structured `409` inventory, §6) | No | Yes — see §6 |

**Finding:** No parity gap in the shared envelope shape or status mapping. The two variants each
project has that the other lacks (`TooManyRequests` / `ConflictWithDetails`) are both justified by a
genuine structural difference (an unauthenticated public endpoint on one side; a blocking
cascade-delete-conflict flow on the other), not an oversight.

---

## 10. Findings Summary

| # | Finding | Affected | Severity | Status |
| :-- | :--- | :--- | :--- | :--- |
| 1 | Zero `#[serde(deny_unknown_fields)]` usage across all 6 mutating payload structs | `simply_ip_exporter` | Medium | Open — recommend adding to `keys.rs`/`endpoints.rs` payload types |
| 2 | `master.rs::pin_at_boot` uses `SchemaManager::has_index`, the API `simply_ip_vault` replaced after a documented PostgreSQL failure | `simply_ip_exporter` | Medium (portability; not exploitable under this crate's stated SQLite-only deployment) | Open — recommend porting `db::has_index` if/when Postgres is ever entertained |
| 3 | No startup canary for a mismatched (syntactically valid, wrong-bytes) encryption key | `simply_ip_vault` | Medium | Open on the peer — reported per `AGENT.MD`'s peer-repository rules, not fixed here; `simply_ip_exporter` already carries the equivalent fix |
| 4 | Authorization logic is inline per-handler rather than centralized in a named, individually-documented guards module | `simply_ip_exporter` | Low (structural/maintainability, not a live gap at current RBAC complexity) | Open — see Structural Convergence Report |
| 5 | Orphaned-resource handling on key deletion is `SET NULL` rather than a blocking pre-flight inventory | `simply_ip_exporter` | Low (documented divergence, not a vulnerability) | No action recommended unless ownership model complexity grows |

No **High** or **Critical** findings — no authorization bypass, no forgeable signature, no
plaintext-secret exposure, and no RBAC uniqueness-bypass were found on either side in this pass.

---

## 11. Executive Verdict

**`simply_ip_exporter` and `simply_ip_vault` share one security foundation, correctly reimplemented
rather than copy-pasted.** The `CANONICAL_V1` signing scheme, the XChaCha20-Poly1305 secrets-at-rest
envelope, the boot-time Master-pinning mechanism, and the monotonic-clock anti-replay guard are
behaviorally identical across both codebases, down to shared design rationale documented independently
in each project's own comments. This is the strongest possible signal of genuine architectural
convergence rather than superficial similarity.

Where the two diverge, the divergence is legible and mostly attributable to `simply_ip_vault`'s
longer iteration history (12 migrations and a materially larger, more defensively-tested codebase
against `simply_ip_exporter`'s 2) rather than to a design disagreement — the payload-strictness gap
(§7) is the one item in this report that should be closed promptly, being both cheap to fix and the
kind of gap that compounds silently. The `has_index` portability trap (§3) is worth fixing
opportunistically rather than urgently, given the crate's current SQLite-only deployment target. The
one finding that runs the other direction — `simply_ip_vault` lacking the wrong-encryption-key
startup canary `simply_ip_exporter` already has — is evidence this is a genuine two-way relationship
now, not a one-way import of patterns from the more mature project.

**Maturity, not convergence, is the axis these two projects differ on.** Both implement the same
security posture correctly; `simply_ip_vault` has simply had more time and more incidents to harden
the edges of that posture. Closing finding #1 would remove the only item in this report with a
plausible, if narrow, defense-in-depth argument for near-term action.
