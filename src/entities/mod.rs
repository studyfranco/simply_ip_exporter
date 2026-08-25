//! SeaORM entity definitions mirroring the tables described in `SCHEMA.MD`.
//!
//! Configuration only: `api_keys`, `endpoints`, and `audit_logs`. IP records never appear here —
//! they are kept strictly in-memory, per `AGENT.MD`.

/// Re-exports of every entity type.
pub mod prelude;

/// The `api_keys` table: local admin authentication tokens and RBAC flags.
pub mod api_key;
/// The `audit_logs` table: the audit trail for mutating administrative actions.
pub mod audit_log;
/// The `endpoints` table: public feed route configuration.
pub mod endpoint;
/// The `vault_group_permissions` table: which local API keys may reference which Vault groups.
pub mod vault_group_permission;
