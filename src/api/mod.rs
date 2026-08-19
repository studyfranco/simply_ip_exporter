//! Admin API handlers, mounted under `/api/*` behind [`crate::middleware::auth_middleware`], plus
//! the unauthenticated health probes mounted outside it.

/// `GET /api/audit-logs`.
pub mod audit;
/// `GET /api/auth/me`.
pub mod auth;
/// `GET /health`, `/ready` and their `z`-suffixed aliases.
pub mod health;
/// CRUD for `endpoints`.
pub mod endpoints;
/// Authorization decisions shared by more than one handler — Master-key immutability and the
/// generic administrative check every route already inlined before this module existed.
pub mod guards;
/// CRUD for `api_keys`.
pub mod keys;
/// Shared key-minting/hashing helpers and the audit-log writer.
pub mod support;

pub use audit::list_audit_logs;
pub use auth::get_me;
pub use endpoints::{create_endpoint, delete_endpoint, list_endpoints, reassign_endpoint_owner, update_endpoint};
pub use health::{health_check, readiness_check};
pub use keys::{create_api_key, delete_api_key, list_api_keys, rotate_api_key, update_api_key};
