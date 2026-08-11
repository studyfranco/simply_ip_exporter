//! SeaORM entity definitions mirroring the tables described in `SCHEMA.MD`.
//!
//! Configuration only: `api_keys` and `endpoints`. IP records never appear here — they are kept
//! strictly in-memory, per `AGENT.MD`.

/// Re-exports of every entity type.
pub mod prelude;

/// The `api_keys` table: local admin authentication tokens and RBAC flags.
pub mod api_key;
/// The `endpoints` table: public feed route configuration.
pub mod endpoint;
