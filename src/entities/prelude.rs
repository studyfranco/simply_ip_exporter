//! Convenience re-exports of every entity type in [`crate::entities`].

/// The `api_keys` entity.
pub use super::api_key::Entity as ApiKey;
/// The `audit_logs` entity.
pub use super::audit_log::Entity as AuditLog;
/// The `endpoints` entity.
pub use super::endpoint::Entity as Endpoint;
/// The `vault_group_permissions` entity.
pub use super::vault_group_permission::Entity as VaultGroupPermission;
