//! Shared helpers for minting and hashing local API keys, and for writing audit trail entries.

use chrono::Utc;
use rand::RngExt;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, audit_log};
use crate::error::AppError;

/// Generates a fresh 32-byte random API key, hex-encoded (`sie_<64 hex>` when displayed with its
/// prefix, but the returned value is the bare secret).
pub fn generate_random_key() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Hashes a plaintext API key with SHA-256 for storage/lookup.
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Parses a comma-separated `bound_ips` string, validating every entry is a CIDR or bare address.
pub fn validate_bound_ips(raw: &str) -> Result<(), String> {
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if entry.parse::<ipnet::IpNet>().is_err() && entry.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("Invalid CIDR or IP address in bound_ips: {entry:?}"));
        }
    }
    Ok(())
}

/// Renders a stable `kind:id (name)` reference for an audit log's `target_resource`.
pub fn describe_resource(kind: &str, id: Uuid, name: &str) -> String {
    format!("{kind}:{id} ({name})")
}

/// Writes one audit trail entry. `key` and `client_ip` denormalize the acting key's name/prefix
/// and the caller's resolved address into the row so it stays legible and attributable even after
/// that key is later deleted (`audit_logs.api_key_id` is `ON DELETE SET NULL`; the name/prefix
/// survive as a point-in-time snapshot rather than a live join).
///
/// Deliberately propagates a write failure via `?` rather than logging and swallowing it: the
/// mutation this call follows has already committed, so a caller that ignored this error would
/// report `200 OK` for an action the audit trail never recorded — the two are meant to be
/// inseparable. A `500` here is the honest answer: something is wrong with the database, and the
/// caller should know its request did not fully succeed.
///
/// Generic over `ConnectionTrait` rather than a concrete `&DatabaseConnection` so a caller running a
/// multi-step mutation inside `db.transaction(...)` (e.g. `api::keys::delete_api_key`'s endpoint
/// reassignment) can pass the transaction handle directly — the audit entry then commits or rolls
/// back atomically with the mutation it describes, rather than being a separate write that could
/// succeed even if the transaction it was meant to describe did not.
pub async fn create_audit_log<C: ConnectionTrait>(
    db: &C,
    key: &api_key::Model,
    client_ip: std::net::IpAddr,
    action: &str,
    target_resource: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(Some(key.id)),
        api_key_name: Set(key.name.clone()),
        api_key_prefix: Set(key.prefix.clone()),
        client_ip: Set(client_ip.to_string()),
        action: Set(action.to_owned()),
        target_resource: Set(target_resource),
        details: Set(details),
        timestamp: Set(Utc::now().naive_utc()),
    };
    log.insert(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_full_width_hex_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let key = generate_random_key();
            assert_eq!(key.len(), 64);
            assert!(seen.insert(key));
        }
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_key("abc"), hash_key("abc"));
        assert_ne!(hash_key("abc"), hash_key("abd"));
    }

    #[test]
    fn bound_ips_validation() {
        assert!(validate_bound_ips("10.0.0.0/8, ::1, 192.168.1.1").is_ok());
        assert!(validate_bound_ips("").is_ok());
        assert!(validate_bound_ips("not-an-ip").is_err());
    }

    #[test]
    fn describe_resource_renders_kind_id_and_name() {
        let id = Uuid::nil();
        assert_eq!(describe_resource("api_key", id, "Daughter Key"), format!("api_key:{id} (Daughter Key)"));
    }
}
