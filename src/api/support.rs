//! Shared helpers for minting and hashing local API keys.

use rand::RngExt;
use sha2::{Digest, Sha256};

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
}
