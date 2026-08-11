//! Outbound `simply_ip_vault` API client: `CANONICAL_V1` HMAC-signed `GET /api/ips` requests for
//! the hybrid differential/full sync protocol.

use chrono::NaiveDateTime;
use serde::Deserialize;

use crate::crypto::{canonical_v1_payload, compute_signature};

/// One record as returned by Vault's `GET /api/ips` contract.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultApiRecord {
    /// The IP address or CIDR range, exactly as Vault stored it.
    pub target_address: String,
    /// Last activity timestamp, UTC naive ISO-8601.
    pub updated_at: NaiveDateTime,
    /// Whether this is a soft-deleted tombstone (only present with `include_deleted=true`).
    #[serde(default)]
    pub is_deleted: bool,
}

/// Failure modes for a Vault sync request.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The client is not configured (`VAULT_BASE_URL`/`VAULT_API_KEY`/`VAULT_SIGNING_SECRET`).
    #[error("simply_ip_vault client is not configured")]
    NotConfigured,
    /// The HTTP request itself failed (network error, timeout, connection refused).
    #[error("request to simply_ip_vault failed: {0}")]
    Request(#[from] reqwest::Error),
    /// Vault answered with a non-success status.
    #[error("simply_ip_vault returned HTTP {0}")]
    Status(reqwest::StatusCode),
}

/// A signed HTTP client for `simply_ip_vault`.
#[derive(Clone)]
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    signing_secret: String,
}

impl VaultClient {
    /// Builds a client from the runtime configuration, or `None` if Vault sync is not configured.
    pub fn from_config(config: &crate::config::RuntimeConfig) -> Option<Self> {
        let (base_url, api_key, signing_secret) = (
            config.vault_base_url.clone()?,
            config.vault_api_key.clone()?,
            config.vault_signing_secret.clone()?,
        );
        Some(Self { http: reqwest::Client::new(), base_url, api_key, signing_secret })
    }

    /// Fetches IP records for `groups`. When `since` is set, performs a differential query
    /// (`include_deleted=true`); otherwise performs a full, unconstrained query.
    pub async fn fetch_ips(
        &self,
        groups: &str,
        since: Option<NaiveDateTime>,
    ) -> Result<Vec<VaultApiRecord>, VaultError> {
        let mut path_and_query = format!("/api/ips?groups={}", urlencode(groups));
        if let Some(since) = since {
            path_and_query.push_str(&format!(
                "&since={}&include_deleted=true",
                urlencode(&since.and_utc().timestamp().to_string())
            ));
        }

        let timestamp = chrono::Utc::now().timestamp().to_string();
        let payload = canonical_v1_payload("GET", &path_and_query, &timestamp, b"");
        let signature = compute_signature(&self.signing_secret, &payload)
            .ok_or(VaultError::Status(reqwest::StatusCode::INTERNAL_SERVER_ERROR))?;

        let url = format!("{}{}", self.base_url, path_and_query);
        let response = self
            .http
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("X-Timestamp", &timestamp)
            .header("X-Signature-256", &signature)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultError::Status(response.status()));
        }

        Ok(response.json::<Vec<VaultApiRecord>>().await?)
    }
}

/// Minimal query-string percent-encoding, sufficient for group names/UUIDs and Unix timestamps
/// (comma, alphanumeric, `-`).
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b',' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_passes_through_safe_characters() {
        assert_eq!(urlencode("g1,g2-3_a.b~c"), "g1,g2-3_a.b~c");
    }

    #[test]
    fn urlencode_escapes_unsafe_characters() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a/b"), "a%2Fb");
    }

    #[test]
    fn a_client_with_missing_configuration_is_none() {
        let config = crate::config::RuntimeConfig::default();
        assert!(VaultClient::from_config(&config).is_none());
    }

    #[test]
    fn a_fully_configured_client_is_built() {
        let config = crate::config::RuntimeConfig {
            vault_base_url: Some("http://vault:3000".to_owned()),
            vault_api_key: Some("key".to_owned()),
            vault_signing_secret: Some("secret".to_owned()),
            ..crate::config::RuntimeConfig::default()
        };
        assert!(VaultClient::from_config(&config).is_some());
    }
}
