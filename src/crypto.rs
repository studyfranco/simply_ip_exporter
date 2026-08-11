//! Cryptographic primitives: `CANONICAL_V1` HMAC-SHA256 request signing, and XChaCha20-Poly1305
//! encryption at rest for `api_keys.signing_secret`.

use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;

// ─────────────────────────────────────────────────────────────
// Request signing (CANONICAL_V1)
// ─────────────────────────────────────────────────────────────

/// The mandatory algorithm tag on every `X-Signature-256` value.
pub const SIGNATURE_PREFIX: &str = "sha256=";

/// Generates a fresh 32-byte HMAC signing secret, hex-encoded.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the `CANONICAL_V1` byte string that gets signed: `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`.
///
/// `target` must include the query string when present, and `body` is used verbatim — never a
/// re-serialized form — so the bytes verified are exactly the bytes sent.
pub fn canonical_v1_payload(method: &str, target: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(method.len() + target.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(target.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

/// Computes the `X-Signature-256` header value (`sha256=<hex>`, prefix included) over a payload.
pub fn compute_signature(secret: &str, payload: &[u8]) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload);
    Some(format!("{SIGNATURE_PREFIX}{}", hex::encode(mac.finalize().into_bytes())))
}

/// Why a presented signature was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureRejection {
    /// The value did not begin with [`SIGNATURE_PREFIX`].
    MissingPrefix,
    /// The prefix was present, but what followed is not hexadecimal.
    MalformedHex,
    /// Well-formed, and does not match the expected digest.
    Mismatch,
    /// The stored secret could not be used as HMAC key material — a server fault.
    KeyUnusable,
}

/// Verifies a caller-supplied `X-Signature-256` value against `payload`.
///
/// Comparison goes through [`Mac::verify_slice`] (constant-time). Returns the raw decoded digest
/// bytes on success, so [`crate::replay::ReplayGuard`] can key on canonical material.
pub fn verify_signature(
    secret: &str,
    payload: &[u8],
    provided: &str,
) -> Result<Vec<u8>, SignatureRejection> {
    let hex_digest = provided
        .trim()
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or(SignatureRejection::MissingPrefix)?;
    let provided_bytes =
        hex::decode(hex_digest.trim()).map_err(|_| SignatureRejection::MalformedHex)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| SignatureRejection::KeyUnusable)?;
    mac.update(payload);
    mac.verify_slice(&provided_bytes).map_err(|_| SignatureRejection::Mismatch)?;

    Ok(provided_bytes)
}

// ─────────────────────────────────────────────────────────────
// Encryption at rest
// ─────────────────────────────────────────────────────────────

/// Environment variable holding the 32-byte (64 hex character) encryption key.
const KEY_ENV_VAR: &str = "EXPORTER_ENCRYPTION_KEY";
/// Prefix marking a value stored without encryption.
const PLAINTEXT_PREFIX: &str = "v1.plain.";
/// Prefix marking a value sealed with XChaCha20-Poly1305.
const SEALED_PREFIX: &str = "v1.xchacha20poly1305.";
/// XChaCha20-Poly1305 nonce width, in bytes.
const NONCE_LEN: usize = 24;
/// Required encryption key width, in bytes.
const KEY_LEN: usize = 32;

/// Failure modes for sealing and opening stored secrets.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// `EXPORTER_ENCRYPTION_KEY` was set but is not 64 hex characters.
    #[error(
        "{KEY_ENV_VAR} must be exactly {} hex characters ({KEY_LEN} bytes); generate one with \
         `openssl rand -hex {KEY_LEN}`",
        KEY_LEN * 2
    )]
    InvalidKey,
    /// The stored value is not in a recognized format.
    #[error("Stored secret is malformed or was written by a newer version")]
    MalformedCiphertext,
    /// The ciphertext failed authentication — wrong key, or the row was tampered with.
    #[error(
        "Stored secret could not be decrypted. This usually means {KEY_ENV_VAR} does not match the \
         key the secret was written with"
    )]
    DecryptionFailed,
    /// The cipher itself failed.
    #[error("Encryption failed")]
    EncryptionFailed,
}

/// How recoverable secrets are protected at rest.
pub enum SecretCipher {
    /// No encryption key configured: secrets are stored verbatim (hex-encoded).
    Plaintext,
    /// Secrets are sealed with XChaCha20-Poly1305 under the configured key.
    Sealed(Box<XChaCha20Poly1305>),
}

impl std::fmt::Debug for SecretCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => f.write_str("SecretCipher::Plaintext"),
            Self::Sealed(_) => f.write_str("SecretCipher::Sealed(<redacted>)"),
        }
    }
}

impl SecretCipher {
    /// Builds the cipher from `EXPORTER_ENCRYPTION_KEY`. A malformed key aborts startup rather
    /// than silently falling back to plaintext.
    pub fn from_env() -> Result<Self, CryptoError> {
        let configured = std::env::var(KEY_ENV_VAR).ok().filter(|raw| !raw.trim().is_empty());
        match configured {
            Some(raw) => Self::from_hex_key(raw.trim()),
            None => Ok(Self::Plaintext),
        }
    }

    /// Builds a cipher from a hex-encoded 32-byte key.
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let key = Key::try_from(bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::Sealed(Box::new(XChaCha20Poly1305::new(&key))))
    }

    /// Whether secrets are actually being encrypted.
    pub fn is_encrypting(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// Encodes a secret for storage.
    pub fn seal(&self, plaintext: &str) -> Result<String, CryptoError> {
        match self {
            Self::Plaintext => Ok(format!("{PLAINTEXT_PREFIX}{}", hex::encode(plaintext))),
            Self::Sealed(cipher) => {
                let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
                let nonce = XNonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed)?;
                Ok(format!(
                    "{SEALED_PREFIX}{}.{}",
                    hex::encode(nonce_bytes),
                    hex::encode(ciphertext)
                ))
            }
        }
    }

    /// Recovers a secret written by [`SecretCipher::seal`]. Plaintext rows remain readable
    /// regardless of the configured mode, so enabling encryption does not invalidate old rows.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        if let Some(encoded) = stored.strip_prefix(PLAINTEXT_PREFIX) {
            let bytes = hex::decode(encoded).map_err(|_| CryptoError::MalformedCiphertext)?;
            return String::from_utf8(bytes).map_err(|_| CryptoError::MalformedCiphertext);
        }

        let body = stored.strip_prefix(SEALED_PREFIX).ok_or(CryptoError::MalformedCiphertext)?;
        let (nonce_hex, ciphertext_hex) =
            body.split_once('.').ok_or(CryptoError::MalformedCiphertext)?;

        let nonce_bytes = hex::decode(nonce_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptoError::MalformedCiphertext);
        }
        let ciphertext = hex::decode(ciphertext_hex).map_err(|_| CryptoError::MalformedCiphertext)?;

        let Self::Sealed(cipher) = self else {
            return Err(CryptoError::DecryptionFailed);
        };

        let nonce =
            XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::MalformedCiphertext)?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn sign(secret: &str, payload: &[u8]) -> String {
        compute_signature(secret, payload).expect("HMAC accepts any key length")
    }

    #[test]
    fn canonical_base_is_newline_delimited() {
        assert_eq!(
            canonical_v1_payload("POST", "/api/keys", "1700000000", b"{}"),
            b"POST\n/api/keys\n1700000000\n{}".to_vec()
        );
    }

    #[test]
    fn compute_and_verify_are_inverses() {
        let payload = canonical_v1_payload("GET", "/api/ips", "1700000000", b"");
        let signature = sign("secret", &payload);
        assert!(signature.starts_with(SIGNATURE_PREFIX));
        let digest = verify_signature("secret", &payload, &signature).expect("verifies");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn rejects_tampered_payload_and_wrong_secret() {
        let payload = canonical_v1_payload("POST", "/api/endpoints", "1700000000", b"{}");
        let signature = sign("secret", &payload);
        let tampered = canonical_v1_payload("POST", "/api/endpoints", "1700000001", b"{}");
        assert_eq!(
            verify_signature("secret", &tampered, &signature),
            Err(SignatureRejection::Mismatch)
        );
        assert_eq!(
            verify_signature("other", &payload, &signature),
            Err(SignatureRejection::Mismatch)
        );
        assert_eq!(
            verify_signature("secret", &payload, "not-prefixed"),
            Err(SignatureRejection::MissingPrefix)
        );
        assert_eq!(
            verify_signature("secret", &payload, "sha256=nothex"),
            Err(SignatureRejection::MalformedHex)
        );
    }

    #[test]
    fn every_single_byte_mutation_is_rejected() {
        let payload = canonical_v1_payload("POST", "/api/keys", "1700000000", b"{}");
        let valid = sign("secret", &payload);
        let digest = hex::decode(&valid[SIGNATURE_PREFIX.len()..]).expect("valid hex");
        for position in 0..digest.len() {
            let mut mutated = digest.clone();
            mutated[position] ^= 0xff;
            let signature = format!("{SIGNATURE_PREFIX}{}", hex::encode(&mutated));
            assert!(verify_signature("secret", &payload, &signature).is_err());
        }
        assert!(verify_signature("secret", &payload, &valid).is_ok());
    }

    #[test]
    fn plaintext_mode_round_trips_and_hides_the_secret() {
        let cipher = SecretCipher::Plaintext;
        assert!(!cipher.is_encrypting());
        let sealed = cipher.seal("s3cr3t").expect("seals");
        assert!(sealed.starts_with(PLAINTEXT_PREFIX));
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opens"), "s3cr3t");
    }

    #[test]
    fn sealed_mode_round_trips_with_fresh_nonces() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert!(cipher.is_encrypting());
        let a = cipher.seal("same").expect("seals");
        let b = cipher.seal("same").expect("seals");
        assert_ne!(a, b);
        assert_eq!(cipher.open(&a).expect("opens"), "same");
        assert_eq!(cipher.open(&b).expect("opens"), "same");
    }

    #[test]
    fn a_wrong_key_cannot_open_a_sealed_secret() {
        let writer = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let other = SecretCipher::from_hex_key(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .expect("valid key");
        let sealed = writer.seal("s3cr3t").expect("seals");
        assert!(matches!(other.open(&sealed), Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn a_malformed_key_aborts_rather_than_downgrading() {
        for bad in ["not-hex", "00ff", &"a".repeat(63)] {
            assert!(matches!(SecretCipher::from_hex_key(bad), Err(CryptoError::InvalidKey)));
        }
    }

    #[test]
    fn malformed_stored_values_are_rejected_as_malformed() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        for malformed in ["", "garbage", "v1.xchacha20poly1305.nodot", "v1.plain.zz"] {
            assert!(matches!(cipher.open(malformed), Err(CryptoError::MalformedCiphertext)));
        }
    }
}
