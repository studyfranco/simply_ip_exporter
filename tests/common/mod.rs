//! Shared fixtures for the integration test suite.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use sha2::Sha256;
use simply_ip_exporter::{
    api::support::hash_key, config::RuntimeConfig, crypto::SecretCipher, entities::api_key, migration,
    state::AppState,
};
use uuid::Uuid;

/// A migrated, isolated in-memory database.
pub async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite is always available");
    migration::Migrator::up(&db, None).await.expect("migrations apply to a fresh database");
    db
}

/// Builds application state around a database handle, with plaintext secret storage.
pub fn test_state(db: &DatabaseConnection) -> AppState {
    AppState::new(db.clone(), Arc::new(RuntimeConfig::default()), Arc::new(SecretCipher::Plaintext))
}

/// A seeded key: its plaintext secret, signing secret, and database row.
pub struct SeededKey {
    pub plaintext_key: String,
    pub signing_secret: String,
    pub model: api_key::Model,
}

/// Inserts an API key directly (bypassing the API), returning its plaintext credentials.
pub async fn insert_key(db: &DatabaseConnection, is_master: bool, can_manage_keys: bool) -> SeededKey {
    let plaintext_key = "k".repeat(32) + &Uuid::new_v4().simple().to_string();
    let signing_secret = "s".repeat(32) + &Uuid::new_v4().simple().to_string();
    let now = Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set("Test Key".to_owned()),
        prefix: Set(plaintext_key.chars().take(8).collect()),
        key_hash: Set(hash_key(&plaintext_key)),
        signing_secret: Set(Some(format!("v1.plain.{}", hex::encode(&signing_secret)))),
        bound_ips: Set(None),
        is_master: Set(is_master),
        can_manage_keys: Set(can_manage_keys),
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = model.insert(db).await.expect("insert succeeds");
    SeededKey { plaintext_key, signing_secret, model: inserted }
}

fn sign(secret: &str, method: &str, target: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any length key");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(target.as_bytes());
    mac.update(b"\n");
    mac.update(timestamp.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Attaches a simulated TCP peer, required by the auth middleware's `ConnectInfo` extractor.
pub fn with_connect_info(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
}

/// Builds a `CANONICAL_V1`-signed request, stamped at the current time.
pub fn signed_request(method: &str, uri: &str, key: &SeededKey, body: &str) -> Request<Body> {
    signed_request_at(method, uri, key, body, Utc::now().timestamp())
}

/// As [`signed_request`], with an explicit timestamp so replay/window behaviour is testable.
pub fn signed_request_at(method: &str, uri: &str, key: &SeededKey, body: &str, timestamp: i64) -> Request<Body> {
    let ts = timestamp.to_string();
    let signature = sign(&key.signing_secret, method, uri, &ts, body.as_bytes());
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-API-Key", &key.plaintext_key)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", ts)
            .header("X-Signature-256", signature),
    )
    .body(Body::from(body.to_owned()))
    .expect("request builds")
}
