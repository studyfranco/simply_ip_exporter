//! End-to-end integration tests exercising the router: probes, HMAC auth, RBAC, and the public
//! feed pipeline (aggregation, filters, ETag/304, rate limiting).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{insert_key, setup_test_db, signed_request, signed_request_at, test_state, with_connect_info};
use simply_ip_exporter::create_app;
use tower::ServiceExt;

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body reads");
    serde_json::from_slice(&bytes).expect("valid JSON")
}

#[tokio::test]
async fn health_check_is_200_without_a_database() {
    let db = setup_test_db().await;
    let state = test_state(&db);
    let app = create_app(state);

    let response = app
        .oneshot(with_connect_info(Request::builder().uri("/health")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "simply_ip_exporter");
}

#[tokio::test]
async fn readiness_is_503_until_master_is_pinned_then_200() {
    let db = setup_test_db().await;
    let state = test_state(&db);
    let app = create_app(state.clone());

    let response = app
        .clone()
        .oneshot(with_connect_info(Request::builder().uri("/ready")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let key = insert_key(&db, true, true).await;
    state.master_pin.pin_at_boot(&db).await.expect("pins the sole master");
    let _ = &key;

    let response = app
        .oneshot(with_connect_info(Request::builder().uri("/ready")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Adapted from a pattern audited in `example/simply_hook_executor`'s readiness-probe tests
/// (2026-08-17 peer test-harness audit — see `AGENT_NOTES.MD`): readiness must fail on a genuinely
/// broken database dependency, not merely on an unpinned Master — the test above already covers
/// that half. Severs the dependency for real (an unmigrated connection, so the readiness query
/// errors on a missing table) rather than mocking `db_ok` out, with the Master pre-pinned via
/// `with_pinned_master` so a passing master check can't be mistaken for the reason this still 503s.
#[tokio::test]
async fn readiness_is_503_when_the_database_itself_is_broken_even_with_master_pinned() {
    let db = sea_orm::Database::connect("sqlite::memory:").await.expect("in-memory sqlite is always available");
    // Deliberately no `migration::Migrator::up(&db, ...)`: every table-touching query on this
    // connection fails, which is exactly the dependency this test needs severed.
    let state = test_state(&db).with_pinned_master(uuid::Uuid::new_v4());
    let app = create_app(state);

    let response = app
        .oneshot(with_connect_info(Request::builder().uri("/ready")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a broken database must fail readiness even when the Master identity is already pinned"
    );
}

#[tokio::test]
async fn an_unsigned_request_to_the_admin_api_is_rejected() {
    let db = setup_test_db().await;
    let state = test_state(&db);
    let app = create_app(state);

    let response = app
        .oneshot(with_connect_info(Request::builder().uri("/api/auth/me")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_correctly_signed_request_authenticates_and_reports_identity() {
    let db = setup_test_db().await;
    let key = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(key.model.id);
    let app = create_app(state);

    let response =
        app.oneshot(signed_request("GET", "/api/auth/me", &key, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["is_master"], true);
}

#[tokio::test]
async fn a_replayed_signature_is_rejected_on_second_use() {
    let db = setup_test_db().await;
    let key = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(key.model.id);
    let app = create_app(state);

    let timestamp = chrono::Utc::now().timestamp();
    let first = signed_request_at("GET", "/api/auth/me", &key, "", timestamp);
    let second = signed_request_at("GET", "/api/auth/me", &key, "", timestamp);

    assert_eq!(app.clone().oneshot(first).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.oneshot(second).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stale_timestamp_is_rejected() {
    let db = setup_test_db().await;
    let key = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(key.model.id);
    let app = create_app(state);

    let stale = chrono::Utc::now().timestamp() - 3600;
    let response = app.oneshot(signed_request_at("GET", "/api/auth/me", &key, "", stale)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_daughter_key_cannot_manage_api_keys() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let daughter = insert_key(&db, false, false).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let response = app
        .oneshot(signed_request(
            "POST",
            "/api/keys",
            &daughter,
            r#"{"name":"Attempted Daughter Key"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_daughter_key_can_manage_only_its_own_endpoints() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let owner = insert_key(&db, false, false).await;
    let other = insert_key(&db, false, false).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let create = app
        .clone()
        .oneshot(signed_request(
            "POST",
            "/api/endpoints",
            &owner,
            r#"{"name":"DMZ Blacklist","vault_groups":"fail2ban"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let created = body_json(create).await;
    let id = created["id"].as_str().unwrap();

    // The owner may update its own endpoint.
    let update = app
        .clone()
        .oneshot(signed_request(
            "PUT",
            &format!("/api/endpoints/{id}"),
            &owner,
            r#"{"ttl_seconds":120}"#,
        ))
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    // A different Daughter key may not.
    let forbidden = app
        .oneshot(signed_request(
            "DELETE",
            &format!("/api/endpoints/{id}"),
            &other,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn feed_aggregates_filters_etags_and_rate_limits() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);

    let create = create_app(state.clone())
        .oneshot(signed_request(
            "POST",
            "/api/endpoints",
            &master,
            r#"{"name":"Test Feed","vault_groups":"g1","filter_rfc1918":true}"#,
        ))
        .await
        .unwrap();
    let created = body_json(create).await;
    let endpoint_id: uuid::Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let token = created["token_secret"].as_str().unwrap().to_owned();

    // Populate the in-memory cache directly, as the sync worker would.
    state
        .ip_cache
        .apply_full(
            endpoint_id,
            &[
                simply_ip_exporter::cache::VaultRecord {
                    target_address: "203.0.113.5/32".to_owned(),
                    updated_at: chrono::Utc::now().naive_utc(),
                    is_deleted: false,
                },
                simply_ip_exporter::cache::VaultRecord {
                    target_address: "10.0.0.5/32".to_owned(),
                    updated_at: chrono::Utc::now().naive_utc(),
                    is_deleted: false,
                },
            ],
        )
        .await;

    let app = create_app(state);
    let uri = format!("/feed/v1/{token}/list.txt");

    let first = app
        .clone()
        .oneshot(with_connect_info(Request::builder().uri(uri.as_str())).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers().get("content-type").unwrap(), "text/plain; charset=utf-8");
    let etag = first.headers().get("etag").unwrap().to_str().unwrap().to_owned();
    let bytes = axum::body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    // The RFC 1918 address is filtered out; only the public one survives.
    assert_eq!(text.trim(), "203.0.113.5/32");

    // Second request from the same IP, with no conditional header, is rate-limited.
    let throttled = app
        .clone()
        .oneshot(with_connect_info(Request::builder().uri(uri.as_str())).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // A matching If-None-Match from that SAME throttled IP still gets 304, not 429: a conditional
    // revalidation the caller already has an up-to-date copy for is free and bypasses the limiter.
    let revalidate = app
        .clone()
        .oneshot(
            with_connect_info(Request::builder().uri(uri.as_str()).header("If-None-Match", &etag))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revalidate.status(), StatusCode::NOT_MODIFIED);

    // A fresh source IP is unaffected by the other IP's throttle, and honours If-None-Match.
    let conditional = app
        .oneshot(
            Request::builder()
                .uri(uri.as_str())
                .header("If-None-Match", etag)
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([10, 0, 0, 9], 9000))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conditional.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn feed_enforces_bound_ips() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);

    let create = create_app(state.clone())
        .oneshot(signed_request(
            "POST",
            "/api/endpoints",
            &master,
            r#"{"name":"Restricted","vault_groups":"g1","bound_ips":"192.168.0.0/16"}"#,
        ))
        .await
        .unwrap();
    let created = body_json(create).await;
    let token = created["token_secret"].as_str().unwrap().to_owned();

    let app = create_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/feed/v1/{token}/list.txt"))
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([1, 2, 3, 4], 9000))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unknown_feed_token_is_404() {
    let db = setup_test_db().await;
    let state = test_state(&db);
    let app = create_app(state);

    let response = app
        .oneshot(
            with_connect_info(Request::builder().uri("/feed/v1/does-not-exist/list.txt"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Audit logging ────────────────────────────────────────────────────────────

/// Fetches the full, unfiltered audit log as Master and returns it as a JSON array.
async fn fetch_audit_logs(app: axum::Router, master: &common::SeededKey) -> Vec<serde_json::Value> {
    let response = app.oneshot(signed_request("GET", "/api/audit-logs", master, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await.as_array().unwrap().clone()
}

#[tokio::test]
async fn creating_an_api_key_writes_an_audit_log_entry() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let create = app
        .clone()
        .oneshot(signed_request("POST", "/api/keys", &master, r#"{"name":"Audited Key"}"#))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let created = body_json(create).await;
    let key_id = created["id"].as_str().unwrap();

    let logs = fetch_audit_logs(app, &master).await;
    let entry = logs.iter().find(|l| l["action"] == "KEY_CREATE").expect("a KEY_CREATE entry exists");
    assert!(entry["target_resource"].as_str().unwrap().contains(key_id));
    assert!(entry["target_resource"].as_str().unwrap().contains("Audited Key"));
    assert_eq!(entry["api_key_name"], master.model.name);
    assert_eq!(entry["api_key_prefix"], master.model.prefix);
    assert!(!entry["client_ip"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn key_update_rotate_and_delete_each_write_their_own_audit_entry() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let create = app
        .clone()
        .oneshot(signed_request("POST", "/api/keys", &master, r#"{"name":"Lifecycle Key"}"#))
        .await
        .unwrap();
    let key_id = body_json(create).await["id"].as_str().unwrap().to_owned();

    let update = app
        .clone()
        .oneshot(signed_request(
            "PUT",
            &format!("/api/keys/{key_id}"),
            &master,
            r#"{"name":"Renamed Key"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    let rotate = app
        .clone()
        .oneshot(signed_request("POST", &format!("/api/keys/{key_id}/rotate"), &master, ""))
        .await
        .unwrap();
    assert_eq!(rotate.status(), StatusCode::OK);

    let delete = app
        .clone()
        .oneshot(signed_request("DELETE", &format!("/api/keys/{key_id}"), &master, ""))
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let logs = fetch_audit_logs(app, &master).await;
    for expected_action in ["KEY_CREATE", "KEY_UPDATE", "KEY_ROTATE", "KEY_DELETE"] {
        assert!(
            logs.iter().any(|l| l["action"] == expected_action
                && l["target_resource"].as_str().is_some_and(|t| t.contains(&key_id))),
            "expected an audit entry for {expected_action} against key {key_id}, got: {logs:#?}"
        );
    }

    // KEY_UPDATE's details records which fields actually changed.
    let update_entry = logs.iter().find(|l| l["action"] == "KEY_UPDATE").unwrap();
    assert!(update_entry["details"].as_str().unwrap().contains("name"));
}

#[tokio::test]
async fn endpoint_create_update_delete_and_owner_reassign_each_write_an_audit_entry() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let other = insert_key(&db, false, false).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let create = app
        .clone()
        .oneshot(signed_request(
            "POST",
            "/api/endpoints",
            &master,
            r#"{"name":"Audited Feed","vault_groups":"g1"}"#,
        ))
        .await
        .unwrap();
    let ep_id = body_json(create).await["id"].as_str().unwrap().to_owned();

    let update = app
        .clone()
        .oneshot(signed_request(
            "PUT",
            &format!("/api/endpoints/{ep_id}"),
            &master,
            r#"{"ttl_seconds":120}"#,
        ))
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    let reassign = app
        .clone()
        .oneshot(signed_request(
            "PUT",
            &format!("/api/endpoints/{ep_id}/owner"),
            &master,
            &format!(r#"{{"owner_key_id":"{}"}}"#, other.model.id),
        ))
        .await
        .unwrap();
    assert_eq!(reassign.status(), StatusCode::OK);

    let delete = app
        .clone()
        .oneshot(signed_request("DELETE", &format!("/api/endpoints/{ep_id}"), &master, ""))
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let logs = fetch_audit_logs(app, &master).await;
    for expected_action in
        ["ENDPOINT_CREATE", "ENDPOINT_UPDATE", "ENDPOINT_OWNER_REASSIGN", "ENDPOINT_DELETE"]
    {
        assert!(
            logs.iter().any(|l| l["action"] == expected_action
                && l["target_resource"].as_str().is_some_and(|t| t.contains(&ep_id))),
            "expected an audit entry for {expected_action} against endpoint {ep_id}, got: {logs:#?}"
        );
    }
}

#[tokio::test]
async fn audit_logs_are_readable_only_by_the_master_key() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let daughter = insert_key(&db, false, false).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let response =
        app.oneshot(signed_request("GET", "/api/audit-logs", &daughter, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn audit_log_action_filter_narrows_results() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    app.clone()
        .oneshot(signed_request("POST", "/api/keys", &master, r#"{"name":"Filter Test Key"}"#))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            "POST",
            "/api/endpoints",
            &master,
            r#"{"name":"Filter Test Endpoint","vault_groups":"g1"}"#,
        ))
        .await
        .unwrap();

    let response = app
        .oneshot(signed_request("GET", "/api/audit-logs?action=KEY_CREATE", &master, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let logs = body_json(response).await.as_array().unwrap().clone();
    assert!(!logs.is_empty());
    assert!(logs.iter().all(|l| l["action"] == "KEY_CREATE"));
}

// ── Malformed request handling (StrictJson / StrictPath) ────────────────────
//
// Axum's built-in `Json`/`Path` extractors reject a malformed request with a plain-text body of
// their own, before any handler runs — bypassing `AppError`'s `{"error": ...}` envelope entirely.
// `src/extract.rs`'s `StrictJson`/`StrictPath` close that gap; these tests pin the closed shape
// rather than just the status code, since a regression back to the built-in extractors would still
// return the same 400 while silently changing the body format every other endpoint promises.

#[tokio::test]
async fn a_malformed_json_body_is_reported_in_the_normal_error_envelope() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let response =
        app.oneshot(signed_request("POST", "/api/keys", &master, "{not valid json")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    // The envelope is exactly `{"error": "..."}` — a bare string field, present and non-empty —
    // rather than axum's own plain-text rejection body (which `body_json`'s `serde_json::from_slice`
    // would fail to parse at all, panicking this test before the assertion below ever ran).
    assert!(json["error"].as_str().is_some_and(|s| !s.is_empty()));
}

/// `#[serde(deny_unknown_fields)]` on every mutating payload (2026-08-18 harmonization pass, see
/// `AGENT_NOTES.MD`): a stray field is refused with a `400` naming it, not silently dropped. The
/// primary control — `is_master` absent from the type entirely — already stops it from taking
/// effect even without this; this proves the *second* control, that the attempt itself is refused
/// and visible, actually fires.
#[tokio::test]
async fn an_unknown_field_in_a_mutating_payload_is_rejected_rather_than_silently_dropped() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let response = app
        .oneshot(signed_request(
            "POST",
            "/api/keys",
            &master,
            r#"{"name":"daughter","is_master":true}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert!(
        json["error"].as_str().is_some_and(|s| s.contains("is_master")),
        "the error should name the rejected field: {json:?}"
    );
}

#[tokio::test]
async fn an_invalid_uuid_path_parameter_is_reported_in_the_normal_error_envelope() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let response =
        app.oneshot(signed_request("DELETE", "/api/keys/not-a-uuid", &master, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert!(json["error"].as_str().is_some_and(|s| !s.is_empty()));
}

/// The body-size limit is a distinct failure from "malformed content" and must keep its own status
/// (`413`) rather than being flattened into a `400` — see `AppError::BodyRejected`'s doc comment
/// and the `Content-Length` pre-check in `middleware::auth_middleware`.
#[tokio::test]
async fn an_oversized_body_is_413_not_400() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let huge = format!(r#"{{"name":"{}"}}"#, "x".repeat(simply_ip_exporter::MAX_REQUEST_BODY_BYTES));
    let response = app.oneshot(signed_request("POST", "/api/keys", &master, &huge)).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ── Concurrent mutations ─────────────────────────────────────────────────────
//
// `tower::ServiceExt::oneshot` consumes one clone of the router per call, but every clone shares
// the same `AppState` (an `Arc`-wrapped bundle — see `state::AppState`), so firing several clones'
// requests concurrently genuinely exercises shared state (the DB pool, the replay guard) under
// real concurrency, not just sequential reuse.

/// The exact same signed request, fired twice at once rather than one after another. The replay
/// guard (`ReplayGuard::check_and_record`) is a `std::sync::Mutex`-guarded map checked-and-inserted
/// under one lock acquisition — this is what actually proves that's atomic: a naive
/// check-then-insert split across two lock acquisitions would let both concurrent callers observe
/// "not yet seen" and both succeed, silently defeating single-use enforcement.
#[tokio::test]
async fn two_concurrent_identical_signed_requests_only_one_succeeds() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let timestamp = chrono::Utc::now().timestamp();
    let first = signed_request_at("GET", "/api/auth/me", &master, "", timestamp);
    let second = signed_request_at("GET", "/api/auth/me", &master, "", timestamp);

    let app_a = app.clone();
    let app_b = app.clone();
    let (result_a, result_b) =
        tokio::join!(app_a.oneshot(first), app_b.oneshot(second));
    let statuses = [result_a.unwrap().status(), result_b.unwrap().status()];

    let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let rejected_count = statuses.iter().filter(|s| **s == StatusCode::UNAUTHORIZED).count();
    assert_eq!(ok_count, 1, "exactly one of the two identical concurrent requests must succeed, got {statuses:?}");
    assert_eq!(rejected_count, 1, "the other must be rejected as a replay, got {statuses:?}");
}

/// Two concurrent `DELETE` requests for the same endpoint: exactly one actually deletes it (`204`)
/// and the other finds it already gone (`404`) — never two `204`s, and never a panic or a
/// database error surfacing as a `500` from the race.
#[tokio::test]
async fn two_concurrent_deletes_of_the_same_endpoint_do_not_both_succeed() {
    let db = setup_test_db().await;
    let master = insert_key(&db, true, true).await;
    let state = test_state(&db).with_pinned_master(master.model.id);
    let app = create_app(state);

    let create = app
        .clone()
        .oneshot(signed_request(
            "POST",
            "/api/endpoints",
            &master,
            r#"{"name":"Concurrent Delete Target","vault_groups":"g1"}"#,
        ))
        .await
        .unwrap();
    let id = body_json(create).await["id"].as_str().unwrap().to_owned();

    // Distinct timestamps (and therefore distinct signatures) so this races the DELETE handler's
    // own find-then-delete logic, not the replay guard from the test above.
    let now = chrono::Utc::now().timestamp();
    let first = signed_request_at("DELETE", &format!("/api/endpoints/{id}"), &master, "", now);
    let second = signed_request_at("DELETE", &format!("/api/endpoints/{id}"), &master, "", now + 1);

    let app_a = app.clone();
    let app_b = app.clone();
    let (result_a, result_b) =
        tokio::join!(app_a.oneshot(first), app_b.oneshot(second));
    let statuses = [result_a.unwrap().status(), result_b.unwrap().status()];

    let deleted_count = statuses.iter().filter(|s| **s == StatusCode::NO_CONTENT).count();
    let not_found_count = statuses.iter().filter(|s| **s == StatusCode::NOT_FOUND).count();
    assert_eq!(deleted_count, 1, "exactly one concurrent delete must succeed, got {statuses:?}");
    assert_eq!(not_found_count, 1, "the other must find it already gone, got {statuses:?}");
}
