//! Authorization guards: the single place a permission decision is *made*, per `AGENT.MD`'s
//! two-tier Master/Daughter model.
//!
//! This crate's RBAC surface is deliberately small — there is no delegated-grant mechanism to
//! reason about, unlike the fuller Master/Parent/Daughter model `RBAC_MODEL.md` specifies for
//! `simply_ip_vault`/`simply_hook_executor` (this crate implements a documented subset of that
//! model, not the specification itself — see `AGENT.MD`'s "Local RBAC Model" section). Even so,
//! centralizing the decisions every mutating key handler makes keeps them reviewable in one place
//! and individually testable, rather than reimplemented inline per handler — the same practice
//! this crate's own `STRUCTURAL_CONVERGENCE_REPORT.md` noted three of four `example/` ecosystem
//! peers had already converged on.

use crate::entities::api_key;
use crate::error::AppError;

/// Every mutating `/api/keys/*` route requires the caller to be the Master key — the only tier able
/// to manage local API keys, per `AGENT.MD`.
pub(crate) fn require_master(caller: &api_key::Model) -> Result<(), AppError> {
    if caller.is_master {
        Ok(())
    } else {
        Err(AppError::Forbidden("Only the Master key can manage API keys".to_owned()))
    }
}

/// Refuses deleting or rotating the Master key through the API. `operation` names the refused verb
/// in the client-facing message (e.g. `"deleted"`, `"rotated"`).
///
/// The Master key's credential is deliberately unreachable this way: `POST /api/keys/{id}/rotate`
/// returns the new plaintext secret in its response body, so an API-reachable Master rotation would
/// be an API-reachable full takeover of the most powerful credential in the system. Re-minting it
/// requires direct database access, which an HTTP-only compromise does not have.
pub(crate) fn guard_master_delete_or_rotate(
    target: &api_key::Model,
    operation: &str,
) -> Result<(), AppError> {
    if target.is_master {
        return Err(AppError::Forbidden(format!("The Master key cannot be {operation} through the API")));
    }
    Ok(())
}

/// Refuses a `PUT /api/keys/{id}` update to the Master key's `name` or `can_manage_keys`. The one
/// field the Master's own record may still change through this route is `bound_ips` (`AGENT.MD`:
/// the Master key is immutable through the API except for its own network binding) — callers pass
/// only whether `name`/`can_manage_keys` are *present* in the request, not their values, since even
/// a no-op resubmission of the Master's current name must still be refused: this endpoint is not
/// the place to distinguish "no real change" from "no permitted change".
///
/// `is_master` itself needs no check here: it is not a field on `UpdateKeyPayload` at all, so it
/// can never reach this far regardless of which key is targeted.
pub(crate) fn guard_master_update(
    target: &api_key::Model,
    name_present: bool,
    can_manage_keys_present: bool,
) -> Result<(), AppError> {
    if target.is_master && (name_present || can_manage_keys_present) {
        return Err(AppError::Forbidden(
            "The Master key is immutable through the API except for its own bound_ips".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn key(is_master: bool) -> api_key::Model {
        api_key::Model {
            id: Uuid::new_v4(),
            name: "test key".to_owned(),
            prefix: "abcdefgh".to_owned(),
            key_hash: "hash".to_owned(),
            signing_secret: None,
            bound_ips: None,
            is_master,
            can_manage_keys: is_master,
            parent_key_id: None,
            owner_key_id: None,
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }

    #[test]
    fn require_master_accepts_master_and_refuses_daughter() {
        assert!(require_master(&key(true)).is_ok());
        assert!(require_master(&key(false)).is_err());
    }

    #[test]
    fn guard_master_delete_or_rotate_refuses_master_only() {
        assert!(guard_master_delete_or_rotate(&key(true), "deleted").is_err());
        assert!(guard_master_delete_or_rotate(&key(false), "deleted").is_ok());
    }

    #[test]
    fn guard_master_update_allows_bound_ips_only_but_refuses_name_and_can_manage_keys() {
        assert!(guard_master_update(&key(true), false, false).is_ok(), "no restricted field present must pass");
        assert!(guard_master_update(&key(true), true, false).is_err(), "a present name must be refused");
        assert!(
            guard_master_update(&key(true), false, true).is_err(),
            "a present can_manage_keys must be refused"
        );
        assert!(guard_master_update(&key(false), true, true).is_ok(), "a Daughter key has no such restriction");
    }
}
