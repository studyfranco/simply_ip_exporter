//! Single-use enforcement for `CANONICAL_V1` signatures on `/api/*`.
//!
//! The `X-Timestamp` window bounds how long a captured request stays valid; it does nothing about
//! the same request being replayed more than once inside that window. [`ReplayGuard`] closes that
//! gap by remembering which signatures have already been accepted. A signature is only ever
//! recorded **after** verification, so filling the map requires the signing secret.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

/// How often expired entries are swept, as a fraction of the replay window.
const PRUNE_INTERVAL_DIVISOR: u32 = 4;
/// Minimum spacing between capacity-triggered sweeps, as a fraction of the replay window.
const CAPACITY_BACKOFF_DIVISOR: u32 = 16;
/// Hard ceiling on tracked signatures, past which the guard sweeps early rather than flush.
const MAX_TRACKED_SIGNATURES: usize = 250_000;

/// Identifies one accepted signature: the key that signed it, plus the raw digest bytes.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct SignatureId {
    key_id: Uuid,
    digest: Vec<u8>,
}

#[derive(Debug)]
struct PruneSchedule {
    next: Instant,
    next_capacity: Instant,
}

/// Remembers recently accepted signatures so none is honoured twice. Shared through
/// [`crate::state::AppState`].
#[derive(Debug)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<SignatureId, Instant>>,
    schedule: Mutex<PruneSchedule>,
    window: Duration,
    prune_interval: Duration,
    capacity_backoff: Duration,
}

impl ReplayGuard {
    /// Builds a guard remembering signatures for `window_seconds`, clamped into a sane range.
    pub fn new(window_seconds: i64) -> Self {
        let window = Duration::from_secs(window_seconds.clamp(1, 3600) as u64);
        let prune_interval = window / PRUNE_INTERVAL_DIVISOR;
        let capacity_backoff = window / CAPACITY_BACKOFF_DIVISOR;
        let now = Instant::now();
        Self {
            seen: Mutex::new(HashMap::new()),
            schedule: Mutex::new(PruneSchedule { next: now + prune_interval, next_capacity: now }),
            window,
            prune_interval,
            capacity_backoff,
        }
    }

    /// Records a verified signature, reporting whether it had already been used. Call only after
    /// the signature has been verified.
    pub fn check_and_record(&self, key_id: Uuid, digest: &[u8]) -> bool {
        let now = Instant::now();
        self.prune_if_due(now);

        let Ok(mut seen) = self.seen.lock() else {
            tracing::error!("Replay guard lock is poisoned; rejecting rather than accepting");
            return false;
        };

        let id = SignatureId { key_id, digest: digest.to_vec() };
        match seen.get(&id) {
            Some(expires_at) if *expires_at > now => false,
            _ => {
                seen.insert(id, now + self.window);
                true
            }
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }

    fn prune_if_due(&self, now: Instant) {
        let over_capacity = self.seen.lock().is_ok_and(|seen| seen.len() >= MAX_TRACKED_SIGNATURES);

        {
            let Ok(mut schedule) = self.schedule.lock() else { return };
            let routine_due = now >= schedule.next;
            let capacity_due = over_capacity && now >= schedule.next_capacity;
            if !routine_due && !capacity_due {
                return;
            }
            schedule.next = now + self.prune_interval;
            if capacity_due {
                schedule.next_capacity = now + self.capacity_backoff;
            }
        }

        let Ok(mut seen) = self.seen.lock() else { return };
        seen.retain(|_, expires_at| *expires_at > now);

        if seen.len() >= MAX_TRACKED_SIGNATURES {
            tracing::warn!(
                tracked = seen.len(),
                ceiling = MAX_TRACKED_SIGNATURES,
                "Replay guard is at capacity: a client is signing faster than the window expires \
                 entries. Replay protection remains enforced."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn a_signature_is_accepted_once_and_refused_afterwards() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();
        assert!(guard.check_and_record(key, &digest(1)));
        assert!(!guard.check_and_record(key, &digest(1)));
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let guard = ReplayGuard::new(300);
        let key_a = Uuid::new_v4();
        let key_b = Uuid::new_v4();
        assert!(guard.check_and_record(key_a, &digest(1)));
        assert!(guard.check_and_record(key_b, &digest(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn entries_expire_and_are_swept() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();
        assert!(guard.check_and_record(key, &digest(1)));
        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(guard.check_and_record(key, &digest(1)));
        assert_eq!(guard.tracked(), 1);
    }

    #[test]
    fn a_nonsensical_window_is_clamped_rather_than_disabling_the_guard() {
        let key = Uuid::new_v4();
        for window in [0, -1, i64::MIN, i64::MAX] {
            let guard = ReplayGuard::new(window);
            assert!(guard.check_and_record(key, &digest(7)));
            assert!(!guard.check_and_record(key, &digest(7)));
        }
    }
}
