//! In-memory anti-DoS rate limiter for the public feed endpoint: at most one request every two
//! minutes per source IP, tracked in a bounded structure so a spoofed-IP flood cannot grow memory
//! without limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Minimum spacing between requests from the same source IP.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(120);

/// Hard ceiling on the number of source IPs tracked at once.
pub const MAX_TRACKED_IPS: usize = 10_000;

/// Bounded, insertion-ordered map of "when this IP may next be served".
///
/// Eviction is oldest-first once [`MAX_TRACKED_IPS`] is reached, which is a close enough
/// approximation of LRU for this purpose: entries are only ever refreshed to "now", so the
/// insertion order the `HashMap` + queue combination tracks is also the recency order.
pub struct RateLimiter {
    state: Mutex<Inner>,
}

struct Inner {
    next_allowed: HashMap<IpAddr, Instant>,
    order: std::collections::VecDeque<IpAddr>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Builds an empty limiter.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Inner { next_allowed: HashMap::new(), order: Default::default() }),
        }
    }

    /// Checks whether `ip` may be served now, and if so records that it was.
    ///
    /// Returns `Ok(())` when the request may proceed, or `Err(remaining)` with the time left in
    /// the throttle window otherwise. A poisoned lock fails open toward rejecting the request
    /// rather than bypassing the limiter.
    pub fn check_and_record(&self, ip: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let Ok(mut inner) = self.state.lock() else {
            return Err(RATE_LIMIT_WINDOW);
        };

        if let Some(next_allowed) = inner.next_allowed.get(&ip) {
            if *next_allowed > now {
                return Err(*next_allowed - now);
            }
        } else if inner.next_allowed.len() >= MAX_TRACKED_IPS {
            // Evict the oldest tracked entry to make room, rather than refusing to track (and
            // thereby exempting) the new caller.
            while inner.next_allowed.len() >= MAX_TRACKED_IPS {
                let Some(oldest) = inner.order.pop_front() else { break };
                inner.next_allowed.remove(&oldest);
            }
        }

        inner.next_allowed.insert(ip, now + RATE_LIMIT_WINDOW);
        inner.order.push_back(ip);
        Ok(())
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.state.lock().map(|i| i.next_allowed.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, n))
    }

    #[test]
    fn first_request_is_allowed_second_is_throttled() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record(ip(1)).is_ok());
        assert!(limiter.check_and_record(ip(1)).is_err());
    }

    #[test]
    fn distinct_ips_do_not_interfere() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record(ip(1)).is_ok());
        assert!(limiter.check_and_record(ip(2)).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn allowed_again_after_the_window_elapses() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record(ip(1)).is_ok());
        tokio::time::advance(RATE_LIMIT_WINDOW + Duration::from_secs(1)).await;
        assert!(limiter.check_and_record(ip(1)).is_ok());
    }

    #[test]
    fn tracked_ips_are_capped() {
        let limiter = RateLimiter::new();
        for n in 0..MAX_TRACKED_IPS + 50 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(n as u32 + 1));
            let _ = limiter.check_and_record(addr);
        }
        assert!(limiter.tracked() <= MAX_TRACKED_IPS);
    }
}
