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
/// Eviction is oldest-*first-seen*-first once [`MAX_TRACKED_IPS`] is reached — a FIFO over
/// distinct IPs, not a true LRU. `order` records the position of a caller's *first* request only;
/// a caller re-allowed after its window lapses is not moved to the back of the queue on that
/// later request. Doing so would mean pushing an entry on every call, including repeat calls from
/// an address already tracked — and since eviction only fires once the map is genuinely at
/// capacity, an address that is reused far more often than the map ever fills would accumulate an
/// unbounded number of queue entries for itself alone, long before eviction ever had a reason to
/// look at them. That is the actual failure mode this type has to resist in production: not a
/// wide flood of distinct IPs (which fills the map and triggers eviction correctly regardless),
/// but a single legitimate, indefinitely-long-lived poller. The tradeoff is a queue that can evict
/// a since-reused address ahead of a truly stale one under sustained capacity pressure — cheaper
/// than perfect recency, and irrelevant to what this bound exists to guarantee: `order.len()`
/// never exceeds the map it accompanies.
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

        let is_new = !inner.next_allowed.contains_key(&ip);

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
        // Only a genuinely new key gets a queue entry — see the type's doc comment for why
        // re-pushing on every re-allow of an already-tracked IP would leak unboundedly instead.
        if is_new {
            inner.order.push_back(ip);
        }
        Ok(())
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.state.lock().map(|i| i.next_allowed.len()).unwrap_or(0)
    }

    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.state.lock().map(|i| i.order.len()).unwrap_or(0)
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

    /// A flood of 50,000 distinct source IPs — five times the ceiling — must still leave both the
    /// tracked-IP map AND its eviction queue bounded at `MAX_TRACKED_IPS`. `AGENT.MD` requires this
    /// specifically as protection "under IP spoofing attacks", where every request names a fresh
    /// address on purpose.
    #[test]
    fn a_flood_of_over_ten_thousand_distinct_ips_stays_bounded() {
        let limiter = RateLimiter::new();
        for n in 0..50_000u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(n));
            assert!(limiter.check_and_record(addr).is_ok(), "a first-ever request from any IP is always allowed");
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_IPS, "the map must sit exactly at the ceiling");
        assert_eq!(limiter.order_len(), MAX_TRACKED_IPS, "the eviction queue must not outgrow the map");
    }

    /// Eviction actually removes the *earliest-seen* addresses, not an arbitrary or empty set —
    /// bounded memory is only half the guarantee; the other half is that a caller pushed out by
    /// the flood is genuinely re-throttleable as a "new" IP rather than stuck in limbo.
    #[test]
    fn eviction_forgets_the_oldest_ips_first_and_keeps_the_newest() {
        let limiter = RateLimiter::new();
        for n in 0..MAX_TRACKED_IPS as u32 + 10 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(n));
            assert!(limiter.check_and_record(addr).is_ok());
        }

        // The first 10 IPs inserted were evicted to make room for the last 10, so they are no
        // longer throttled — a fresh request from one succeeds exactly as if it were unseen.
        for n in 0..10u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(n));
            assert!(limiter.check_and_record(addr).is_ok(), "IP {n} should have been evicted");
        }

        // The most recently inserted IP is still within its window and stays throttled.
        let newest = IpAddr::V4(std::net::Ipv4Addr::from(MAX_TRACKED_IPS as u32 + 9));
        assert!(limiter.check_and_record(newest).is_err(), "the newest IP must not have been evicted");
    }

    /// The companion leak this rate limiter is *actually* exposed to in production is not a wide
    /// flood of distinct IPs (which the test above covers) but the opposite: a single low-volume,
    /// perfectly legitimate caller (a pfBlockerNG poller hitting the feed every few minutes,
    /// forever) that keeps being re-allowed once its window lapses. The tracked-IP *map* handles
    /// this correctly by construction (re-inserting an existing key does not grow a `HashMap`), but
    /// the eviction queue is a separate structure that has to be told about it explicitly — and
    /// this asserts it actually is, across ten thousand simulated re-polls.
    #[tokio::test(start_paused = true)]
    async fn one_ip_polling_forever_past_its_window_does_not_grow_the_queue_without_bound() {
        let limiter = RateLimiter::new();
        let addr = ip(1);
        for _ in 0..10_000 {
            assert!(limiter.check_and_record(addr).is_ok());
            tokio::time::advance(RATE_LIMIT_WINDOW + Duration::from_secs(1)).await;
        }
        assert_eq!(limiter.tracked(), 1, "still exactly one IP tracked");
        assert_eq!(
            limiter.order_len(),
            1,
            "the eviction queue must hold one entry per *tracked* IP, not one per call — a queue \
             that grows on every re-poll of the same address is an unbounded allocation a single \
             well-behaved, indefinitely-long-lived client can trigger for free"
        );
    }
}
