//! Per-route request-rate limiting (`RouteRateLimiter`).
//!
//! A `RouteRateLimiter` caps the rate of L7 HTTP requests the proxy forwards to
//! a single route's upstream, containing a runaway or compromised agent. It is a
//! security containment control, so it fails closed.
//!
//! ## Algorithm
//!
//! A token bucket refills continuously at `requests_per_minute` and holds up to
//! `burst` tokens. On each request:
//!
//! * a token is available -> proceed immediately;
//! * the bucket is empty -> the request is *delayed* until a token accrues, but
//!   only if that wait is within `max_delay`. A request that would wait longer
//!   is **rejected** (the caller returns HTTP 429). Reserving a token drives the
//!   token count negative, and the `max_delay` bound caps how negative it can go
//!   — so the implicit delay queue is always bounded and the proxy cannot be
//!   pushed into a self-inflicted denial of service.
//!
//! This is the nginx `limit_req ... burst / delay` model. See
//! `docs/adr/0001-route-rate-limiter-bounded-throttle-then-reject.md` for why
//! overload is a bounded delay then reject, never a human approval and never an
//! unbounded wait.
//!
//! ## Scope
//!
//! The limiter only acts where the proxy can see individual requests:
//! reverse-proxy routes and TLS-intercepted CONNECT. It has **no effect** on an
//! opaque CONNECT tunnel (no interception), where the proxy sees one TCP stream
//! and cannot count requests.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Outcome of a rate-limit acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateLimitDecision {
    /// A token was available or reserved within the delay bound. When `delay`
    /// is non-zero the caller must wait that long before forwarding.
    Proceed { delay: Duration },
    /// The bucket is empty and a token cannot be reserved within `max_delay`.
    /// The caller must reject the request with HTTP 429.
    Reject,
}

#[derive(Debug)]
struct Bucket {
    /// Current token count. May be negative when tokens are reserved for
    /// delayed requests; bounded below by `-refill_per_sec * max_delay`.
    tokens: f64,
    last_refill: Instant,
}

/// Per-route token-bucket request-rate limiter with a bounded delay queue.
#[derive(Debug)]
pub struct RouteRateLimiter {
    /// Maximum token count (burst capacity), always >= 1.
    capacity: f64,
    /// Token refill rate, in tokens per second (`requests_per_minute / 60`).
    refill_per_sec: f64,
    /// Longest a request may be delayed before it is rejected.
    max_delay: Duration,
    bucket: Mutex<Bucket>,
}

impl RouteRateLimiter {
    /// Build a limiter, or `None` when `requests_per_minute` is 0 (disabled).
    ///
    /// `burst` is clamped to at least 1 so a single request can always pass on
    /// an otherwise-idle route.
    pub(crate) fn new(requests_per_minute: u32, burst: u32, max_delay: Duration) -> Option<Self> {
        if requests_per_minute == 0 {
            return None;
        }
        let capacity = f64::from(burst.max(1));
        Some(Self {
            capacity,
            refill_per_sec: f64::from(requests_per_minute) / 60.0,
            max_delay,
            bucket: Mutex::new(Bucket {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        })
    }

    /// Try to consume one token for a request.
    ///
    /// Returns [`RateLimitDecision::Proceed`] (possibly with a delay the caller
    /// must await) or [`RateLimitDecision::Reject`]. Non-blocking: any waiting is
    /// performed by the caller so the internal lock is never held across an
    /// `await`.
    pub(crate) fn acquire(&self) -> RateLimitDecision {
        self.acquire_at(Instant::now())
    }

    /// [`Self::acquire`] with an explicit clock reading, for deterministic tests.
    fn acquire_at(&self, now: Instant) -> RateLimitDecision {
        // A poisoned lock means a previous holder panicked. The critical section
        // below is panic-free arithmetic, so recover the guard rather than
        // permanently bricking a route (which would itself be a DoS).
        let mut bucket = match self.bucket.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.last_refill = now;
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateLimitDecision::Proceed {
                delay: Duration::ZERO,
            };
        }

        // Bucket empty: how long until one token accrues for this request?
        let deficit = 1.0 - bucket.tokens; // strictly positive
        let wait_secs = deficit / self.refill_per_sec;
        if wait_secs > self.max_delay.as_secs_f64() {
            return RateLimitDecision::Reject;
        }

        // Reserve the token; `tokens` goes (further) negative but stays bounded
        // because the next request past `max_delay` worth of reservations is
        // rejected above.
        bucket.tokens -= 1.0;
        RateLimitDecision::Proceed {
            delay: Duration::from_secs_f64(wait_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_zero_rpm() {
        assert!(RouteRateLimiter::new(0, 5, Duration::from_secs(5)).is_none());
    }

    #[test]
    fn burst_clamped_to_at_least_one() {
        let limiter = RouteRateLimiter::new(60, 0, Duration::from_secs(0))
            .expect("limiter should be enabled");
        // A single request on an idle route passes even with burst 0.
        assert_eq!(
            limiter.acquire(),
            RateLimitDecision::Proceed {
                delay: Duration::ZERO
            }
        );
    }

    #[test]
    fn allows_up_to_burst_instantly() {
        let limiter = RouteRateLimiter::new(60, 5, Duration::from_secs(0)).expect("enabled");
        let start = Instant::now();
        for _ in 0..5 {
            assert_eq!(
                limiter.acquire_at(start),
                RateLimitDecision::Proceed {
                    delay: Duration::ZERO
                }
            );
        }
    }

    #[test]
    fn rejects_when_burst_exhausted_and_no_delay_budget() {
        // 60 rpm = 1 token/sec, burst 2, no delay allowed.
        let limiter = RouteRateLimiter::new(60, 2, Duration::from_secs(0)).expect("enabled");
        let start = Instant::now();
        assert!(matches!(
            limiter.acquire_at(start),
            RateLimitDecision::Proceed { .. }
        ));
        assert!(matches!(
            limiter.acquire_at(start),
            RateLimitDecision::Proceed { .. }
        ));
        // Third request within the same instant: bucket empty, zero delay budget.
        assert_eq!(limiter.acquire_at(start), RateLimitDecision::Reject);
    }

    #[test]
    fn delays_within_budget_then_rejects_beyond_it() {
        // 60 rpm = 1 token/sec, burst 1, up to 5s of delay.
        let limiter = RouteRateLimiter::new(60, 1, Duration::from_secs(5)).expect("enabled");
        let start = Instant::now();

        // First consumes the single burst token.
        assert_eq!(
            limiter.acquire_at(start),
            RateLimitDecision::Proceed {
                delay: Duration::ZERO
            }
        );

        // Next requests are delayed by ~1s, ~2s, ... as tokens are reserved.
        match limiter.acquire_at(start) {
            RateLimitDecision::Proceed { delay } => {
                assert!((delay.as_secs_f64() - 1.0).abs() < 1e-6, "delay={delay:?}");
            }
            other => panic!("expected delayed proceed, got {other:?}"),
        }
        match limiter.acquire_at(start) {
            RateLimitDecision::Proceed { delay } => {
                assert!((delay.as_secs_f64() - 2.0).abs() < 1e-6, "delay={delay:?}");
            }
            other => panic!("expected delayed proceed, got {other:?}"),
        }

        // Reservations now total ~3s..5s..; once the projected wait exceeds the
        // 5s bound, further requests are rejected rather than queued unboundedly.
        let mut rejected = false;
        for _ in 0..10 {
            if limiter.acquire_at(start) == RateLimitDecision::Reject {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "queue must be bounded by max_delay");
    }

    #[test]
    fn refills_over_time() {
        // 60 rpm = 1 token/sec, burst 1, no delay.
        let limiter = RouteRateLimiter::new(60, 1, Duration::from_secs(0)).expect("enabled");
        let start = Instant::now();
        assert!(matches!(
            limiter.acquire_at(start),
            RateLimitDecision::Proceed { .. }
        ));
        assert_eq!(limiter.acquire_at(start), RateLimitDecision::Reject);
        // One second later a token has refilled.
        let later = start + Duration::from_secs(1);
        assert_eq!(
            limiter.acquire_at(later),
            RateLimitDecision::Proceed {
                delay: Duration::ZERO
            }
        );
    }

    #[test]
    fn refill_capped_at_capacity() {
        // Idle for a long time must not accumulate more than `burst` tokens.
        let limiter = RouteRateLimiter::new(60, 3, Duration::from_secs(0)).expect("enabled");
        let start = Instant::now();
        let much_later = start + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(matches!(
                limiter.acquire_at(much_later),
                RateLimitDecision::Proceed { .. }
            ));
        }
        assert_eq!(limiter.acquire_at(much_later), RateLimitDecision::Reject);
    }
}
