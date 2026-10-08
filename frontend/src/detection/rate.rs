//! Sliding-window request-rate tracking per source IP.
//!
//! Flags credential stuffing / brute force: many requests from one IP inside
//! a short window, with a cooldown so a sustained attack produces a steady
//! drip of alerts instead of one per request.

use std::collections::{HashMap, VecDeque};

/// Rolling window length in milliseconds.
pub const WINDOW_MS: f64 = 10_000.0;
/// Requests from one IP within the window before it counts as a burst.
pub const BURST_LIMIT: usize = 20;
/// Minimum milliseconds between two alerts for the same IP.
pub const ALERT_COOLDOWN_MS: f64 = 30_000.0;

#[derive(Default)]
pub struct RateTracker {
    /// ip → timestamps (ms) inside the rolling window.
    hits: HashMap<String, VecDeque<f64>>,
    /// ip → last alert timestamp (ms), for cooldown.
    last_alert: HashMap<String, f64>,
}

impl RateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one request for `ip` at `ts` (epoch ms).
    ///
    /// Returns `true` when the burst threshold is crossed *and* the per-IP
    /// alert cooldown has elapsed. Events without a usable IP are ignored —
    /// an aggregate rate alert is useless without an attribution target.
    pub fn register(&mut self, ip: &str, ts: f64) -> bool {
        let ip = ip.trim();
        if ip.is_empty() || ip == "-" || ts <= 0.0 {
            return false;
        }

        let window = self.hits.entry(ip.to_string()).or_default();
        window.push_back(ts);
        // Drop timestamps that fell out of the window.
        while window.front().is_some_and(|&t| ts - t > WINDOW_MS) {
            window.pop_front();
        }

        if window.len() < BURST_LIMIT {
            return false;
        }

        let last = self.last_alert.get(ip).copied().unwrap_or(f64::MIN);
        if ts - last < ALERT_COOLDOWN_MS {
            return false;
        }
        self.last_alert.insert(ip.to_string(), ts);

        // Opportunistic cleanup so long sessions don't accumulate dead IPs.
        if self.hits.len() > 4_096 {
            self.hits
                .retain(|_, w| w.back().is_some_and(|&t| ts - t <= WINDOW_MS));
            if self.last_alert.len() > 4_096 {
                self.last_alert
                    .retain(|_, &mut t| ts - t <= ALERT_COOLDOWN_MS);
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_traffic_below_limit_never_alerts() {
        let mut r = RateTracker::new();
        for i in 0..19 {
            assert!(!r.register("198.51.100.9", 1_000.0 + i as f64 * 500.0));
        }
    }

    #[test]
    fn burst_crossing_limit_alerts_once() {
        let mut r = RateTracker::new();
        let mut fired = 0;
        for i in 0..BURST_LIMIT + 5 {
            if r.register("198.51.100.9", 1_000.0 + i as f64 * 100.0) {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "one burst → exactly one alert");
    }

    #[test]
    fn distinct_ips_are_tracked_independently() {
        let mut r = RateTracker::new();
        // The burst fires on the BURST_LIMIT-th request from one IP…
        for i in 0..BURST_LIMIT - 1 {
            assert!(!r.register("10.0.0.1", 1_000.0 + i as f64 * 100.0));
        }
        assert!(r.register("10.0.0.1", 1_000.0 + (BURST_LIMIT - 1) as f64 * 100.0));
        // …while a different IP starts with a clean slate.
        assert!(!r.register("10.0.0.2", 2_900.0));
    }

    #[test]
    fn old_requests_expire_out_of_the_window() {
        let mut r = RateTracker::new();
        for i in 0..BURST_LIMIT - 1 {
            r.register("10.0.0.3", 1_000.0 + i as f64 * 100.0);
        }
        // Jump far past the window: history is empty again, so no alert.
        assert!(!r.register("10.0.0.3", 1_000.0 + WINDOW_MS + 5_000.0));
    }

    #[test]
    fn missing_ip_is_ignored() {
        let mut r = RateTracker::new();
        assert!(!r.register("", 1_000.0));
        assert!(!r.register("-", 1_000.0));
        assert!(!r.register("10.0.0.4", 0.0));
    }
}
