//! Client-side threat detection engine.
//!
//! Runs entirely in the browser (later: inside a Web Worker) so raw log data
//! never leaves the machine. Only the [`crate::state::Threat] incidents it
//! produces are synced back to GritShield.
//!
//! Everything in this module is pure `std` Rust — no `web-sys`, no signals —
//! so it compiles and tests natively on the host (`cargo test -p
//! gritshield-soc`).

pub mod entropy;
pub mod rate;
pub mod signatures;

use serde::{Deserialize, Serialize};

use crate::state::LogEvent;

/// How bad a finding is. Serialized to the GritShield threat database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// CSS modifier for cards, chips, and toasts.
    pub fn css(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A single rule hit, before it is promoted to a persisted threat incident.
#[derive(Clone, Debug)]
pub struct Detection {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
}

/// Wire form of a [`Detection`], carrying the index of the offending event in
/// its batch. The Web Worker posts batches of these back to the main thread,
/// so every field is owned and the type is (de)serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleHit {
    /// Index into the batch's `events` vector.
    pub index: usize,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
}

/// Stateful detector: signature + entropy checks are stateless, but the
/// sliding-window rate check needs to remember per-IP history between events.
pub struct Detector {
    rates: rate::RateTracker,
}

impl Detector {
    pub fn new() -> Self {
        Self {
            rates: rate::RateTracker::new(),
        }
    }

    /// Inspect one event and return every rule it trips.
    pub fn inspect(&mut self, ev: &LogEvent) -> Vec<Detection> {
        let mut hits = signatures::scan(&ev.msg);
        hits.extend(entropy::check(&ev.msg));

        if self.rates.register(&ev.ip, ev.ts) {
            hits.push(Detection {
                rule_id: "rate.credential_stuffing",
                title: "Request burst from a single IP",
                severity: Severity::High,
            });
        }

        hits
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(msg: &str) -> LogEvent {
        LogEvent {
            ts: 1_000.0,
            level: "INFO".into(),
            ip: "203.0.113.7".into(),
            route: "/api/login".into(),
            msg: msg.into(),
        }
    }

    #[test]
    fn clean_log_produces_no_hits() {
        let mut d = Detector::new();
        assert!(d.inspect(&event("GET /health 200 OK in 4ms")).is_empty());
    }

    #[test]
    fn sqli_trips_signature() {
        let mut d = Detector::new();
        let hits = d.inspect(&event("user=admin' OR 1=1--"));
        assert!(hits.iter().any(|h| h.rule_id == "sqli.boolean"));
        assert_eq!(hits[0].severity, Severity::Critical);
    }

    #[test]
    fn traversal_trips_signature() {
        let mut d = Detector::new();
        let hits = d.inspect(&event("GET /static/../../../etc/passwd 200"));
        assert!(hits.iter().any(|h| h.rule_id == "traversal.path"));
    }

    #[test]
    fn scanner_ua_trips_signature() {
        let mut d = Detector::new();
        let hits = d.inspect(&event("sqlmap/1.7.2#stable (https://sqlmap.org)"));
        assert!(hits.iter().any(|h| h.rule_id == "scanner.tool"));
    }

    #[test]
    fn rate_burst_trips_after_threshold() {
        let mut d = Detector::new();
        let mut fired = false;
        // 25 rapid requests from one IP inside a 10s window.
        for i in 0..25 {
            let mut ev = event("POST /api/login 401");
            ev.ts = 1_000.0 + i as f64 * 100.0;
            fired |= d
                .inspect(&ev)
                .iter()
                .any(|h| h.rule_id == "rate.credential_stuffing");
        }
        assert!(fired, "expected rate detection during the burst");
    }

    #[test]
    fn rate_burst_is_rate_limited_by_cooldown() {
        let mut d = Detector::new();
        let mut fired = 0;
        for i in 0..60 {
            let mut ev = event("POST /api/login 401");
            ev.ts = 1_000.0 + i as f64 * 100.0;
            if d.inspect(&ev)
                .iter()
                .any(|h| h.rule_id == "rate.credential_stuffing")
            {
                fired += 1;
            }
        }
        // 6 seconds of sustained burst → at most a couple of alerts, not 40.
        assert!(fired <= 2, "fired {fired} alerts for one burst");
    }
}
