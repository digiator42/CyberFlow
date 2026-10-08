//! Ingestion pipeline — the single funnel every log event flows through,
//! whether it arrived over SSE or from a local file drop.
//!
//! Per batch it runs the detection engine, appends capped terminal rows,
//! raises threat incidents (side panel + flash toast + backend sync), and
//! bumps the hot-path metric counters.

use crate::api;
use crate::detection::Detection as DetectionHit;
use crate::state::{
    AppState, LogEntry, LogEvent, LogLevel, Threat, RAW_KEEP, RAW_TRIM_AT, THREAT_KEEP, TOAST_KEEP,
    TOAST_TTL_MS,
};

/// Run one batch of events through detection + state.
///
/// `origin` attributes the batch (`"live"` or `"file:<name>"`) and is stamped
/// onto every row and threat it produces.
pub fn ingest_events(app: &AppState, origin: &str, events: Vec<LogEvent>) {
    if events.is_empty() {
        return;
    }

    // ---- 0. Stamp missing timestamps up-front so detection (rate windows)
    //         and the terminal both see real times. `js_sys::Date::now()` is
    //         only called on wasm; host-side unit tests never touch it.
    let events: Vec<LogEvent> = events
        .into_iter()
        .map(|mut ev| {
            if ev.ts <= 0.0 {
                ev.ts = js_sys::Date::now();
            }
            ev
        })
        .collect();

    // ---- 1. Detect (borrow the detector once for the whole batch) --------
    let mut flagged: Vec<(LogEvent, DetectionHit)> = Vec::new();
    {
        let mut detector = app.detector.borrow_mut();
        for ev in &events {
            for hit in detector.inspect(ev) {
                flagged.push((ev.clone(), hit));
            }
        }
    }

    // ---- 2. Append terminal rows in one notification ----------------------
    let count = events.len() as u32;
    app.logs.with_mut(|v| {
        for ev in events {
            let level = LogLevel::parse(&ev.level);
            let haystack = format!("{} {} {}", ev.ip, ev.route, ev.msg).to_ascii_lowercase();
            v.push(LogEntry {
                id: app.metrics.next_row_id(),
                ts_ms: ev.ts,
                level,
                ip: ev.ip,
                route: ev.route,
                msg: crate::state::truncate_chars(&ev.msg, 500),
                source: origin.to_string(),
                haystack,
            });
        }
        // Batched raw-buffer eviction (see RAW_TRIM_AT).
        if v.len() > RAW_TRIM_AT {
            let excess = v.len() - RAW_KEEP;
            v.drain(..excess);
        }
    });

    app.metrics
        .window_logs
        .set(app.metrics.window_logs.get().saturating_add(count));

    // ---- 3. Promote detections to threat incidents ------------------------
    for (ev, hit) in flagged {
        raise_threat(
            app,
            Threat {
                id: app.metrics.next_row_id(),
                ts_ms: ev.ts,
                severity: hit.severity,
                rule_id: hit.rule_id.to_string(),
                rule_name: hit.title.to_string(),
                ip: ev.ip.clone(),
                payload: crate::state::truncate_chars(&ev.msg, 200),
                origin: origin.to_string(),
            },
        );
    }
}

/// Push a threat into the panel, flash a toast, and sync it to GritShield.
fn raise_threat(app: &AppState, threat: Threat) {
    // Side panel — newest first, capped.
    app.threats.with_mut(|v| {
        v.insert(0, threat.clone());
        v.truncate(THREAT_KEEP);
    });

    // Flash toast — cap the stack, then schedule auto-dismissal.
    app.toasts.with_mut(|v| {
        v.push(threat.clone());
        if v.len() > TOAST_KEEP {
            let excess = v.len() - TOAST_KEEP;
            v.drain(..excess);
        }
    });
    let toast_id = threat.id;
    let toasts = app.toasts.clone();
    wasm_bindgen_futures::spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(TOAST_TTL_MS).await;
        toasts.with_mut(|v| v.retain(|t| t.id != toast_id));
    });

    app.metrics.threat_count.update(|c| *c += 1);

    // Fire-and-forget backend sync; local state never depends on the result.
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(err) = api::post_threat(&threat).await {
            web_sys::console::warn_1(
                &format!("threat sync failed (backend offline?): {err}").into(),
            );
        }
    });
}

/// Dismiss a flash alert early (user clicked the ×).
pub fn dismiss_threat(app: &AppState, id: u64) {
    app.toasts.with_mut(|v| v.retain(|t| t.id != id));
}

// ---------------------------------------------------------------------------
// Local file line parsing
// ---------------------------------------------------------------------------

/// Best-effort parsing of an unstructured log line into a [`LogEvent`].
///
/// Handles Nginx/Apache/CloudTrail-ish text: picks the first IPv4-shaped
/// token as the source IP, guesses the level from keywords, and extracts a
/// `METHOD /path` route when present. Everything else stays in `msg`.
///
/// `ts` is left at `0` ("assign on ingest") so this function stays free of
/// wasm imports and is unit-testable on the host; [`ingest_events`] stamps
/// the wall clock before detection runs.
pub fn parse_raw_line(line: &str) -> Option<LogEvent> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    Some(LogEvent {
        ts: 0.0,
        level: LogLevel::from_line(line).as_str().to_string(),
        ip: extract_ip(line).unwrap_or_default(),
        route: extract_route(line).unwrap_or_default(),
        msg: line.to_string(),
        ..Default::default()
    })
}

/// First token that looks like an IPv4 address (`a.b.c.d`, each ≤ 3 digits).
fn extract_ip(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace() || c == '"' || c == '[' || c == ']' || c == ',')
        .find(|tok| {
            let parts: Vec<&str> = tok.split('.').collect();
            parts.len() == 4
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(|s| s.to_string())
}

/// `GET /api/v1/login` → `/api/v1/login`.
///
/// Quoted variants from access logs (`"GET /path HTTP/1.1"`) are unquoted
/// before matching.
fn extract_route(line: &str) -> Option<String> {
    const METHODS: [&str; 6] = ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"];
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens.windows(2).find_map(|w| {
        let method = w[0].trim_matches('"');
        let path = w[1].trim_end_matches(|c| c == ',' || c == '"');
        if METHODS.contains(&method) && path.starts_with('/') {
            Some(path.to_string())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_style_line() {
        let ev = parse_raw_line(
            r#"198.51.100.44 - - [08/Oct/2026:12:00:01] "GET /admin/login HTTP/1.1" 200 512 "-""#,
        )
        .unwrap();
        assert_eq!(ev.ip, "198.51.100.44");
        assert_eq!(ev.route, "/admin/login");
        assert_eq!(ev.level, "INFO");
    }

    #[test]
    fn parses_error_level_from_text() {
        let ev = parse_raw_line("2026-10-08 ERROR database connection refused").unwrap();
        assert_eq!(ev.level, "ERROR");
    }

    #[test]
    fn skips_blank_lines() {
        assert!(parse_raw_line("   ").is_none());
    }

    #[test]
    fn leaves_line_without_ipv4_untouched() {
        let ev = parse_raw_line("backend health check ok").unwrap();
        assert_eq!(ev.ip, "");
        assert!(ev.msg.contains("health check ok"));
    }
}
