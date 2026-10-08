use serde::{Deserialize, Serialize};

/// Timestamp helper: current wall clock in epoch milliseconds as `f64`.
pub fn now_ms_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0)
}

/// Epoch milliseconds as a signed `i64` (for DB columns).
pub fn now_ms_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A single structured log line.
///
/// Wire shape (frontend contract):
/// ```json
/// { "ts": 1720524000000, "level": "WARN", "ip": "203.0.113.9", "route": "/login", "msg": "..." }
/// ```
/// `ts == 0` means "assign server time on ingest". `level` is accepted
/// case-insensitively and normalized to `DEBUG|INFO|WARN|ERROR|CRITICAL`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogEvent {
    #[serde(default)]
    pub ts: f64,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub route: String,
    #[serde(default)]
    pub msg: String,
}

impl LogEvent {
    /// Normalize a raw ingest event: stamp the server time when the client
    /// left `ts == 0`, and coerce the level into the canonical uppercase set.
    pub fn normalize(&mut self, server_now_ms: f64) {
        if self.ts <= 0.0 {
            self.ts = server_now_ms;
        }
        let trimmed = self.level.trim().to_uppercase();
        self.level = match trimmed.as_str() {
            "DEBUG" | "INFO" | "WARN" | "ERROR" | "CRITICAL" => trimmed,
            _ => "INFO".to_string(),
        };
    }
}

/// Accepts either a single `LogEvent` or a batch wrapped as `{ "events": [...] }`.
#[derive(Clone, Debug, Deserialize)]
pub struct IngestRequest {
    #[serde(default)]
    pub events: Option<Vec<LogEvent>>,
}

/// The canonical severities understood by the SOC threat table.
pub const SEVERITIES: [&str; 4] = ["low", "medium", "high", "critical"];

/// Normalize an incoming severity string; anything unknown becomes `medium`.
pub fn normalize_severity(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    if SEVERITIES.contains(&lower.as_str()) {
        lower
    } else {
        "medium".to_string()
    }
}

/// Payload of `POST /api/v1/threats`.
///
/// `id` is the *frontend-generated* id (the UI assigns it before posting); the
/// backend assigns its own auto-increment row id and keeps the frontend's in
/// `frontend_id`.
#[derive(Clone, Debug, Deserialize)]
pub struct ThreatInput {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub ts_ms: f64,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub origin: String,
}

/// A threat as served back out of the persistence layer.
#[derive(Clone, Debug, Serialize)]
pub struct Threat {
    pub id: i64,
    pub frontend_id: u64,
    pub ts_ms: f64,
    pub severity: String,
    pub rule_id: String,
    pub rule_name: String,
    pub ip: String,
    pub payload: String,
    pub origin: String,
    pub received_at: i64,
}