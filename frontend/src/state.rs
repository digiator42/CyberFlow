//! Reactive application state for the GritShield SOC console.
//!
//! One [`AppState`] value holds every signal the dashboard reads or writes.
//! It is provided once via `provide!` in `run_app` and pulled out of context
//! with `use_context::<AppState>()` inside components, so no component needs
//! to thread props through the tree.
//!
//! The module also owns the two **ingestion caps** and the derived-log
//! pipeline:
//!
//! ```text
//!  net::SSE ─┐                       ┌─ visible (capped, filter output)
//!            ├─► ingest_events ─► logs ┤        ▲
//!  files ───┘        │                └─ filter effect (level + query)
//!                     └─► detector ─► threats ─► toasts
//! ```

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use velo::prelude::*;

use crate::detection::{Detector, Severity};

// ---------------------------------------------------------------------------
// Buffer sizing
// ---------------------------------------------------------------------------

/// Raw log events retained in memory (the filter's source of truth).
pub const RAW_KEEP: usize = 800;
/// Raw buffer grows to this before being trimmed back to [`RAW_KEEP`].
pub const RAW_TRIM_AT: usize = 1000;

/// Rows kept in the terminal viewport after a trim.
pub const VISIBLE_KEEP: usize = 300;
/// Trim the terminal back to [`VISIBLE_KEEP`] only when it grows past this.
///
/// Evicting rows shifts every remaining row's position, which makes the keyed
/// reconciler re-move the whole list. Trimming in batches of
/// `VISIBLE_TRIM_AT - VISIBLE_KEEP` rows amortizes that cost to ~once per 60
/// pushes instead of once per push.
pub const VISIBLE_TRIM_AT: usize = 360;

/// Threat incidents retained in the side panel.
pub const THREAT_KEEP: usize = 200;
/// Flash alerts visible at once.
pub const TOAST_KEEP: usize = 5;
/// Milliseconds before a flash alert auto-dismisses.
pub const TOAST_TTL_MS: u32 = 6_000;

// ---------------------------------------------------------------------------
// Wire format — what GritShield's SSE stream POSTs to us
// ---------------------------------------------------------------------------

/// A single log event as delivered by `GET /api/v1/stream`.
///
/// Missing fields fall back to defaults so a noisy upstream producer can never
/// break the dashboard — an event without `ip`/`route` simply renders blank.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LogEvent {
    /// Epoch milliseconds. `0` means "assign on ingest".
    pub ts: f64,
    /// `DEBUG` | `INFO` | `WARN` | `ERROR` | `CRITICAL` (case-insensitive).
    pub level: String,
    pub ip: String,
    pub route: String,
    pub msg: String,
}

// ---------------------------------------------------------------------------
// Display enums
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Server-driven: SSE stream from GritShield.
    Live,
    /// Client-driven: local drag & drop file analysis.
    Local,
}

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Live => "LIVE STREAM",
            Mode::Local => "LOCAL FILES",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnStatus {
    Connecting,
    Open,
    Reconnecting,
    Closed,
}

impl ConnStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "CONNECTING",
            ConnStatus::Open => "STREAMING",
            ConnStatus::Reconnecting => "RECONNECTING",
            ConnStatus::Closed => "OFFLINE",
        }
    }

    /// CSS modifier for the status dot.
    pub fn css(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "connecting",
            ConnStatus::Open => "open",
            ConnStatus::Reconnecting => "reconnecting",
            ConnStatus::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

impl LogLevel {
    /// Parse a producer-supplied level string. Unknown levels collapse to `Info`.
    pub fn parse(s: &str) -> LogLevel {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "debug" | "trace" => LogLevel::Debug,
            "info" | "notice" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" | "err" => LogLevel::Error,
            "critical" | "crit" | "fatal" | "alert" | "emerg" | "emergency" => LogLevel::Critical,
            _ => LogLevel::Info,
        }
    }

    /// Heuristic level for raw (unstructured) file lines.
    pub fn from_line(line: &str) -> LogLevel {
        let l = line.to_ascii_lowercase();
        if l.contains("critical") || l.contains(" fatal") || l.contains("[crit]") {
            LogLevel::Critical
        } else if l.contains("error") || l.contains("[error]") || l.contains(" err ") {
            LogLevel::Error
        } else if l.contains("warn") {
            LogLevel::Warn
        } else if l.contains("debug") || l.contains("trace") {
            LogLevel::Debug
        } else {
            LogLevel::Info
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
        }
    }

    /// CSS modifier shared by log rows and level chips.
    pub fn css(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal row
// ---------------------------------------------------------------------------

/// One rendered terminal line. Built eagerly on ingest so the keyed `for`
/// body can hand owned values to `<LogRow>` without borrowing.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub id: u64,
    pub ts_ms: f64,
    pub level: LogLevel,
    pub ip: String,
    pub route: String,
    pub msg: String,
    /// `live` or `file:<name>` — where the event came from.
    pub source: String,
    /// Pre-lowercased search haystack so filtering never allocates per keystroke.
    pub haystack: String,
}

// ---------------------------------------------------------------------------
// Threat intelligence
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Threat {
    pub id: u64,
    pub ts_ms: f64,
    pub severity: Severity,
    pub rule_id: String,
    pub rule_name: String,
    pub ip: String,
    /// Snippet of the offending payload (truncated on creation).
    pub payload: String,
    pub origin: String,
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Metrics {
    /// Log events ingested in the last full second.
    pub logs_per_sec: RwSignal<u32>,
    /// Bytes processed in the last full second (file ingestion + SSE payload).
    pub bytes_per_sec: RwSignal<u32>,
    /// Highest sustained byte rate observed this session.
    pub peak_bytes_per_sec: RwSignal<u32>,
    /// Total log events ingested this session.
    pub total_logs: RwSignal<u32>,
    /// Total threat incidents raised this session.
    pub threat_count: RwSignal<u32>,
    /// Rolling `logs/sec` samples (newest last) feeding the sparkline.
    pub rate_history: RwSignal<Vec<f32>>,

    // Unsignalized counters, drained once per metrics tick. Ingestion hot
    // paths bump these instead of setting a signal 100×/sec.
    pub window_logs: Rc<Cell<u32>>,
    pub window_bytes: Rc<Cell<u32>>,
    /// Monotonic id source for log rows and threats.
    pub next_id: Rc<Cell<u64>>,
}

impl Metrics {
    /// Next unique id for a log row or threat incident.
    pub fn next_row_id(&self) -> u64 {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }
}

#[derive(Clone)]
pub struct Analysis {
    pub active: RwSignal<bool>,
    /// 0.0 – 1.0 byte-progress of the file currently being read.
    pub progress: RwSignal<f64>,
    pub file: RwSignal<String>,
    pub lines: RwSignal<u32>,
}

#[derive(Clone)]
pub struct AppState {
    pub mode: RwSignal<Mode>,
    pub conn: RwSignal<ConnStatus>,

    /// Raw ingested events (capped at [`RAW_KEEP`]).
    pub logs: SignalVec<LogEntry>,
    /// Filtered tail of `logs` actually rendered by the terminal.
    pub visible: SignalVec<LogEntry>,
    /// `None` = show every level.
    pub filter_level: RwSignal<Option<LogLevel>>,
    pub filter_query: RwSignal<String>,
    pub auto_scroll: RwSignal<bool>,

    pub threats: SignalVec<Threat>,
    /// Ephemeral flash alerts (auto-dismissed after [`TOAST_TTL_MS`]).
    pub toasts: SignalVec<Threat>,

    pub metrics: Metrics,
    pub analysis: Analysis,

    /// Sliding-window rate tracker shared by live + file ingestion.
    pub detector: Rc<RefCell<Detector>>,
}

impl AppState {
    pub fn new() -> Self {
        let metrics = Metrics {
            logs_per_sec: signal!(0u32),
            bytes_per_sec: signal!(0u32),
            peak_bytes_per_sec: signal!(0u32),
            total_logs: signal!(0u32),
            threat_count: signal!(0u32),
            rate_history: signal!(Vec::<f32>::new()),
            window_logs: Rc::new(Cell::new(0)),
            window_bytes: Rc::new(Cell::new(0)),
            next_id: Rc::new(Cell::new(1)),
        };

        let app = Self {
            mode: signal!(Mode::Live),
            conn: signal!(ConnStatus::Connecting),
            logs: signal_vec(Vec::new()),
            visible: signal_vec(Vec::new()),
            filter_level: signal!(Option::<LogLevel>::None),
            filter_query: signal!(String::new()),
            auto_scroll: signal!(true),
            threats: signal_vec(Vec::new()),
            toasts: signal_vec(Vec::new()),
            metrics,
            analysis: Analysis {
                active: signal!(false),
                progress: signal!(0.0),
                file: signal!(String::new()),
                lines: signal!(0u32),
            },
            detector: Rc::new(RefCell::new(Detector::new())),
        };

        app.install_filter();
        app.install_metrics_tick();
        app
    }

    /// Derive `visible` from `logs` + the active filters.
    ///
    /// Runs once at startup and then on every ingestion batch or filter
    /// change. The result is written with a single `with_mut` so the keyed
    /// reconciler diffs old keys against new keys exactly once per change.
    fn install_filter(&self) {
        let logs = self.logs.clone();
        let visible = self.visible.clone();
        let level = self.filter_level;
        let query = self.filter_query;

        effect!(move || {
            let want_level = level.get();
            let q = query.get().to_ascii_lowercase();
            let source = logs.get();

            let mut out: Vec<LogEntry> = source
                .into_iter()
                .filter(|e| want_level.map_or(true, |l| e.level == l))
                .filter(|e| q.is_empty() || e.haystack.contains(&q))
                .collect();

            // Batched eviction — see VISIBLE_TRIM_AT docs.
            if out.len() > VISIBLE_TRIM_AT {
                let excess = out.len() - VISIBLE_KEEP;
                out.drain(..excess);
            }

            visible.with_mut(|v| *v = out);
        });
    }

    /// 1 Hz metrics tick: drain the hot-path counters into display signals,
    /// track the peak byte rate, and push a sparkline sample.
    fn install_metrics_tick(&self) {
        let app = self.clone();

        let _interval = gloo_timers::callback::Interval::new(1_000, move || {
            let logs = app.metrics.window_logs.replace(0);
            let bytes = app.metrics.window_bytes.replace(0);

            app.metrics.logs_per_sec.set(logs);
            app.metrics.bytes_per_sec.set(bytes);
            app.metrics.total_logs.update(|t| *t += logs);
            if bytes > app.metrics.peak_bytes_per_sec.get() {
                app.metrics.peak_bytes_per_sec.set(bytes);
            }
            app.metrics.rate_history.update(|h| {
                h.push(logs as f32);
                if h.len() > 60 {
                    h.remove(0);
                }
            });
        });
        // Retained for the app lifetime (dropping would cancel the timer).
        std::mem::forget(_interval);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `HH:MM:SS.mmm` in the browser's local timezone.
pub fn format_time(ts_ms: f64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ts_ms));
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds(),
        d.get_milliseconds()
    )
}

/// Truncate to `max` characters without splitting a char boundary.
pub fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}
