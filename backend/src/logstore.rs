use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gritshield::http::SseStream;
use tokio::sync::Mutex;

use crate::types::LogEvent;

/// Maximum number of events retained in the in-memory ring buffer.
pub const HISTORY_CAPACITY: usize = 10_000;

/// A newly-registered SSE stream is given this long to attach a subscriber
/// before it becomes a prune candidate. Without the grace period, a fan-out
/// triggered between `attach()` and the connection pump subscribing would
/// evict a live client who simply has not subscribed yet.
const STREAM_ATTACH_GRACE: Duration = Duration::from_secs(5);

struct RegisteredStream {
    sse: SseStream,
    since: Instant,
}

struct LogStoreInner {
    history: VecDeque<LogEvent>,
    streams: Vec<RegisteredStream>,
    received_total: u64,
    attached_total: u64,
}

/// The shared in-memory log pipeline: a bounded ring buffer of recent events
/// plus the set of live SSE fan-out streams.
#[derive(Clone)]
pub struct LogStore {
    inner: Arc<Mutex<LogStoreInner>>,
}

impl LogStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LogStoreInner {
                history: VecDeque::with_capacity(HISTORY_CAPACITY),
                streams: Vec::new(),
                received_total: 0,
                attached_total: 0,
            })),
        }
    }

    /// Most recent events first, newest at index 0.
    pub async fn history(&self, limit: usize) -> Vec<LogEvent> {
        let guard = self.inner.lock().await;
        guard
            .history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Attach a new consumer stream. The stream must also be handed to
    /// `Response::sse` by the caller; this copy is what `ingest` broadcasts on.
    pub async fn attach(&self, stream: SseStream) {
        let mut guard = self.inner.lock().await;
        guard.streams.push(RegisteredStream {
            sse: stream,
            since: Instant::now(),
        });
        guard.attached_total += 1;
    }

    /// Push a normalised event into the ring buffer and fan it out to every
    /// live SSE consumer. Returns the number of consumers that received the
    /// frame.
    pub async fn ingest(&self, event: &LogEvent) -> usize {
        let mut guard = self.inner.lock().await;
        guard.received_total += 1;

        if guard.history.len() >= HISTORY_CAPACITY {
            guard.history.pop_front();
        }
        guard.history.push_back(event.clone());

        // Evict streams that connected, never subscribed, and are past grace.
        guard.streams.retain(|s| {
            s.since.elapsed() < STREAM_ATTACH_GRACE || s.sse.listeners() > 0
        });

        let payload = serde_json::to_string(event).unwrap_or_default();
        let mut live = 0usize;
        for registered in &guard.streams {
            // `Ok(0)` = nobody attached yet; `Err` = zero receivers at all.
            if let Ok(n) = registered.sse.send("log", &payload) {
                live += n;
            }
        }
        live
    }

    pub async fn stats(&self) -> (usize, usize, u64, u64) {
        let guard = self.inner.lock().await;
        (
            guard.history.len(),
            guard.streams.len(),
            guard.received_total,
            guard.attached_total,
        )
    }
}

impl Default for LogStore {
    fn default() -> Self {
        Self::new()
    }
}