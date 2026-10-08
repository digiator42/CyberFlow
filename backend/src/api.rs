use gritshield::http::SseStream;
use gritshield::prelude::{RequestContext, Response};
use serde_json::{json, Value};

use crate::db;
use crate::state;
use crate::types::{now_ms_f64, IngestRequest, LogEvent, ThreatInput};

/// `GET /health` — liveness plus a peek at the pipeline buffers.
pub async fn health(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    let (history_len, stream_count, received_total, attached_total) = st.store.stats().await;

    let db_ok = db::ping(st.db.as_ref()).await.is_ok();

    Response::json_ok(&json!({
        "service": "logs-soc-backend",
        "status": "ok",
        "db": db_ok,
        "buffers": {
            "history_count": history_len,
            "history_capacity": crate::logstore::HISTORY_CAPACITY,
            "live_streams": stream_count,
            "received_total": received_total,
            "attached_total": attached_total,
        }
    }))
}

/// `POST /api/v1/logs` — accept a single `LogEvent` or `{ "events": [...] }`,
/// normalize each event, push it into the ring buffer and broadcast it to every
/// attached SSE stream.
pub async fn post_logs(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({"error": "invalid_json"})),
    };

    let mut events: Vec<LogEvent> = Vec::new();

    if body.get("events").is_some() {
        // Batch form: { "events": [...] }
        let req: IngestRequest = match serde_json::from_value(body) {
            Ok(req) => req,
            Err(e) => {
                return Response::json_bad_request(&json!({
                    "error": "invalid_log_event",
                    "detail": e.to_string()
                }))
            }
        };
        events = req.events.unwrap_or_default();
        if events.is_empty() {
            return Response::json_bad_request(&json!({"error": "no_events"}));
        }
    } else {
        // Single event form
        match serde_json::from_value::<LogEvent>(body) {
            Ok(ev) => events.push(ev),
            Err(e) => {
                return Response::json_bad_request(&json!({
                    "error": "invalid_log_event",
                    "detail": e.to_string()
                }))
            }
        }
    }

    let server_now = now_ms_f64();
    let mut accepted = 0usize;
    let mut live = 0usize;
    for ev in events.iter_mut() {
        ev.normalize(server_now);
        live = st.store.ingest(ev).await;
        accepted += 1;
    }

    Response::json_accepted(&json!({
        "accepted": accepted,
        "live_consumers": live
    }))
}

/// `GET /api/v1/stream` — Server-Sent Events live log tail.
///
/// The most recent `history` events (default 50) are replayed as initial
/// frames so a late subscriber does not connect into silence, then live events
/// arrive under the `log` event name:
///
/// ```text
/// event: log
/// data: {"ts":1720524000000,"level":"WARN","ip":"203.0.113.9","route":"/login","msg":"..."}
/// ```
///
/// Query params:
/// * `history` — how many recent events to replay (default 50, max 1000).
/// * `since`   — only replay events with `ts >=` this epoch-ms value.
/// * `api_key` — accepted when `SOC_API_KEY` is configured (EventSource cannot
///   set the `X-API-Key` header).
pub async fn stream(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let limit = ctx
        .query_param("history")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(1000);
    let since = ctx.query_param("since").and_then(|v| v.parse::<f64>().ok());

    let history = st.store.history(limit).await;

    let mut sse = SseStream::new();
    for ev in history {
        if let Some(min_ts) = since {
            if ev.ts < min_ts {
                continue;
            }
        }
        if let Ok(payload) = serde_json::to_string(&ev) {
            sse.queue_initial("log", &payload);
        }
    }

    // Register a fan-out copy, then hand the owned stream to the transport.
    st.store.attach(sse.clone()).await;
    Response::sse(sse)
}

/// `POST /api/v1/threats` — persist a client-reported security threat.
///
/// Body (frontend contract, `id` is the UI-generated one):
/// ```json
/// {
///   "id": 42,
///   "ts_ms": 1720524000000,
///   "severity": "high",
///   "rule_id": "soc-07",
///   "rule_name": "Brute force burst",
///   "ip": "203.0.113.9",
///   "payload": "…",
///   "origin": "detector"
/// }
/// ```
pub async fn post_threat(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({"error": "invalid_json"})),
    };

    let input: ThreatInput = match serde_json::from_value(body) {
        Ok(input) => input,
        Err(e) => {
            return Response::json_bad_request(&json!({
                "error": "invalid_threat",
                "detail": e.to_string()
            }))
        }
    };

    match db::insert_threat(st.db.as_ref(), &input).await {
        Ok(row_id) => Response::json_created(&json!({
            "accepted": true,
            "id": row_id,
            "frontend_id": input.id
        })),
        Err(e) => Response::json_internal_error_msg(format!("threat_persist_failed: {e}")),
    }
}