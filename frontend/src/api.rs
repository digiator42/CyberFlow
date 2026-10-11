//! GritShield backend API contract.
//!
//! The backend is implemented separately; this module is the **single place**
//! the frontend's assumptions about it live. When real API docs arrive, only
//! this file (plus possibly `LogEvent` in `state.rs`) should need touching.

use crate::state::Threat;

/// Backend base URL (dev). When served from the same origin as the API, this
/// can stay empty.
const BASE_URL: &str = "http://127.0.0.1:8010";

/// Server-Sent Events feed of live log telemetry.
pub const STREAM_PATH: &str = "/api/v1/stream";

/// Threat incident ingestion (JSON POST).
pub const THREATS_PATH: &str = "/api/v1/threats";

fn with_base(path: &str) -> String {
    if BASE_URL.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", BASE_URL.trim_end_matches('/'), path)
    }
}

/// API key expected by GritShield's `on_request` auth middleware.
///
/// `EventSource` cannot set request headers, so the key travels as a query
/// parameter instead — the backend middleware should accept `?api_key=` as an
/// alternative to the `X-API-Key` header.
pub const API_KEY: &str = "";

/// Fully-qualified SSE URL including the auth query parameter.
pub fn stream_url() -> String {
    let url = with_base(STREAM_PATH);
    if API_KEY.is_empty() {
        url
    } else {
        format!("{url}?api_key={API_KEY}")
    }
}

/// POST one threat incident to the GritShield threat database.
///
/// Fire-and-forget from the UI's perspective: the dashboard keeps working
/// (and the incident stays visible locally) even when the backend is down.
pub async fn post_threat(threat: &Threat) -> Result<(), String> {
    velo::request(&with_base(THREATS_PATH))
        .method("POST")
        .json_body(threat)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}
