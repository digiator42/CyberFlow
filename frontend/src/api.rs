//! GritShield backend API contract.
//!
//! The backend is implemented separately; this module is the **single place**
//! the frontend's assumptions about it live. When real API docs arrive, only
//! this file (plus possibly `LogEvent` in `state.rs`) should need touching.

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit};

use crate::state::Threat;

/// Server-Sent Events feed of live log telemetry.
pub const STREAM_PATH: &str = "/api/v1/stream";

/// Threat incident ingestion (JSON POST).
pub const THREATS_PATH: &str = "/api/v1/threats";

/// API key expected by GritShield's `on_request` auth middleware.
///
/// `EventSource` cannot set request headers, so the key travels as a query
/// parameter instead — the backend middleware should accept `?api_key=` as an
/// alternative to the `X-API-Key` header.
pub const API_KEY: &str = "";

/// Fully-qualified SSE URL including the auth query parameter.
pub fn stream_url() -> String {
    if API_KEY.is_empty() {
        STREAM_PATH.to_string()
    } else {
        format!("{STREAM_PATH}?api_key={API_KEY}")
    }
}

/// POST one threat incident to the GritShield threat database.
///
/// Fire-and-forget from the UI's perspective: the dashboard keeps working
/// (and the incident stays visible locally) even when the backend is down.
pub async fn post_threat(threat: &Threat) -> Result<(), String> {
    let body = serde_json::to_string(threat).map_err(|e| e.to_string())?;

    let headers = web_sys::Headers::new().map_err(|e| debug_js(&e))?;
    headers
        .append("content-type", "application/json")
        .map_err(|e| debug_js(&e))?;

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&body));

    let request = Request::new_with_str_and_init(THREATS_PATH, &init).map_err(|e| debug_js(&e))?;

    // `fetch` lives on `Window` in web-sys, not on `Request`.
    let window = web_sys::window().ok_or("no window object")?;
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| debug_js(&e))?;
    let response: web_sys::Response = response
        .dyn_into()
        .map_err(|_| "threat POST resolved to a non-Response".to_string())?;

    if response.ok() {
        Ok(())
    } else {
        Err(format!(
            "threat POST returned {} {}",
            response.status(),
            response.status_text()
        ))
    }
}

fn debug_js(v: &JsValue) -> String {
    v.as_string().unwrap_or_else(|| format!("{v:?}"))
}
