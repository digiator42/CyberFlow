use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use gritshield::http::request::HttpMethod;
use gritshield::http::response::Response;
use gritshield::middleware::{Middleware, MiddlewareResult};
use gritshield::prelude::RequestContext;
use gritshield::security::rate_limit::RateLimiter;
use serde_json::json;

use crate::state::AppState;

/// Require `X-API-Key` (or `?api_key=`) when the operator configured
/// `SOC_API_KEY`. With no key configured every route is open — this is the
/// default posture the WASM frontend expects (`EventSource` cannot set headers,
/// so it falls back to the query parameter variant).
pub struct ApiKeyMiddleware {
    expected: Option<String>,
}

impl ApiKeyMiddleware {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            expected: state.api_key.clone(),
        }
    }
}

#[async_trait]
impl Middleware for ApiKeyMiddleware {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        if let Some(expected) = &self.expected {
            let provided = ctx
                .header("x-api-key")
                .map(ToOwned::to_owned)
                .or_else(|| ctx.query_param("api_key").map(ToOwned::to_owned))
                .unwrap_or_default();

            if provided.is_empty() || provided != *expected {
                return MiddlewareResult::Error(Response::json_unauthorized(&json!({
                    "error": "unauthorized",
                    "detail": "missing or invalid X-API-Key header (or ?api_key= query param)"
                })));
            }
        }
        MiddlewareResult::Next(None)
    }
}

/// Reject requests from IPs present in the live blocklist shared with the
/// `add_ip_blacklist` MCP tool.
pub struct IpBlacklistMiddleware {
    blacklist: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl IpBlacklistMiddleware {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            blacklist: state.blacklist.clone(),
        }
    }
}

#[async_trait]
impl Middleware for IpBlacklistMiddleware {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        let ip = ctx.resolve_client_ip();
        let blocked = self
            .blacklist
            .lock()
            .map(|set| set.contains(&ip))
            .unwrap_or(false);

        if blocked {
            MiddlewareResult::Error(Response::json_forbidden(&json!({
                "error": "ip_blacklisted",
                "ip": ip
            })))
        } else {
            MiddlewareResult::Next(None)
        }
    }
}

/// Cap the size of write payloads. `ctx.raw_body` is fully buffered before the
/// middleware chain runs, so this is a cheap length check.
pub struct BodyLimitMiddleware {
    max_bytes: usize,
}

impl BodyLimitMiddleware {
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }
}

#[async_trait]
impl Middleware for BodyLimitMiddleware {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        if ctx.req.method != HttpMethod::GET && ctx.raw_body.len() > self.max_bytes {
            let mut res =
                Response::json_unauthorized(&json!({"error": "payload_too_large", "max": self.max_bytes}));
            res.status = 413;
            MiddlewareResult::Error(res)
        } else {
            MiddlewareResult::Next(None)
        }
    }
}

/// Sliding-window per-IP request limiter backed by GritShield's `RateLimiter`.
/// `SSE` connects and MCP traffic count against the same bucket.
pub struct RateLimitMdlw {
    limiter: RateLimiter,
}

impl RateLimitMdlw {
    pub fn new(_state: Arc<AppState>, max_requests: usize, window: Duration) -> Self {
        Self {
            limiter: RateLimiter::new(max_requests, window),
        }
    }
}

#[async_trait]
impl Middleware for RateLimitMdlw {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        let ip = ctx.resolve_client_ip();
        if self.limiter.is_allowed(ip) {
            MiddlewareResult::Next(None)
        } else {
            let mut res = Response::json_too_many_requests(&json!({
                "error": "rate_limited",
                "detail": "request volume exceeded the per-IP window"
            }));
            res.headers
                .push(("Retry-After".to_string(), "60".to_string()));
            MiddlewareResult::Error(res)
        }
    }
}

/// Attach hardening headers to the final response and expose request duration.
pub struct HttpSecurityMiddleware;

impl HttpSecurityMiddleware {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Middleware for HttpSecurityMiddleware {
    async fn on_request(&self, _ctx: &mut RequestContext) -> MiddlewareResult {
        MiddlewareResult::Next(None)
    }

    async fn on_response(&self, ctx: &RequestContext, res: &mut Response) {
        push_header(res, "X-Content-Type-Options", "nosniff");
        push_header(res, "X-Frame-Options", "DENY");
        push_header(res, "Referrer-Policy", "no-referrer");
        push_header(res, "Cache-Control", "no-store");
        push_header(res, "Server", "logs-soc-backend");
        res.headers.push((
            "X-SOC-Response-Time-Ms".to_string(),
            ctx.start_time.elapsed().as_millis().to_string(),
        ));
    }
}

fn push_header(res: &mut Response, key: &str, value: impl Into<String>) {
    if !res.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
        res.headers.push((key.to_string(), value.into()));
    }
}