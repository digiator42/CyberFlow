use gritshield::mcp::prompt::McpPromptMessage;
use gritshield::mcp_prompt;
use gritshield::mcp_tool;
use gritshield::routing::engine::RequestContext;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db;
use crate::state;
use crate::types::normalize_severity;

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ThreatsArgs {
    #[serde(default)]
    pub limit: u32,
    #[serde(default)]
    pub severity: Option<String>,
}

/// `tools/call get_active_threats` — query the persisted threat table.
#[mcp_tool(
    name = "get_active_threats",
    service = "LogsSoc",
    description = "List the most recently reported security threats persisted by the SOC ingestion API",
    schema = r#"{
        "type": "object",
        "properties": {
            "limit":    { "type": "integer", "description": "Max threats to return", "minimum": 1, "maximum": 500 },
            "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Filter by severity" }
        },
        "required": []
    }"#,
)]
pub async fn get_active_threats(
    _ctx: &RequestContext,
    args: ThreatsArgs,
) -> Result<Value, String> {
    let st = state::resolve();
    let limit = if args.limit == 0 { 20 } else { args.limit.clamp(1, 500) } as u64;
    let severity = args.severity.map(|s| normalize_severity(&s));

    let threats = db::list_threats(st.db.as_ref(), limit, severity.as_deref()).await?;

    let values: Vec<Value> = threats
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "frontend_id": t.frontend_id,
                "ts_ms": t.ts_ms,
                "severity": t.severity,
                "rule_id": t.rule_id,
                "rule_name": t.rule_name,
                "ip": t.ip,
                "payload": t.payload,
                "origin": t.origin,
                "received_at": t.received_at
            })
        })
        .collect();

    Ok(json!({ "count": values.len(), "threats": values }))
}

#[derive(Debug, Deserialize)]
pub struct BlacklistArgs {
    pub ip: String,
    #[serde(default)]
    pub reason: String,
}

/// `tools/call add_ip_blacklist` — block an IP immediately (in-memory) and
/// persist it so the block survives restarts.
#[mcp_tool(
    name = "add_ip_blacklist",
    service = "LogsSoc",
    description = "Immediately block an IP address at the middleware layer and persist the block",
    schema = r#"{
        "type": "object",
        "properties": {
            "ip":     { "type": "string", "description": "IPv4 or IPv6 address to block" },
            "reason": { "type": "string", "description": "Optional note explaining why" }
        },
        "required": ["ip"]
    }"#,
)]
pub async fn add_ip_blacklist(_ctx: &RequestContext, args: BlacklistArgs) -> Result<Value, String> {
    let st = state::resolve();
    let ip = args.ip.trim().to_string();
    if ip.is_empty() {
        return Err("ip must not be empty".to_string());
    }

    db::upsert_blacklist(st.db.as_ref(), &ip, &args.reason).await?;

    if let Ok(mut set) = st.blacklist.lock() {
        set.insert(ip.clone());
    }

    Ok(json!({ "blocked": true, "ip": ip }))
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IncidentSummaryArgs {
    #[serde(default)]
    pub threat_id: Option<i64>,
    #[serde(default)]
    pub recent_events: u32,
}

/// `prompts/get summarize_incident` — turn recent SOC log activity (and an
/// optional threat) into a stakeholder-facing incident summary template.
#[mcp_prompt(
    name = "summarize_incident",
    description = "Build a stakeholder-facing incident summary from recent SOC log activity and an optional reported threat",
    arguments = "recent_events?,threat_id?",
    descriptions = "recent_events=Number of recent log events to fold into the summary (default 20);\
                    threat_id=Database id of the persisted threat to highlight, if any"
)]
pub async fn summarize_incident(args: IncidentSummaryArgs) -> Result<Vec<McpPromptMessage>, String> {
    let st = state::resolve();

    let limit = if args.recent_events == 0 {
        20
    } else {
        (args.recent_events as usize).min(500)
    };
    let events = st.store.history(limit).await;

    let mut by_level: std::collections::BTreeMap<String, usize> = Default::default();
    for ev in &events {
        *by_level.entry(ev.level.clone()).or_insert(0) += 1;
    }
    let level_line = if by_level.is_empty() {
        "No log events in the current buffer.".to_string()
    } else {
        let counts: Vec<String> = by_level
            .iter()
            .map(|(level, n)| format!("{level}={n}"))
            .collect();
        format!("Log volume by level over the last {} events: {}", events.len(), counts.join(", "))
    };

    let threat_line = match args.threat_id {
        Some(id) => match db::find_threat(st.db.as_ref(), id).await? {
            Some(t) => format!(
                "Related threat #{} (severity {}): rule \"{}\" against {} via {} at ts_ms {:.0}.",
                t.id, t.severity, t.rule_name, t.ip, t.origin, t.ts_ms
            ),
            None => format!("Threat #{} was not found in the persisted store.", id),
        },
        None => {
            let latest = events.first();
            match latest {
                Some(ev) => format!("Most recent log event: level={} ip={} route={} msg={:?}.", ev.level, ev.ip, ev.route, ev.msg),
                None => "No log events available.".to_string(),
            }
        }
    };

    let message = format!(
        "Write a concise incident summary for a non-technical stakeholder.\n\n\
         Context from the SOC pipeline:\n- {level_line}\n- {threat_line}\n\n\
         Include: what happened, the impacted assets/IPs, severity, current status, \
         and the recommended next actions."
    );

    Ok(vec![McpPromptMessage::user(message)])
}