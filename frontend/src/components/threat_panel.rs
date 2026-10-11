//! Threat intelligence side panel + flash-alert toast stack.

use veloasm::prelude::*;

use crate::ingest;
use crate::state::{format_time, AppState, Threat};

/// One threat incident card.
#[component]
pub fn ThreatCard(threat: Threat) -> DomNode {
    let severity_class = class_names!("threat-card", format!("sev-{}", threat.severity.css()));
    let severity_text = threat.severity.as_str().to_string();
    let rule = threat.rule_name;
    let rule_id = threat.rule_id;
    let ip = if threat.ip.is_empty() {
        "-".to_string()
    } else {
        threat.ip
    };
    let time = format_time(threat.ts_ms);
    let payload = threat.payload;
    let origin = threat.origin;

    view! {
        <div class={ severity_class }>
            <div class="threat-head">
                <span class="threat-sev">{ severity_text }</span>
                <span class="threat-time">{ time }</span>
            </div>
            <div class="threat-rule">{ rule } <span class="threat-rule-id">"[" { rule_id } "]"</span></div>
            <div class="threat-ip">"src " { ip }</div>
            <code class="threat-payload">{ payload }</code>
            <div class="threat-origin">{ origin }</div>
        </div>
    }
}

/// Flash alert shown over the dashboard whenever a threat is raised.
#[component]
pub fn ToastAlert(threat: Threat) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let toast_id = threat.id;
    let severity_class = class_names!("toast", format!("sev-{}", threat.severity.css()));
    let title = threat.rule_name;
    let detail = format!(
        "{} · {}",
        if threat.ip.is_empty() {
            "-".to_string()
        } else {
            threat.ip
        },
        threat.severity.as_str()
    );

    view! {
        <div class={ severity_class }>
            <div class="toast-body">
                <div class="toast-title">{ title }</div>
                <div class="toast-detail">{ detail }</div>
            </div>
            <button
                class="toast-close"
                on:click={ move |_| ingest::dismiss_threat(&app, toast_id) }>
                "×"
            </button>
        </div>
    }
}

/// Right-hand column: threat feed + counter.
#[component]
pub fn ThreatPanel() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let count_threats = app.threats.clone();
    let flag_threats = app.threats.clone();
    let for_threats = app.threats.clone();
    let count = memo!(move || format!("{}", count_threats.len()));
    let is_empty = memo!(move || flag_threats.len() == 0);

    view! {
        <section class="panel threats">
            <div class="panel-head">
                <h2 class="panel-title">"Threat Intelligence"</h2>
                <span class="panel-meta">{ count } " incidents"</span>
            </div>

            <div class="threat-list">
                {
                    move || if is_empty.get() {
                        view! { <div class="threat-empty">"No threats detected. Signals and rate checks are armed."</div> }
                    } else {
                        DomNode::empty()
                    }
                }
                {
                    for t in for_threats key = |t: &Threat| t.id {
                        <ThreatCard threat={ t.clone() } />
                    }
                }
            </div>
        </section>
    }
}

/// Fixed overlay stack of flash alerts (auto-dismissing, click × to close).
#[component]
pub fn ToastStack() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let toasts = app.toasts.clone();

    view! {
        <div class="toasts">
            {
                for t in toasts key = |t: &Threat| t.id {
                    <ToastAlert threat={ t.clone() } />
                }
            }
        </div>
    }
}

