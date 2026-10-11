//! Real-time metrics strip: throughput, threat count, and a rolling
//! logs/sec sparkline chart.

use veloasm::prelude::*;

use crate::state::AppState;

/// Map a history window onto SVG polyline coordinates (120×36 viewBox).
fn sparkline_points(history: &[f32]) -> String {
    if history.is_empty() {
        return String::new();
    }
    let max = history.iter().copied().fold(1.0f32, f32::max);
    let n = history.len();
    history
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = if n == 1 {
                120.0
            } else {
                i as f32 * 120.0 / (n - 1) as f32
            };
            // Invert: SVG y grows downward, chart bars grow upward.
            let y = 34.0 - (v / max) * 32.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[component]
pub fn MetricsBar() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let logs_per_sec = app.metrics.logs_per_sec;
    let threat_count = app.metrics.threat_count;
    let total_logs = app.metrics.total_logs;
    let peak_bps = app.metrics.peak_bytes_per_sec;

    let bandwidth = memo!(move || {
        format!(
            "{:.1} KB/s",
            app.metrics.bytes_per_sec.get() as f64 / 1024.0
        )
    });
    let peak_label = memo!(move || format!("{} KB/s", peak_bps.get() / 1024));
    let total_label = memo!(move || format!("{}", total_logs.get()));

    let history = app.metrics.rate_history;
    let points = memo!(move || sparkline_points(&history.get()));

    view! {
        <section class="metrics">
            <div class="metric-tile">
                <span class="metric-label">"LOGS / SEC"</span>
                <span class="metric-value">{ logs_per_sec }</span>
                <span class="metric-sub">"total " { total_label }</span>
            </div>

            <div class="metric-tile">
                <span class="metric-label">"THREATS"</span>
                <span class="metric-value metric-danger">{ threat_count }</span>
                <span class="metric-sub">"flagged this session"</span>
            </div>

            <div class="metric-tile">
                <span class="metric-label">"BANDWIDTH"</span>
                <span class="metric-value metric-small">{ bandwidth }</span>
                <span class="metric-sub">"peak " { peak_label }</span>
            </div>

            <div class="metric-tile metric-spark">
                <span class="metric-label">"TRAFFIC · 60s"</span>
                <svg class="sparkline" viewBox="0 0 120 36" preserveAspectRatio="none">
                    <polyline class="sparkline-line" points={ points } fill="none" />
                </svg>
            </div>
        </section>
    }
}

