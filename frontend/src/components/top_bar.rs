//! Header bar: brand mark + live stream status.

use veloasm::prelude::*;

use crate::state::AppState;

#[component]
pub fn TopBar() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    // `RwSignal` is `Copy`, so each derived memo captures its own handle.
    let conn = app.conn;
    let mode = app.mode;

    // Derived display strings — each memo is its own fine-grained subscription.
    let conn_label = memo!(move || conn.get().label().to_string());
    let conn_css = memo!(move || format!("conn-dot {}", conn.get().css()));
    let mode_label = memo!(move || mode.get().label().to_string());

    view! {
        <header class="topbar">
            <div class="brand">
                <span class="brand-mark">"⌖"</span>
                <span class="brand-name">"GRITSHIELD"</span>
                <span class="brand-sub">"SOC"</span>
            </div>

            <div class="topbar-status">
                <span class="mode-badge">{ mode_label }</span>
                <span class="conn">
                    <span class={ conn_css }></span>
                    <span class="conn-text">{ conn_label }</span>
                </span>
                <span class="stream-endpoint">{ crate::api::STREAM_PATH }</span>
            </div>
        </header>
    }
}

