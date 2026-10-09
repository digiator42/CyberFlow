//! `examples/gritshield-soc` — GritShield SOC, a hybrid live log stream and
//! privacy-preserving client-side threat analysis console.
//!
//! One codebase exercising Velo features end-to-end:
//!
//! - SSE live feed (`EventSource` bridge in [`net`]) feeding a keyed `for`
//!   terminal that holds up under the 100+ events/sec verification target
//! - [`ingest`] — one ingestion funnel for stream + file sources, running the
//!   pure-`std` [`detection`] engine (signatures, Shannon entropy, rate)
//! - `<Show>`, `class:` toggles, `bind:value` / `bind:checked` — filters,
//!   mode switch, auto-scroll
//! - `<DragEvent>` drop zone streaming `Blob` chunks with incremental UTF-8
//!   line splitting (nothing leaves the browser)
//! - threat cards + auto-dismissing toast stack, metrics bar with SVG
//!   sparkline
//!
//! Backend endpoints are stubbed in [`api`] pending GritShield API docs.

use velo::prelude::*;
use wasm_bindgen::prelude::wasm_bindgen;

mod api;
mod components;
mod detection;
mod ingest;
mod net;
mod state;
mod worker;

use crate::components::*;
use crate::state::AppState;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    // The same wasm module is instantiated inside the analysis Web Worker.
    // There is no `window` there, so skip mounting the dashboard; the worker
    // is driven by the `worker::worker_*` entry points instead.
    if web_sys::window().is_none() {
        return;
    }
    run_app();
}

pub fn run_app() {
    // Seed global context before mounting so every component can pull the
    // shared state with `use_context::<AppState>()`.
    let app = AppState::new();
    provide!(app.clone());

    // Open the SSE stream (Live mode is the default).
    net::connect(&app);

    let shell = view! {
        <div class="app-shell">
            <TopBar />
            <MetricsBar />
            <ControlPanel />

            <main class="layout">
                <div class="col-main">
                    <DropZone />
                    <LogTerminal />
                </div>
                <aside class="col-side">
                    <ThreatPanel />
                </aside>
            </main>

            <ToastStack />
            <LogDetail />
        </div>
    };
    mount(shell);
}
