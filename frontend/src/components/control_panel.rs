//! Interactive control panel: ingest-mode toggle, log filters, and viewport
//! controls.

use velo::prelude::*;

use crate::net;
use crate::state::{AppState, LogLevel, Mode};

#[component]
pub fn ControlPanel() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let mode = app.mode;
    let filter_level = app.filter_level;
    let auto_scroll = app.auto_scroll;
    let query = app.filter_query.clone();

    // Per-closure clones (AppState is Clone; mode/filter handles are Copy).
    let app_live = app.clone();
    let logs_for_clear = app.logs.clone();

    let logs_count = app.logs.clone();
    let visible_count = app.visible.clone();
    let raw_label = memo!(move || format!("{}", logs_count.len()));
    let shown_label = memo!(move || format!("{}", visible_count.len()));

    view! {
        <section class="controls">
            <div class="controls-group mode-toggle">
                <button
                    class="mode-btn"
                    class:active={ move || mode.get() == Mode::Live }
                    on:click={ move |_| {
                        mode.set(Mode::Live);
                        net::connect(&app_live);
                    }}>
                    "◉ " "LIVE STREAM"
                </button>
                <button
                    class="mode-btn"
                    class:active={ move || mode.get() == Mode::Local }
                    on:click={ move |_| {
                        mode.set(Mode::Local);
                        net::disconnect();
                    }}>
                    "⬓ " "LOCAL FILE ANALYSIS"
                </button>
            </div>

            <div class="controls-group chips">
                <button
                    class="chip"
                    class:active={ move || filter_level.get().is_none() }
                    on:click={ move |_| filter_level.set(None) }>
                    "ALL"
                </button>
                <button
                    class="chip chip-debug"
                    class:active={ move || filter_level.get() == Some(LogLevel::Debug) }
                    on:click={ move |_| filter_level.set(Some(LogLevel::Debug)) }>
                    "DEBUG"
                </button>
                <button
                    class="chip chip-info"
                    class:active={ move || filter_level.get() == Some(LogLevel::Info) }
                    on:click={ move |_| filter_level.set(Some(LogLevel::Info)) }>
                    "INFO"
                </button>
                <button
                    class="chip chip-warn"
                    class:active={ move || filter_level.get() == Some(LogLevel::Warn) }
                    on:click={ move |_| filter_level.set(Some(LogLevel::Warn)) }>
                    "WARN"
                </button>
                <button
                    class="chip chip-error"
                    class:active={ move || filter_level.get() == Some(LogLevel::Error) }
                    on:click={ move |_| filter_level.set(Some(LogLevel::Error)) }>
                    "ERROR"
                </button>
                <button
                    class="chip chip-critical"
                    class:active={ move || filter_level.get() == Some(LogLevel::Critical) }
                    on:click={ move |_| filter_level.set(Some(LogLevel::Critical)) }>
                    "CRITICAL"
                </button>
            </div>

            <div class="controls-group controls-search">
                <input
                    type="text"
                    class="filter-input"
                    placeholder="filter by IP, route, or message…"
                    bind:value={ query }
                />
                <span class="filter-count">{ shown_label } " / " { raw_label }</span>
            </div>

            <div class="controls-group controls-view">
                <label class="auto-scroll">
                    <input type="checkbox" bind:checked={ auto_scroll } />
                    "Auto-scroll"
                </label>
                <button
                    class="btn-ghost"
                    on:click={ move |_| logs_for_clear.clear() }>
                    "Clear"
                </button>
            </div>
        </section>
    }
}
