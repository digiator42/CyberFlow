//! Live log terminal: keyed, fine-grained rows over the filtered log stream.
//!
//! Built to hold up under the framework verification target of **100+
//! events/sec**: rows are appended by the keyed reconciler (only new nodes
//! are created), filters recompute into a single batched `with_mut` write,
//! and the DOM is trimmed in batches rather than per-push (see
//! `VISIBLE_TRIM_AT`).

use velo::prelude::*;
use wasm_bindgen::JsCast;

use crate::state::{format_time, AppState, LogEntry};

/// One terminal line. Takes the whole entry as an owned prop so the keyed
/// `for` body can pass `entry.clone()` — `view!` expression slots are `move`
/// closures and must not borrow the loop variable.
#[component]
pub fn LogRow(entry: LogEntry) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let entry_clone = entry.clone();
    let selected = app.selected_log;
    let entry_id = entry.id;

    let row_class = class_names!("log-row", entry.level.css());
    let time = format_time(entry.ts_ms);
    let level_class = class_names!("log-level", format!("lvl-{}", entry.level.css()));
    let level_text = entry.level.as_str().to_string();
    let ip = if entry.ip.is_empty() {
        "-".to_string()
    } else {
        entry.ip
    };
    let route = if entry.route.is_empty() {
        "-".to_string()
    } else {
        entry.route
    };
    let meta = format!("{ip} → {route}");
    let source = entry.source;
    let msg = entry.msg;

    view! {
        <div
            class={ row_class }
            class:log-row-selected={ move || selected.get().as_ref().map(|e| e.id) == Some(entry_id) }
            title={ source }
            on:click={ move |_| {
                selected.set(Some(entry_clone.clone()));
            } }
        >
            <span class="log-time">{ time }</span>
            <span class={ level_class }>{ level_text }</span>
            <span class="log-meta">{ meta }</span>
            <span class="log-msg">{ msg }</span>
        </div>
    }
}

/// Log detail panel showing full information for selected log entry.
#[component]
pub fn LogDetail() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let selected = app.selected_log;

    view! {
        <div
            class="log-detail-overlay"
            style:display={ move || if selected.get().is_some() { "flex".to_string() } else { "none".to_string() } }
            on:click={ move |_| selected.set(None) }
        >
            <div class="log-detail-panel" on:click={ move |ev| {
                let ev = ev.dyn_ref::<web_sys::Event>().unwrap();
                ev.stop_propagation();
            }}>
                {
                    move || {
                        if let Some(entry) = selected.get() {
                            let time = format_time(entry.ts_ms);
                            let level_text = entry.level.as_str().to_string();
                            let ip = if entry.ip.is_empty() { "-".to_string() } else { entry.ip.clone() };
                            let route = if entry.route.is_empty() { "-".to_string() } else { entry.route.clone() };

                            view! {
                                <div class="log-detail-content">
                                    <div class="log-detail-header">
                                        <h3 class="log-detail-title">"Log Details"</h3>
                                        <button
                                            class="log-detail-close"
                                            on:click={ move |_| selected.set(None) }
                                        >"×"</button>
                                    </div>
                                    <div class="log-detail-body">
                                        <div class="log-detail-row">
                                            <span class="log-detail-label">"Timestamp:"</span>
                                            <span class="log-detail-value">{ time }</span>
                                        </div>
                                        <div class="log-detail-row">
                                            <span class="log-detail-label">"Level:"</span>
                                            <span class={ format!("log-detail-value log-level lvl-{}", entry.level.css()) }>{ level_text }</span>
                                        </div>
                                        <div class="log-detail-row">
                                            <span class="log-detail-label">"Source IP:"</span>
                                            <span class="log-detail-value">{ ip }</span>
                                        </div>
                                        <div class="log-detail-row">
                                            <span class="log-detail-label">"Route:"</span>
                                            <span class="log-detail-value">{ route }</span>
                                        </div>
                                        <div class="log-detail-row">
                                            <span class="log-detail-label">"Source:"</span>
                                            <span class="log-detail-value">{ entry.source.clone() }</span>
                                        </div>
                                        <div class="log-detail-row log-detail-row-full">
                                            <span class="log-detail-label">"Message:"</span>
                                            <pre class="log-detail-msg">{ entry.msg.clone() }</pre>
                                        </div>
                                    </div>
                                </div>
                            }
                        } else {
                            view! { <div></div> }
                        }
                    }
                }
            </div>
        </div>
    }
}

#[component]
pub fn LogTerminal() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    // `SignalVec` is cheap (Rc-backed) but not `Copy` — give each `move`
    // closure below its own handle.
    let for_list = app.visible.clone();
    let count_list = app.visible.clone();
    let empty_list = app.visible.clone();
    let scroll_list = app.visible.clone();
    let auto_scroll = app.auto_scroll;

    let shown = memo!(move || format!("{}", count_list.len()));
    let is_empty = memo!(move || empty_list.len() == 0);

    let node = view! {
        <section class="panel terminal">
            <div class="panel-head">
                <h2 class="panel-title">"Log Terminal"</h2>
                <span class="panel-meta">{ shown } " lines in view"</span>
            </div>

            <div class="term-body" id="log-terminal">
                {
                    move || if is_empty.get() {
                        view! { <div class="term-empty">"No events match. Start the live stream or drop a log file."</div> }
                    } else {
                        DomNode::empty()
                    }
                }
                {
                    for e in for_list key = |e: &LogEntry| e.id {
                        <LogRow entry={ e.clone() } />
                    }
                }
            </div>
        </section>
    };

    // Auto-scroll effect. Created *after* `view!` — and therefore after the
    // keyed reconciler's effect — so on every list change the DOM is already
    // updated when we measure scrollHeight. Reading `len()` subscribes it.
    effect!(move || {
        let _rows = scroll_list.len();
        if auto_scroll.get() {
            scroll_to_bottom();
        }
    });

    node
}

/// Jump the terminal viewport to the newest row (no-op before mount).
fn scroll_to_bottom() {
    if let Some(el) = document().get_element_by_id("log-terminal") {
        el.set_scroll_top(el.scroll_height());
    }
}
