//! Live log terminal: keyed, fine-grained rows over the filtered log stream.
//!
//! Built to hold up under the framework verification target of **100+
//! events/sec**: rows are appended by the keyed reconciler (only new nodes
//! are created), filters recompute into a single batched `with_mut` write,
//! and the DOM is trimmed in batches rather than per-push (see
//! `VISIBLE_TRIM_AT`).

use velo::prelude::*;

use crate::state::{format_time, AppState, LogEntry};

/// One terminal line. Takes the whole entry as an owned prop so the keyed
/// `for` body can pass `entry.clone()` — `view!` expression slots are `move`
/// closures and must not borrow the loop variable.
#[component]
pub fn LogRow(entry: LogEntry) -> DomNode {
    // Each local below is captured by exactly one `move` closure in the view
    // (or consumed by `class=`), so no clone-per-use is needed.
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
        <div class={ row_class } title={ source }>
            <span class="log-time">{ time }</span>
            <span class={ level_class }>{ level_text }</span>
            <span class="log-meta">{ meta }</span>
            <span class="log-msg">{ msg }</span>
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
