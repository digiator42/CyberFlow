//! Local file ingestion: drag-drop (or browse) a log file, then stream it
//! chunk-by-chunk into a Web Worker that runs the parsing + detection engine
//! off the UI thread. This component only pumps `Blob.stream()` and renders
//! progress; see [`crate::worker`].
//!
//! Streaming (rather than `FileReader` whole-file reads) keeps the UI
//! responsive on multi-hundred-MB captures: only one chunk is ever in flight,
//! and all CPU-heavy work happens on the worker.

use velo::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::Event;

use crate::state::{AppState, Mode};
use crate::worker;

#[component]
pub fn DropZone() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let mode = app.mode;
    let conn = app.conn;
    let drag = signal!(false);

    let in_local = memo!(move || mode.get() == Mode::Local);

    let drag_class = memo!(move || {
        if drag.get() {
            "dropzone drag-over".to_string()
        } else {
            "dropzone".to_string()
        }
    });

    // Analysis progress mirrors. Each `move` memo needs its own handle to
    // the (cheap, Rc-backed) `Analysis` struct.
    let a_active = app.analysis.clone();
    let a_file = app.analysis.clone();
    let a_pct = app.analysis.clone();
    let a_bar = app.analysis.clone();
    let a_lines = app.analysis.clone();
    let analyzing = memo!(move || a_active.active.get());
    let file_name = memo!(move || a_file.file.get());
    let progress_label = memo!(move || format!("{:.0}%", a_pct.progress.get() * 100.0));
    let bar_style = memo!(move || format!("width: {:.0}%", a_bar.progress.get() * 100.0));
    let lines_label = memo!(move || format!("{}", a_lines.lines.get()));

    // Live-mode fallback status.
    let conn_css = memo!(move || format!("conn-dot {}", conn.get().css()));
    let conn_label = memo!(move || conn.get().label().to_string());
    let endpoint = crate::api::STREAM_PATH;

    let app_drop = app.clone();
    let app_browse = app.clone();

    view! {
        <section class="panel ingest">
            <div class="panel-head">
                <h2 class="panel-title">"File Ingestion"</h2>
            </div>

            <div
                class="stream-status"
                style:display={ move || if in_local.get() { "none".to_string() } else { "flex".to_string() } }
            >
                <span class={ conn_css }></span>
                <span class="conn-text">{ conn_label }</span>
                <code class="endpoint">{ endpoint }</code>
                <p class="stream-hint">
                    "Live mode streams from GritShield. Switch to LOCAL FILE ANALYSIS to inspect captured log files offline."
                </p>
            </div>

            <div
                class={ drag_class }
                style:display={ move || if in_local.get() { "flex".to_string() } else { "none".to_string() } }
                on:dragover={ move |ev: Event| {
                    ev.prevent_default();
                    drag.set(true);
                } }
                on:dragleave={ move |_| drag.set(false) }
                on:drop={ move |ev: Event| {
                    ev.prevent_default();
                    drag.set(false);
                    if app_drop.analysis.active.get() {
                        return;
                    }
                    let Some(de) = ev.dyn_ref::<web_sys::DragEvent>() else { return; };
                    let Some(dt) = de.data_transfer() else { return; };
                    let Some(files) = dt.files() else { return; };
                    let Some(file) = files.get(0) else { return; };
                    start_analysis(&app_drop, file);
                } }
            >
                <Show when={ analyzing } fallback={
                    view! {
                        <div class="drop-hint">
                            <div class="drop-icon">"⇩"</div>
                            <div class="drop-title">"Drop log files here"</div>
                            <div class="drop-sub">".log · .txt · .jsonl — parsed locally, nothing is uploaded"</div>
                            <label class="browse-label">
                                "or click to browse"
                                <input
                                    type="file"
                                    class="file-input"
                                    accept=".log,.txt,.jsonl"
                                    on:change={ move |ev: Event| {
                                        let Some(target) = ev.target() else { return; };
                                        let Ok(input) = target.dyn_into::<web_sys::HtmlInputElement>() else { return; };
                                        let Some(files) = input.files() else { return; };
                                        let Some(file) = files.get(0) else { return; };
                                        input.set_value("");
                                        start_analysis(&app_browse, file);
                                    } }
                                />
                            </label>
                        </div>
                    }
                }>
                    <div class="analysis">
                        <div class="analysis-file">{ file_name }</div>
                        <div class="progress-track">
                            <div class="progress-fill" style={ bar_style }></div>
                        </div>
                        <div class="analysis-meta">
                            <span class="analysis-pct">{ progress_label }</span>
                            <span class="analysis-lines">{ lines_label } " lines parsed"</span>
                        </div>
                    </div>
                </Show>
            </div>
        </section>
    }
}

/// Kick off a background stream-read of `file`; parsing + detection run in the
/// [`crate::worker`].
fn start_analysis(app: &AppState, file: web_sys::File) {
    worker::spawn_analysis(app, file);
}
