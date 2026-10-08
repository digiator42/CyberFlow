//! Local file ingestion: drag-drop (or browse) a log file, stream it through
//! `Blob.stream()` with incremental line splitting, and feed every parsed
//! line through the same [`crate::ingest::ingest_events`] pipeline the SSE
//! stream uses. In Live mode the panel instead reports stream status.
//!
//! Streaming (rather than `FileReader` whole-file reads) keeps the UI
//! responsive on multi-hundred-MB captures: only one chunk + one line buffer
//! are ever resident.

use js_sys::Reflect;
use velo::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::Event;

use crate::ingest;
use crate::state::{AppState, LogEvent, Mode};

/// Events are flushed to state in batches of this size during a file read.
const FLUSH_EVERY: usize = 200;

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

            <Show when={ in_local } fallback={
                view! {
                    <div class="stream-status">
                        <span class={ conn_css }></span>
                        <span class="conn-text">{ conn_label }</span>
                        <code class="endpoint">{ endpoint }</code>
                        <p class="stream-hint">
                            "Live mode streams from GritShield. Switch to LOCAL FILE ANALYSIS to inspect captured log files offline."
                        </p>
                    </div>
                }
            }>
                <div
                    class={ drag_class }
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
                                            let Some(input) = ev.dyn_ref::<web_sys::HtmlInputElement>() else { return; };
                                            let Some(files) = input.files() else { return; };
                                            let Some(file) = files.get(0) else { return; };
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
            </Show>
        </section>
    }
}

/// Kick off a background stream-read + analysis of `file`.
fn start_analysis(app: &AppState, file: web_sys::File) {
    if app.analysis.active.get() {
        web_sys::console::warn_1(&"analysis already in progress".into());
        return;
    }
    let app = app.clone();
    wasm_bindgen_futures::spawn_local(analyze_file(app, file));
}

/// Stream `file` chunk-by-chunk, split complete lines, and ingest them in
/// batches. Bytes are split on `0x0A` before decoding, so multi-byte UTF-8
/// sequences can never be torn (continuation bytes are never `0x0A`).
async fn analyze_file(app: AppState, file: web_sys::File) {
    let origin = format!("file:{}", file.name());
    let total = file.size();

    app.analysis.file.set(file.name());
    app.analysis.active.set(true);
    app.analysis.progress.set(0.0);
    app.analysis.lines.set(0);

    let stream = file.stream();
    // `get_reader()` returns a bare `Object` — narrow it to the default reader.
    let reader = match stream
        .get_reader()
        .dyn_into::<web_sys::ReadableStreamDefaultReader>()
    {
        Ok(reader) => reader,
        Err(_) => {
            web_sys::console::error_1(&"cannot open file reader".into());
            app.analysis.active.set(false);
            return;
        }
    };

    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut batch: Vec<LogEvent> = Vec::with_capacity(FLUSH_EVERY);
    let mut bytes_read = 0.0f64;

    loop {
        let chunk = match JsFuture::from(reader.read()).await {
            Ok(value) => value,
            Err(_) => break,
        };

        let done = Reflect::get(&chunk, &"done".into())
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if done {
            break;
        }

        let Ok(value) = Reflect::get(&chunk, &"value".into()) else {
            continue;
        };
        let Ok(array) = value.dyn_into::<js_sys::Uint8Array>() else {
            continue;
        };

        let bytes = array.to_vec();
        bytes_read += bytes.len() as f64;
        buf.extend_from_slice(&bytes);

        // Drain every complete line from the buffer.
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&buf[..=pos]).into_owned();
            buf.drain(..=pos);
            if let Some(ev) = ingest::parse_raw_line(&line) {
                batch.push(ev);
            }
        }

        if batch.len() >= FLUSH_EVERY {
            flush(&app, &origin, &mut batch);
            app.analysis.progress.set((bytes_read / total).min(1.0));
        }
    }

    // Trailing line without a final newline.
    if !buf.is_empty() {
        let line = String::from_utf8_lossy(&buf).into_owned();
        if let Some(ev) = ingest::parse_raw_line(&line) {
            batch.push(ev);
        }
    }
    flush(&app, &origin, &mut batch);

    app.analysis.progress.set(1.0);
    app.analysis.active.set(false);
}

/// Push a collected batch through the shared ingestion pipeline.
fn flush(app: &AppState, origin: &str, batch: &mut Vec<LogEvent>) {
    if batch.is_empty() {
        return;
    }
    let count = batch.len() as u32;
    app.analysis.lines.update(|l| *l += count);
    let events = std::mem::take(batch);
    ingest::ingest_events(app, origin, events);
}
