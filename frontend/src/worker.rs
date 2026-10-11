//! Web Worker offload for file ingestion.
//!
//! The UI thread only *reads* the dropped file (a cheap `ReadableStream`
//! pump) and posts each `Uint8Array` chunk to a dedicated Web Worker. The
//! worker runs the same Rust engine as the main thread - incremental line
//! splitting, [`crate::ingest::parse_raw_line`], and the full
//! [`crate::detection::Detector`] (signatures + Shannon entropy + rate
//! windows) - and posts back compact batches of parsed events and rule hits.
//!
//! Because parsing and detection never run on the UI thread, the terminal
//! keeps scrolling at 60 FPS even while a multi-hundred-MB capture is being
//! analysed. Raw bytes never leave the machine: only the derived events/hits
//! cross the worker boundary.
//!
//! The worker is bootstrapped by `webworker.js` (copied to the dist root by
//! Trunk), which imports the *same* wasm module and calls the `#[wasm_bindgen]`
//! entry points below. `main()` in [`crate::lib`] detects the worker context
//! via a missing `window` and skips mounting the app there.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};
use veloasm::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::detection::{Detector, RuleHit};
use crate::ingest;
use crate::state::{AppState, LogEvent};

// ---------------------------------------------------------------------------
// Worker-side engine (runs off the UI thread)
// ---------------------------------------------------------------------------

thread_local! {
    /// Persistent worker state: the rate detector must survive across chunks,
    /// and the byte buffer holds a partial line between chunks.
    static ENGINE: RefCell<Engine> = RefCell::new(Engine::new());
}

struct Engine {
    detector: Detector,
    lines: LineBuffer,
    batch: Vec<LogEvent>,
    hits: Vec<RuleHit>,
}

impl Engine {
    fn new() -> Self {
        Self {
            detector: Detector::new(),
            lines: LineBuffer::new(),
            batch: Vec::new(),
            hits: Vec::new(),
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    /// Feed `bytes` and emit every complete line it completes. `ts` is stamped
    /// here (off the UI thread) so rate windows see real times.
    fn push_chunk(&mut self, bytes: &[u8]) {
        self.batch.clear();
        self.hits.clear();
        let batch = &mut self.batch;
        let hits = &mut self.hits;
        let detector = &mut self.detector;
        self.lines.push(bytes, |line| inspect(detector, batch, hits, line));
    }

    /// Flush any trailing line that lacked a final newline.
    fn finish(&mut self) {
        self.batch.clear();
        self.hits.clear();
        let batch = &mut self.batch;
        let hits = &mut self.hits;
        let detector = &mut self.detector;
        self.lines.finish(|line| inspect(detector, batch, hits, line));
    }

    fn take(&mut self) -> BatchResult {
        BatchResult {
            events: std::mem::take(&mut self.batch),
            hits: std::mem::take(&mut self.hits),
        }
    }
}

/// Parse one raw line, run detection, and stage the event + hits.
fn inspect(detector: &mut Detector, batch: &mut Vec<LogEvent>, hits: &mut Vec<RuleHit>, line: String) {
    let Some(mut ev) = ingest::parse_raw_line(&line) else {
        return;
    };
    if ev.ts <= 0.0 {
        ev.ts = js_sys::Date::now();
    }
    for hit in detector.inspect(&ev) {
        hits.push(RuleHit {
            index: batch.len(),
            rule_id: hit.rule_id.to_string(),
            title: hit.title.to_string(),
            severity: hit.severity,
        });
    }
    batch.push(ev);
}

/// Pure, wasm-free incremental line splitter.
///
/// Bytes are split on `0x0A` before UTF-8 decoding, so a multi-byte sequence
/// torn across two chunks is safe: continuation bytes are never `0x0A`, so a
/// line boundary can only fall on a character boundary.
struct LineBuffer {
    buf: Vec<u8>,
}

impl LineBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64 * 1024),
        }
    }

    fn push(&mut self, bytes: &[u8], mut on_line: impl FnMut(String)) {
        self.buf.extend_from_slice(bytes);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..=pos]).into_owned();
            self.buf.drain(..=pos);
            on_line(line);
        }
    }

    fn finish(&mut self, mut on_line: impl FnMut(String)) {
        if self.buf.is_empty() {
            return;
        }
        let line = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        on_line(line);
    }
}

struct BatchResult {
    events: Vec<LogEvent>,
    hits: Vec<RuleHit>,
}

/// A batch crossing the worker boundary, tagged for the main-thread dispatcher.
#[derive(Serialize)]
struct Batch<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    events: &'a [LogEvent],
    hits: &'a [RuleHit],
}

fn encode(result: &BatchResult) -> String {
    if result.events.is_empty() {
        return String::new();
    }
    serde_json::to_string(&Batch {
        kind: "batch",
        events: &result.events,
        hits: &result.hits,
    })
    .unwrap_or_default()
}

/// Initialize (or re-initialize) the worker engine. Called once by
/// `webworker.js` immediately after the wasm module boots.
#[wasm_bindgen]
pub fn worker_start() {
    ENGINE.with(|e| e.borrow_mut().reset());
}

/// Drop all buffered state and reset the rate detector for a new file.
#[wasm_bindgen]
pub fn worker_reset() {
    ENGINE.with(|e| e.borrow_mut().reset());
}

/// Feed one chunk of raw file bytes; returns a JSON batch (empty string when
/// the chunk contained no complete lines).
#[wasm_bindgen]
pub fn worker_chunk(bytes: &[u8]) -> String {
    ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        e.push_chunk(bytes);
        encode(&e.take())
    })
}

/// Flush the trailing partial line and return the final JSON batch.
#[wasm_bindgen]
pub fn worker_finish() -> String {
    ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        e.finish();
        encode(&e.take())
    })
}

// ---------------------------------------------------------------------------
// Main-thread orchestration
// ---------------------------------------------------------------------------

thread_local! {
    /// The single long-lived analysis worker (created on first file drop).
    static WORKER: RefCell<Option<web_sys::Worker>> = const { RefCell::new(None) };
    /// `origin` label stamped onto rows from the file currently being read.
    static ORIGIN: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Messages the worker posts back to the main thread.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WorkerMsg {
    Ready,
    Done,
    Batch {
        events: Vec<LogEvent>,
        hits: Vec<RuleHit>,
    },
}

/// Start streaming `file` through the analysis worker. No-op if a file is
/// already being analysed.
pub fn spawn_analysis(app: &AppState, file: web_sys::File) {
    if app.analysis.active.get() {
        web_sys::console::warn_1(&"analysis already in progress".into());
        return;
    }
    let app = app.clone();
    wasm_bindgen_futures::spawn_local(analyze_file(app, file));
}

/// Lazily create the worker and wire its message handler.
fn ensure_worker(app: &AppState) {
    WORKER.with(|slot| {
        if slot.borrow().is_some() {
            return;
        }
        let Some(worker) = create_worker(app) else {
            web_sys::console::error_1(&"cannot start analysis worker".into());
            return;
        };
        *slot.borrow_mut() = Some(worker);
    });
}

fn create_worker(app: &AppState) -> Option<web_sys::Worker> {
    let document = web_sys::window()?.document()?;

    // Trunk emits `<link rel="modulepreload" href=".../<hash>.js">`; the worker
    // imports that same module so the hashed filename never needs hardcoding.
    let js_url = document
        .query_selector("link[rel=modulepreload]")
        .ok()
        .flatten()
        .and_then(|el| el.get_attribute("href"))?;

    let options = web_sys::WorkerOptions::new();
    options.set_type(web_sys::WorkerType::Module);
    let worker = web_sys::Worker::new_with_options("webworker.js", &options).ok()?;

    let app = app.clone();
    let on_message = wasm_bindgen::closure::Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        let Some(raw) = ev.data().as_string() else {
            return;
        };
        match serde_json::from_str::<WorkerMsg>(&raw) {
            Ok(WorkerMsg::Batch { events, hits }) => {
                let origin = ORIGIN.with(|o| o.borrow().clone());
                app.analysis.lines.update(|l| *l += events.len() as u32);
                ingest::ingest_precomputed(&app, &origin, events, hits);
            }
            Ok(WorkerMsg::Done) => {
                app.analysis.progress.set(1.0);
                app.analysis.active.set(false);
            }
            Ok(WorkerMsg::Ready) => {
                web_sys::console::debug_1(&"analysis worker ready".into());
            }
            Err(err) => {
                web_sys::console::warn_1(&format!("bad worker message: {err}").into())
            }
        }
    }) as Box<dyn FnMut(web_sys::MessageEvent)>);
    worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    // Hand the worker the module + wasm URLs it should import. The wasm URL is
    // explicit because Trunk hashes the filename, which wasm-bindgen's default
    // `import.meta.url`-relative path would miss.
    let wasm_url = wasm_url(&document, &js_url);
    let init = format!(
        "{{\"type\":\"init\",\"jsUrl\":{},\"wasmUrl\":{}}}",
        json_string(&js_url),
        json_string(&wasm_url)
    );
    let _ = worker.post_message(&JsValue::from_str(&init));

    Some(worker)
}

/// Resolve the hashed `_bg.wasm` URL, preferring Trunk's `<link rel="preload">`.
fn wasm_url(document: &web_sys::Document, js_url: &str) -> String {
    if let Ok(Some(el)) = document.query_selector("link[rel=preload][as=fetch]") {
        if let Some(href) = el.get_attribute("href") {
            return href;
        }
    }
    js_url
        .strip_suffix(".js")
        .map(|base| format!("{base}_bg.wasm"))
        .unwrap_or_else(|| js_url.to_string())
}

/// Post a raw `Uint8Array` chunk (JS `worker_chunk` receives it directly).
fn post_chunk(array: &js_sys::Uint8Array) {
    WORKER.with(|slot| {
        if let Some(worker) = slot.borrow().as_ref() {
            let _ = worker.post_message(array.as_ref());
        }
    });
}

/// Post a control message (`reset` / `end`).
fn post_control(json: &str) {
    WORKER.with(|slot| {
        if let Some(worker) = slot.borrow().as_ref() {
            let _ = worker.post_message(&JsValue::from_str(json));
        }
    });
}

async fn analyze_file(app: AppState, file: web_sys::File) {
    ensure_worker(&app);

    let origin = format!("file:{}", file.name());
    let total = file.size();

    app.analysis.file.set(file.name());
    app.analysis.active.set(true);
    app.analysis.progress.set(0.0);
    app.analysis.lines.set(0);
    ORIGIN.with(|o| *o.borrow_mut() = origin);

    post_control("{\"type\":\"reset\"}");

    let stream = file.stream();
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

    let mut bytes_read = 0.0f64;
    loop {
        let chunk = match JsFuture::from(reader.read()).await {
            Ok(value) => value,
            Err(_) => break,
        };

        let done = js_sys::Reflect::get(&chunk, &"done".into())
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if done {
            break;
        }

        let Ok(value) = js_sys::Reflect::get(&chunk, &"value".into()) else {
            continue;
        };
        let Ok(array) = value.dyn_into::<js_sys::Uint8Array>() else {
            continue;
        };

        let len = array.length() as f64;
        bytes_read += len;
        app.metrics
            .window_bytes
            .set(app.metrics.window_bytes.get().saturating_add(len as u32));
        post_chunk(&array);
        app.analysis.progress.set((bytes_read / total).min(1.0));
    }

    post_control("{\"type\":\"end\"}");
}

/// Minimal JSON string encoder for the one value we hand to the worker.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::LineBuffer;

    fn collect(chunks: &[&[u8]], finish: bool) -> Vec<String> {
        let mut lb = LineBuffer::new();
        let mut out = Vec::new();
        for c in chunks {
            lb.push(c, |line| out.push(line));
        }
        if finish {
            lb.finish(|line| out.push(line));
        }
        out
    }

    #[test]
    fn splits_lines_across_chunk_boundaries() {
        let out = collect(&[b"alpha\nbe", b"ta\ngamma\n"], false);
        assert_eq!(out, vec!["alpha\n", "beta\n", "gamma\n"]);
    }

    #[test]
    fn keeps_partial_line_until_newline_arrives() {
        let out = collect(&[b"no newline yet"], false);
        assert!(out.is_empty());
        let out = collect(&[b"no newline yet"], true);
        assert_eq!(out, vec!["no newline yet"]);
    }

    #[test]
    fn multibyte_char_torn_across_chunks_reassembles() {
        // "é" = 0xC3 0xA9; split between the two bytes, then a newline.
        let out = collect(&[&[0xC3], &[0xA9, b'\n']], false);
        assert_eq!(out, vec!["é\n"]);
    }

    #[test]
    fn blank_lines_are_emitted_and_filtered_upstream() {
        let out = collect(&[b"\n\n"], false);
        assert_eq!(out, vec!["\n", "\n"]);
    }
}

