# Logs-SOC Backend — API contract for the frontend

Backend lives in `backend/` (GritShield + SeaORM/SQLite). Default address:
`http://127.0.0.1:8010`. All JSON bodies use `Content-Type: application/json`.

Any deviations from the contract already sketched in `src/api.rs` are marked
**`[IMPORTANT]`**.

---

## Base URL and routing

| Setting    | Env var            | Default           |
|------------|--------------------|-------------------|
| Bind host  | `SOC_BIND`         | `127.0.0.1`       |
| Port       | `SOC_PORT`         | `8010`            |
| SQLite DSN | `SOC_DATABASE_URL` | `sqlite://logs_soc.db?mode=rwc` |
| API key    | `SOC_API_KEY`      | *(unset → open)*  |

Run it:

```bash
cd backend && cargo run
```

---

## Auth

- When `SOC_API_KEY` is **unset**, every endpoint is open (this is the default,
  and it is what the current frontend needs: its `API_KEY` const is empty).
- When set, both `POST /api/v1/logs`, `POST /api/v1/threats`, `GET /api/v1/stream`
  and `/mcp` require either:
  - header `X-API-Key: <key>`, or
  - query param `?api_key=<key>` — **this is the variant the frontend must use**:
    `EventSource` cannot set headers. The frontend's `stream_url()` already
    appends `api_key` when configured; keep that behavior.
- Wrong/missing key → `401 {"error":"unauthorized", ...}`.

---

## `GET /health`

Liveness + pipeline stats.

```json
{
  "service": "logs-soc-backend",
  "status": "ok",
  "db": true,
  "buffers": {
    "history_count": 0,       // events currently in the ring buffer (cap 10_000)
    "history_capacity": 10000,
    "live_streams": 0,        // open SSE connections
    "received_total": 0,      // events ingested since boot
    "attached_total": 0
  }
}
```

---

## `POST /api/v1/logs` — ingest

Accepts **either** a single event **or** a batch:

```jsonc
// single
{ "ts": 1720524000000, "level": "WARN", "ip": "203.0.113.9", "route": "/login", "msg": "failed password attempt" }

// batch
{ "events": [ { "...": "..." }, { "...": "..." } ] }
```

Field rules (`LogEvent`):

| Field  | Type   | Default on ingest |
|--------|--------|-------------------|
| `ts`   | number | epoch **milliseconds** as `f64`; `0` or missing → server stamps the time |
| `level`| string | case-insensitive → normalized to `DEBUG\|INFO\|WARN\|ERROR\|CRITICAL`; anything else becomes `INFO` |
| `ip`   | string | `""` |
| `route`| string | `""` |
| `msg`  | string | `""` |

```json
// 202 Accepted
{ "accepted": 1, "live_consumers": 0 }
```

- `400` for non-JSON body, an unparseable event, or an empty batch.
- `413` `{"error":"payload_too_large","max":524288}` for bodies over 512 KiB.
- `429` `{"error":"rate_limited"}` (+ `Retry-After`) past 120 req/min/IP.

**Frontend note:** fire-and-forget is fine for the current UI.

---

## `GET /api/v1/stream` — SSE live tail  **[IMPORTANT deviations]**

Event name is always **`log`**. `data` is a JSON string of the `LogEvent`
fields above (`ts, level, ip, route, msg`).

```
event: log
data: {"ts":1791502110914.0,"level":"WARN","ip":"203.0.113.9","route":"/login","msg":"failed password attempt"}
```

1. **History replay is newest-first.** On connect the most recent
   `?history=` events (default 50, max 1000) are emitted before any live frame.
   If the frontend wants an ascending timeline it must reverse the replay block
   (or use `?since=<epoch_ms>` and only show events `>=` that watermark).
2. Numerical `ts` values are serialized as `f64` and may render with a trailing
   `.0` (e.g. `1791502110914.0`); `JSON.parse` in the browser yields a plain
   `number` either way — compare numerically, never `===`.
3. Keep-alive is a comment frame (`: keep-alive`) every 15 s; `EventSource`
   surfaces it as nothing, so the frontend just ignores non-`log` events.
4. `?api_key=` query param is honoured here precisely because `EventSource`
   cannot send headers (see Auth).

---

## `POST /api/v1/threats` — report a threat

Body (`Threat` — `id` is the **frontend-generated** id):

```json
{
  "id": 42,
  "ts_ms": 1720524000000,
  "severity": "high",
  "rule_id": "soc-07",
  "rule_name": "Brute force burst",
  "ip": "203.0.113.9",
  "payload": "many login failures",
  "origin": "detector"
}
```

- `severity` is any of `low | medium | high | critical` (case-insensitive);
  unknown→`medium`.
- `ts_ms <= 0` or missing → server stamps it.
- Persisted to SQLite (`threats` table); survives restarts.

```json
// 201 Created
{ "accepted": true, "id": 1, "frontend_id": 42 }
```

`id` is the **database row id** (backend-assigned); `frontend_id` echoes back
the UI's own id. `400` on a malformed body, `500` on persisting failure.

---

## MCP surface (agent tooling, not needed by the UI)

Mounted automatically by `Router::new()` at:

- `POST /mcp` (JSON-RPC 2.0) — relocate with `MCP_HTTP_PREFIX=/agent`.

Exposed tools/prompts:

| Kind | Name | Purpose |
|------|------|---------|
| tool | `get_active_threats` | List persisted threats (`limit`, optional `severity`) |
| tool | `add_ip_blacklist` | Block an IP immediately (in-memory) + persist (`ip`, optional `reason`); blocked IPs get `403 ip_blacklisted` from every endpoint |
| prompt | `summarize_incident` | Stakeholder summary from recent ring-buffer events + optional `threat_id` |

`add_ip_blacklist` blocks only future requests from that client IP in the
current running process; the persisted row is what survives restart.

---

## Error model

- `400` malformed JSON / schema (`{"error":"invalid_json"|"invalid_log_event"|"invalid_threat"|"no_events"}`)
- `401` missing/invalid API key
- `403` IP blacklisted (`{"error":"ip_blacklisted","ip":...}`)
- `413` payload too large (JSON; above 1 MiB total the framework's parser may
  answer a plain `400 Bad Request` first — treat both as "too big")
- `429` rate limited (`Retry-After: 60`)
- `500` persistence failure

Responses carry `X-SOC-Response-Time-Ms`, `X-Content-Type-Options`, and
`Referrer-Policy` hardening headers automatically.