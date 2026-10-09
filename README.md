# CyberFlow — GritShield SOC

A hybrid **log aggregation + SOC threat-intelligence** service. A Rust backend
(GritShield + SeaORM/SQLite) streams logs to a WASM/Velo live console where
detection runs **client-side**, and confirmed threats are reported back and
persisted server-side. A built-in **MCP surface** exposes the threat intel to
agents and assistants.

```
 Browser (Velo/WASM @ :8080)
   │  live log stream (SSE)   ── GET  /api/v1/stream
   │  client-side detection   ── POST /api/v1/threats
   │  raw events              ── POST /api/v1/logs
   ▼
 GritShield backend (@ 127.0.0.1:8010)
   ├─ 10k ring buffer + SSE fan-out
   ├─ SQLite persistence (threats, ip_blacklist)
   └─ MCP tools/prompts       ── POST /mcp
```

## Layout

| Path            | What it is                                              |
|-----------------|---------------------------------------------------------|
| `backend/`      | GritShield + SeaORM backend (ingestion, SSE, threats)   |
| `frontend/`     | Velo/WASM console (live tail, drop-zone ingest, detections) |
| `docs/api.md`   | Full API contract for the frontend & integrations       |
| `backend/scripts/submit-logs.ps1` | Demo script to push sample logs        |

## 1. Run the backend

```bash
cd backend
cargo run
```

Defaults: `http://127.0.0.1:8010`, SQLite file `logs_soc.db`, API open.
CORS is enabled so the browser on `:8080` can stream/push freely.

| Env var          | Default                            |
|------------------|------------------------------------|
| `SOC_BIND`       | `127.0.0.1`                        |
| `SOC_PORT`       | `8010`                             |
| `DATABASE_URL`   | `sqlite://logs_soc.db?mode=rwc`    |
| `SOC_API_KEY`    | *(unset → open API)*               |

Features (compile-time): default `sqlite, mcp`. Disable with
`cargo run --no-default-features` (MCP surface and drivers are gated on them).

## 2. Run the frontend

```bash
cd frontend
velo build        # produces dist/
# serve dist/ on :8080, e.g.:
npx serve dist -l 8080     (or any static server)
```

Open **http://localhost:8080** — you should see the live threat console
connecting to the backend stream.

> `velo dev` also works if you prefer a live-reload dev server.

## 3. See it move (live stream demo)

With the backend running, in one terminal open the stream:

```bash
curl -N http://127.0.0.1:8010/api/v1/stream
```

In another, push sample logs (INFO / DEBUG / ERROR / CRITICAL, 100 by default):

```powershell
pwsh backend/scripts/submit-logs.ps1            # default 100 logs
pwsh backend/scripts/submit-logs.ps1 -Count 500
pwsh backend/scripts/submit-logs.ps1 -ApiKey topsecret   # key mode
```

Every push is acknowledged with the number of live SSE consumers

```json
{ "accepted": 5, "live_consumers": 1 }
```

and the open stream prints each event as it lands:

```
event: log
data: {"ts":1791516829135.0,"level":"CRITICAL","ip":"198.51.100.66","route":"/auth","msg":"token replay detected"}
```

## 4. API surface

Full contract: **[docs/api.md](docs/api.md)**. Quick map:

| Endpoint                | Method | Purpose                                    |
|-------------------------|--------|--------------------------------------------|
| `/health`               | GET    | Liveness + ring-buffer stats               |
| `/api/v1/logs`          | POST   | Ingest single event or `{"events":[...]}`  |
| `/api/v1/stream`        | GET    | SSE live tail (`event: log`, replay + live)|
| `/api/v1/threats`       | POST   | Persist a confirmed threat                 |
| `/mcp`                  | POST   | JSON-RPC MCP — tools & prompts             |

MCP tooling:
- `get_active_threats` → list persisted threats (`limit`, `severity`)
- `add_ip_blacklist` → block an IP immediately (in-memory + persisted)
- `summarize_incident` → stakeholder summary from recent events

## 5. Runtime protections

- API key: `X-API-Key` header **or** `?api_key=` query param (the latter is
  required by `EventSource`, which cannot set headers).
- Rate limit: 120 req/min per IP → `429` + `Retry-After`.
- Body limit: 512 KiB per request → `413` (framework caps at 1 MiB).
- IP blacklist: blocked IPs get `403 ip_blacklisted` on every endpoint.
- Hardening headers (`X-Content-Type-Options`, `X-Frame-Options`, CSP-ish
  `Referrer-Policy`, `Cache-Control: no-store`) + `X-SOC-Response-Time-Ms`.

## Notes for consumers of the SSE stream

1. **History replay is newest-first** — reverse the replay block (or use
   `?since=<epoch_ms>`) for an ascending timeline.
2. `ts` serializes as a `f64` and may render with a trailing `.0`
   (`1791516829135.0`) — compare numerically, never with `===`.
3. `event` is always `log`; keep-alive arrives as SSE comment frames.

Built with [GritShield](https://github.com/digiator42/GritShield) (v0.3.1,
path dep) and [Velo](https://github.com/digiator42/Velo).