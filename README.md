# WebVAST — Web Vulnerability Assessment & Scanning Toolkit

A final-year project: a web-application penetration-testing toolkit that crawls a
target web application and scans it for four common classes of vulnerability —
**SQL injection**, **cross-site scripting (XSS)**, **security misconfiguration**,
and **outdated / vulnerable components** — then presents the results in a web
dashboard and exportable reports.

> ⚖️ **Legal & ethical notice.** This is a defensive security tool for testing
> applications **you own or are explicitly authorized to test**. Scanning systems
> without permission is illegal in most jurisdictions. The toolkit enforces an
> authorization gate, a scope allowlist, a global rate limit, and a host blocklist
> to keep testing contained. Use it only against the bundled demo target, the
> provided Docker lab, or targets you have written permission to assess.

---

## 1. Architecture

```
          ┌──────────────────────┐        ┌───────────────────────────────┐
          │  React + Tailwind UI │  HTTP  │          FastAPI API          │
          │  (dashboard, :5173)  │ ─────► │            (:8000)            │
          └──────────────────────┘        │  scans · findings · reports   │
                                          └───────────────┬───────────────┘
                                                          │
                                    ┌─────────────────────▼─────────────────────┐
                                    │               Scan Engine                 │
                                    │  Scope ▸ Crawler ▸ Scanner plugins ▸ dedupe│
                                    └───────┬───────────────────────┬───────────┘
                                            │                       │
                             ┌──────────────▼───────┐     ┌─────────▼──────────┐
                             │  Rate-limited, scope- │     │  SQLite (scans +   │
                             │  aware async HTTP      │     │  findings, aiosqlite)
                             │  client (httpx)        │     └────────────────────┘
                             └───────────┬───────────┘
                                         ▼
                             ┌───────────────────────┐
                             │  Target web application│
                             └───────────────────────┘
```

**Backend** — Python 3.9+, FastAPI, httpx, BeautifulSoup, aiosqlite.
**Frontend** — React 18 + Vite + Tailwind CSS.
**Storage** — a single SQLite file (no external services).

### Layout

```
webvast/
├── backend/
│   ├── app/
│   │   ├── config.py            # central, conservative settings
│   │   ├── main.py              # FastAPI app
│   │   ├── core/
│   │   │   ├── scope.py         # ⭐ scope enforcement (primary safety control)
│   │   │   ├── http_client.py   # rate-limited, scope-aware async client
│   │   │   ├── crawler.py       # BFS crawler → pages + injection points
│   │   │   └── engine.py        # orchestrates crawl + scanners
│   │   ├── scanners/
│   │   │   ├── base.py          # Finding / InjectionPoint / BaseScanner
│   │   │   ├── sqli.py          # error / boolean / time-based SQLi
│   │   │   ├── xss.py           # reflected + stored XSS
│   │   │   ├── misconfig.py     # headers, cookies, exposed files, errors
│   │   │   └── components.py    # version fingerprint vs signature DB
│   │   ├── signatures/components.json
│   │   ├── models/              # SQLite layer + pydantic schemas
│   │   ├── reporting/report.py  # HTML report (printable to PDF)
│   │   └── api/routes.py        # REST endpoints
│   └── demo_target/app.py       # intentionally-vulnerable practice app
├── frontend/                    # React + Tailwind dashboard
├── lab/                         # Docker vulnerable targets (Juice Shop, DVWA)
└── run.sh                       # one-command dev launcher
```

---

## 2. Quick start

### Fastest path (one command)

```bash
cd webvast
./run.sh
```

This creates the Python venv, installs everything, and starts the demo target
(:5001), the API (:8000) and the dashboard (:5173). Open
**http://localhost:5173**, enter `http://localhost:5001`, tick the authorization
box, and start a scan.

### Manual start

```bash
# 1. Backend
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000        # API + docs at /docs

# 2. Practice target (separate terminal, same venv)
python demo_target/app.py                         # http://localhost:5001

# 3. Frontend (separate terminal)
cd ../frontend
npm install
npm run dev                                       # http://localhost:5173
```

### Hosting the dashboard (frontend-only, e.g. Vercel)

The **dashboard is a static SPA** and can be hosted on Vercel/Netlify/any static
host. The **scan engine is not deployed** — it is a long-running, stateful backend
that makes outbound requests to targets, so it stays on a machine **you** control.
A hosted dashboard is just a UI: it is inert unless it is pointed at a backend that
is reachable *from your browser*, which in the default setup means your own machine.

> ⚠️ **Never expose a working scanner on a public URL.** A publicly reachable scan
> backend is an open attack tool (unauthorized scanning / SSRF). Keep the backend
> local, or firewalled and behind authentication, and only ever scan targets you
> are authorized to test.

**1. Point the dashboard at your backend.** The API base URL is a build-time env
var, `VITE_API_BASE` (see `frontend/.env.example`). Unset = local dev (Vite proxy).
For a hosted build, set it to the backend you run, e.g. `http://localhost:8000`
(browsers treat `localhost` as a secure context, so an HTTPS page may call it — but
only from the machine where that backend runs).

**2. Deploy on Vercel.** Import this repo, then in the project settings set:

| Setting | Value |
|---------|-------|
| **Root Directory** | `frontend` |
| **Framework Preset** | Vite (auto-detected) |
| **Environment Variable** | `VITE_API_BASE` = `http://localhost:8000` |

(`frontend/vercel.json` already pins the build command, output dir and SPA rewrite.)
Or with the CLI: `cd frontend && vercel --prod`.

**3. Allow the dashboard's origin on the backend.** Set `WEBVAST_CORS_ORIGINS` to a
comma-separated list of allowed origins before starting the API:

```bash
WEBVAST_CORS_ORIGINS="https://your-app.vercel.app" uvicorn app.main:app --port 8000
```

Then open your Vercel URL, run the backend locally, and scan the demo target.

---

## 3. How each scanner works

| Module | Technique | Signal |
|--------|-----------|--------|
| **SQL injection** | Inject `'`/`"` (error-based), `' AND '1'='1` vs `'1'='2` (boolean-based), and DB `SLEEP`/`WAITFOR`/`pg_sleep` (time-based) | DB error signatures, response-similarity divergence, or a measurable response delay |
| **XSS** | Inject a unique harmless canary containing HTML metacharacters; for forms, resubmit then re-crawl | The canary reflected/persisted **unencoded** in the response |
| **Misconfiguration** | Observe response headers/cookies; probe well-known sensitive paths | Missing CSP/HSTS/etc., insecure cookie flags, exposed `.env`/`.git`, directory listing, stack traces, version banners |
| **Components** | Fingerprint JS libs (script URLs / inline banners) and the server banner | Version below the `fixed_in` of an entry in `signatures/components.json` |

All probes are **non-destructive** — the scanner only reads or introduces a timing
delay; it never injects `DROP`/`DELETE`/`UPDATE` or runs working exploit payloads.

Findings carry a severity (critical→info), a confidence level, the affected
URL/parameter, the evidence, a CWE id, and concrete remediation advice.

---

## 4. Safety controls (by design)

1. **Authorization gate** — the API rejects any scan request unless `authorized`
   is explicitly `true`; the UI requires a confirmation checkbox.
2. **Scope enforcement** — every outbound request passes through `Scope`; requests
   to out-of-scope hosts are refused before they are sent (`core/scope.py`).
3. **Host blocklist** — major third-party domains are hard-blocked in `config.py`.
4. **Rate limiting + concurrency cap** — a global token interval and semaphore keep
   request volume low and lab-friendly (`core/http_client.py`).
5. **Crawl ceilings** — `max_pages` / `max_depth` bound the scan.

---

## 5. REST API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/scans` | start a scan (`{target_url, modules, authorized}`) |
| `GET` | `/api/scans` | list scans |
| `GET` | `/api/scans/{id}` | scan detail + findings |
| `DELETE` | `/api/scans/{id}` | delete a scan |
| `GET` | `/api/scans/{id}/report.html` | printable HTML report |
| `GET` | `/api/scans/{id}/report.json` | JSON export |
| `GET` | `/api/modules` | available scanner modules |

Interactive docs: **http://localhost:8000/docs**.

---

## 6. Limitations & future work

A deliberately-scoped MVP. Natural extensions for the dissertation / viva:

- **Authenticated scanning** (login sequence, session/cookie reuse).
- **Live CVE feeds** — query the NVD / GitHub Advisory API instead of the local
  signature file, and fingerprint back-end frameworks.
- **More vuln classes** — CSRF, SSRF, path traversal, open redirect, command
  injection, IDOR.
- **DOM-based XSS** via a headless browser (Playwright) to execute client JS.
- **CVSS scoring** and PDF export server-side (e.g. WeasyPrint).
- **Scan profiles**, scheduling, and diffing results between runs.

---

## 7. Disclaimer

Provided for educational and authorized-testing purposes only. The authors accept
no liability for misuse. You are responsible for ensuring you have permission to
test any target you point this tool at.
