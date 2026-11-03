// Thin API client.
//
// The backend base URL is configurable via the VITE_API_BASE build-time env var:
//   - Local dev (default): leave it unset. Requests use relative "/api" paths,
//     which the Vite dev server proxies to http://127.0.0.1:8000 (see vite.config.js).
//   - Hosted frontend (e.g. Vercel): set VITE_API_BASE to the URL of the backend
//     you run yourself, e.g. "http://localhost:8000" or "https://your-backend.example".
//     The backend must allow this frontend's origin via CORS (WEBVAST_CORS_ORIGINS).
//
// Trailing slashes are trimmed so VITE_API_BASE="http://localhost:8000/" also works.
const BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/+$/, "");

const url = (path) => `${BASE}${path}`;

async function j(res) {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail
        ? Array.isArray(body.detail)
          ? body.detail.map((d) => d.msg).join("; ")
          : body.detail
        : detail;
    } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

export const api = {
  modules: () => fetch(url("/api/modules")).then(j),
  listScans: () => fetch(url("/api/scans")).then(j),
  getScan: (id) => fetch(url(`/api/scans/${id}`)).then(j),
  createScan: (payload) =>
    fetch(url("/api/scans"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    }).then(j),
  deleteScan: (id) => fetch(url(`/api/scans/${id}`), { method: "DELETE" }).then(j),
  reportHtmlUrl: (id) => url(`/api/scans/${id}/report.html`),
  reportJsonUrl: (id) => url(`/api/scans/${id}/report.json`),
};
