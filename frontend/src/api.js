// API client with automatic live/demo mode.
//
// Mode is decided once per session:
//   - "live": talk to a real WebVAST backend over HTTP.
//   - "demo": serve a self-contained captured scan from the browser, making no
//     network requests (see ./demo/demoApi.js).
//
// Selection:
//   - VITE_DEMO truthy at build time  -> always demo.
//   - otherwise probe the backend once; if it answers, "live"; if not, "demo".
// This means the same build runs live locally (backend up) and automatically
// shows the demo on a hosted URL that can't reach a backend. No public live
// scanner is ever exposed.
//
// VITE_API_BASE sets the backend base URL in live mode (see .env.example).
// Unset -> relative "/api" paths, proxied by the Vite dev server.

import { demoApi } from "./demo/demoApi";

const BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/+$/, "");
const FORCE_DEMO = !!import.meta.env.VITE_DEMO;

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

// --- live implementation --------------------------------------------------
const liveApi = {
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

// --- mode resolution ------------------------------------------------------
let resolved = null; // "live" | "demo" once known (sync-readable)
let probe = null;

export function resolveMode() {
  if (FORCE_DEMO) {
    resolved = "demo";
    return Promise.resolve("demo");
  }
  if (!probe) {
    probe = (async () => {
      try {
        const res = await fetch(url("/api/modules"), {
          signal: AbortSignal.timeout(2500),
        });
        resolved = res.ok ? "live" : "demo";
      } catch (_) {
        resolved = "demo";
      }
      return resolved;
    })();
  }
  return probe;
}

async function impl() {
  return (await resolveMode()) === "demo" ? demoApi : liveApi;
}

// Reports are referenced as hrefs during render; by then mode is resolved
// (a detail view only renders after getScan succeeded). Default to live.
const reportImpl = () => (resolved === "demo" ? demoApi : liveApi);

export const api = {
  modules: async () => (await impl()).modules(),
  listScans: async () => (await impl()).listScans(),
  getScan: async (id) => (await impl()).getScan(id),
  createScan: async (payload) => (await impl()).createScan(payload),
  deleteScan: async (id) => (await impl()).deleteScan(id),
  reportHtmlUrl: (id) => reportImpl().reportHtmlUrl(id),
  reportJsonUrl: (id) => reportImpl().reportJsonUrl(id),
};
