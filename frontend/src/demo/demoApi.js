// Demo backend — a self-contained, in-browser stand-in for the WebVAST API.
//
// Used when the dashboard has no reachable backend (e.g. the hosted Vercel
// build, which must never be wired to a public live scanner). It serves a
// real captured scan and simulates running a new one, so the live URL is a
// faithful, risk-free showcase. No network requests are made in demo mode.

import { SAMPLE_MODULES, SAMPLE_SCAN, SAMPLE_REPORT_HTML } from "./sampleData";

const SIM = SAMPLE_SCAN.findings; // template findings to replay for new scans

// --- in-memory store ------------------------------------------------------
const store = new Map();
seed();

function seed() {
  store.clear();
  // Deep clone so the seeded scan can be deleted/re-created without mutation.
  store.set(SAMPLE_SCAN.id, structuredClone(SAMPLE_SCAN));
}

function sortedScans() {
  return [...store.values()].sort((a, b) =>
    (b.created_at || "").localeCompare(a.created_at || "")
  );
}

function summary(s) {
  // ScanList/App only need these fields; findings are omitted from the list.
  const { findings, ...rest } = s;
  return rest;
}

function originOf(u) {
  try {
    return new URL(u).origin;
  } catch {
    return null;
  }
}

// Re-point a template finding at the user's chosen target for a bit of realism.
function retarget(finding, target) {
  const srcOrigin = originOf(SAMPLE_SCAN.target_url);
  const dstOrigin = originOf(target);
  if (!srcOrigin || !dstOrigin) return structuredClone(finding);
  const swap = (v) =>
    typeof v === "string" ? v.split(srcOrigin).join(dstOrigin) : v;
  const f = structuredClone(finding);
  f.url = swap(f.url);
  f.evidence = swap(f.evidence);
  return f;
}

function countSeverities(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) if (c[f.severity] !== undefined) c[f.severity]++;
  return c;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const newId = () =>
  "demo" + Math.random().toString(16).slice(2, 10).padEnd(8, "0");

// --- simulated scan lifecycle --------------------------------------------
async function runSimulation(id, target, modules) {
  const steps = [
    { progress: 10, stage: "Resolving scope…" },
    { progress: 30, stage: `Crawling ${target}` },
    { progress: 55, stage: `Scanning: ${modules.join(", ")}` },
    { progress: 80, stage: "Analysing responses…" },
    { progress: 95, stage: "Compiling findings…" },
  ];
  for (const step of steps) {
    await sleep(700);
    const s = store.get(id);
    if (!s) return; // deleted mid-run
    Object.assign(s, { status: "running", ...step });
  }
  await sleep(600);
  const s = store.get(id);
  if (!s) return;
  const findings = SIM.filter((f) => modules.includes(f.type)).map((f, i) => {
    const rt = retarget(f, target);
    rt.id = `${id}-f${i + 1}`;
    rt.scan_id = id;
    return rt;
  });
  Object.assign(s, {
    status: "completed",
    progress: 100,
    stage: "",
    findings,
    severity_counts: countSeverities(findings),
    finished_at: new Date().toISOString(),
    duration_s: 4.6,
    pages_crawled: 5,
    requests_sent: 41,
  });
}

// --- report blob URLs (cached so hrefs are stable across re-renders) ------
const reportCache = new Map(); // id -> { html, json }

function reportUrls(id) {
  const s = store.get(id);
  if (!s) return { html: "about:blank", json: "about:blank" };
  let entry = reportCache.get(id);
  // Rebuild once the scan has findings (i.e. finished) so reports aren't empty.
  if (!entry || entry.status !== s.status) {
    if (entry) {
      URL.revokeObjectURL(entry.html);
      URL.revokeObjectURL(entry.json);
    }
    const dst = originOf(s.target_url);
    const src = originOf(SAMPLE_SCAN.target_url);
    const html =
      dst && src ? SAMPLE_REPORT_HTML.split(src).join(dst) : SAMPLE_REPORT_HTML;
    entry = {
      status: s.status,
      html: URL.createObjectURL(new Blob([html], { type: "text/html" })),
      json: URL.createObjectURL(
        new Blob([JSON.stringify(s, null, 2)], { type: "application/json" })
      ),
    };
    reportCache.set(id, entry);
  }
  return entry;
}

// --- public API (mirrors ../api.js) --------------------------------------
export const demoApi = {
  modules: async () => structuredClone(SAMPLE_MODULES),
  listScans: async () => sortedScans().map(summary),
  getScan: async (id) => {
    const s = store.get(id);
    if (!s) throw new Error("Scan not found");
    return structuredClone(s);
  },
  createScan: async ({ target_url, modules }) => {
    const id = newId();
    const scan = {
      id,
      target_url: target_url || "http://localhost:5001",
      modules,
      status: "queued",
      progress: 0,
      stage: "Queued",
      created_at: new Date().toISOString(),
      finished_at: null,
      pages_crawled: 0,
      requests_sent: 0,
      duration_s: 0,
      severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      error: null,
      findings: [],
    };
    store.set(id, scan);
    runSimulation(id, scan.target_url, modules); // fire-and-forget
    return structuredClone(scan);
  },
  deleteScan: async (id) => {
    store.delete(id);
    const e = reportCache.get(id);
    if (e) {
      URL.revokeObjectURL(e.html);
      URL.revokeObjectURL(e.json);
      reportCache.delete(id);
    }
    return { ok: true };
  },
  reportHtmlUrl: (id) => reportUrls(id).html,
  reportJsonUrl: (id) => reportUrls(id).json,
};
