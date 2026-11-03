import { useState } from "react";
import { api } from "../api";
import { SEV_ORDER, SeverityBadge } from "./Severity";

const CARD_BG = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

function Finding({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-slate-200 bg-white">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        <SeverityBadge severity={f.severity} />
        <span className="flex-1 font-medium">{f.title}</span>
        {f.cwe && <span className="text-xs text-slate-400">{f.cwe}</span>}
        <span className="text-slate-400">{open ? "–" : "+"}</span>
      </button>
      {open && (
        <div className="space-y-2 border-t border-slate-100 px-4 py-3 text-sm">
          <p className="text-slate-700">{f.description}</p>
          <Row label="URL" mono>{f.url}</Row>
          {f.parameter && <Row label="Parameter" mono>{f.parameter}</Row>}
          {f.payload && <Row label="Payload" mono>{f.payload}</Row>}
          {f.evidence && <Row label="Evidence" mono>{f.evidence}</Row>}
          <Row label="Confidence">{f.confidence}</Row>
          <div className="rounded-md bg-emerald-50 p-3 text-emerald-900 ring-1 ring-emerald-100">
            <span className="font-semibold">Remediation: </span>
            {f.remediation}
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ label, children, mono }) {
  return (
    <div className="flex gap-2">
      <span className="w-20 shrink-0 font-semibold text-slate-500">{label}</span>
      <span className={mono ? "break-all font-mono text-xs text-slate-700" : "text-slate-700"}>
        {children}
      </span>
    </div>
  );
}

export default function ScanDetail({ scan, onDeleted }) {
  if (!scan) {
    return (
      <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white p-10 text-sm text-slate-500">
        Select a scan to view its findings.
      </div>
    );
  }

  const running = scan.status === "running" || scan.status === "queued";

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{scan.target_url}</h2>
          <p className="font-mono text-xs text-slate-400">
            {scan.id} · {scan.status} · {scan.duration_s}s ·{" "}
            {scan.pages_crawled} pages · {scan.requests_sent} requests
          </p>
        </div>
        <div className="flex gap-2">
          <a
            href={api.reportHtmlUrl(scan.id)}
            target="_blank"
            rel="noreferrer"
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
          >
            HTML report
          </a>
          <a
            href={api.reportJsonUrl(scan.id)}
            target="_blank"
            rel="noreferrer"
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
          >
            JSON
          </a>
          <button
            onClick={() => api.deleteScan(scan.id).then(onDeleted)}
            className="rounded-lg border border-red-200 px-3 py-1.5 text-sm text-red-600 hover:bg-red-50"
          >
            Delete
          </button>
        </div>
      </div>

      {running && (
        <div className="mt-4">
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200">
            <div
              className="h-full bg-blue-500 transition-all"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <p className="mt-1 text-sm text-slate-500">{scan.stage}</p>
        </div>
      )}

      {scan.error && (
        <div className="mt-4 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800">
          {scan.error}
        </div>
      )}

      <div className="mt-5 grid grid-cols-5 gap-2">
        {SEV_ORDER.map((s) => (
          <div
            key={s}
            className={`rounded-lg p-3 text-center text-white ${CARD_BG[s]}`}
          >
            <div className="text-2xl font-bold">{scan.severity_counts[s] || 0}</div>
            <div className="text-[11px] uppercase tracking-wide opacity-90">{s}</div>
          </div>
        ))}
      </div>

      {!running && (
        <div className="mt-5 space-y-2">
          <h3 className="text-sm font-semibold text-slate-500">
            {scan.findings.length} finding{scan.findings.length === 1 ? "" : "s"}
          </h3>
          {scan.findings.map((f) => (
            <Finding key={f.id} f={f} />
          ))}
          {scan.findings.length === 0 && (
            <p className="text-sm text-slate-500">
              No vulnerabilities detected by the selected modules.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
