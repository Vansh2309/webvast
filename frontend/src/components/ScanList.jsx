import { SeverityCounts } from "./Severity";

const STATUS_STYLE = {
  queued: "bg-slate-100 text-slate-600",
  running: "bg-blue-100 text-blue-700",
  completed: "bg-emerald-100 text-emerald-700",
  failed: "bg-red-100 text-red-700",
};

export default function ScanList({ scans, selectedId, onSelect }) {
  if (!scans.length) {
    return (
      <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 text-center text-sm text-slate-500">
        No scans yet. Start one on the left.
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {scans.map((s) => (
        <button
          key={s.id}
          onClick={() => onSelect(s.id)}
          className={`block w-full rounded-xl border bg-white p-4 text-left shadow-sm transition hover:border-slate-400 ${
            selectedId === s.id ? "border-slate-900 ring-1 ring-slate-900" : "border-slate-200"
          }`}
        >
          <div className="flex items-center justify-between gap-3">
            <span className="truncate font-medium">{s.target_url}</span>
            <span
              className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                STATUS_STYLE[s.status] || "bg-slate-100"
              }`}
            >
              {s.status}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400">{s.id}</span>
            {s.status === "running" || s.status === "queued" ? (
              <div className="h-1.5 w-32 overflow-hidden rounded-full bg-slate-200">
                <div
                  className="h-full bg-blue-500 transition-all"
                  style={{ width: `${s.progress}%` }}
                />
              </div>
            ) : (
              <SeverityCounts counts={s.severity_counts} />
            )}
          </div>
          {(s.status === "running" || s.status === "queued") && (
            <div className="mt-1 truncate text-xs text-slate-500">{s.stage}</div>
          )}
        </button>
      ))}
    </div>
  );
}
