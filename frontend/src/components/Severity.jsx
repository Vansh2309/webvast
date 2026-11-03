// Severity colour helpers. Full class strings are listed literally so Tailwind's
// JIT compiler can see them (it cannot detect dynamically-built class names).

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const BADGE = {
  critical: "bg-sev-critical text-white",
  high: "bg-sev-high text-white",
  medium: "bg-sev-medium text-white",
  low: "bg-sev-low text-white",
  info: "bg-sev-info text-white",
};

const DOT = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export function SeverityBadge({ severity }) {
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${
        BADGE[severity] || "bg-slate-500 text-white"
      }`}
    >
      {severity}
    </span>
  );
}

export function SeverityCounts({ counts }) {
  return (
    <div className="flex gap-1">
      {SEV_ORDER.map((s) =>
        counts[s] ? (
          <span
            key={s}
            title={`${counts[s]} ${s}`}
            className={`flex h-5 min-w-[20px] items-center justify-center rounded px-1 text-[11px] font-bold text-white ${DOT[s]}`}
          >
            {counts[s]}
          </span>
        ) : null
      )}
    </div>
  );
}
