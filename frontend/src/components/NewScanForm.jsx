import { useEffect, useState } from "react";
import { api } from "../api";

export default function NewScanForm({ onCreated }) {
  const [modules, setModules] = useState([]);
  const [selected, setSelected] = useState({
    sqli: true,
    xss: true,
    misconfig: true,
    components: true,
  });
  const [target, setTarget] = useState("http://127.0.0.1:5001");
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.modules().then(setModules).catch(() => {});
  }, []);

  async function submit(e) {
    e.preventDefault();
    setError("");
    if (!authorized) {
      setError("You must confirm authorization before scanning.");
      return;
    }
    const mods = Object.keys(selected).filter((k) => selected[k]);
    if (mods.length === 0) {
      setError("Select at least one scan module.");
      return;
    }
    setBusy(true);
    try {
      const scan = await api.createScan({
        target_url: target.trim(),
        modules: mods,
        authorized: true,
      });
      onCreated(scan);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={submit}
      className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
    >
      <h2 className="mb-4 text-lg font-semibold">New scan</h2>

      <label className="mb-1 block text-sm font-medium">Target URL</label>
      <input
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="http://localhost:5001"
        className="mb-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
      />

      <div className="mb-4 grid grid-cols-2 gap-2">
        {modules.map((m) => (
          <label
            key={m.key}
            className="flex cursor-pointer items-start gap-2 rounded-lg border border-slate-200 p-2 text-sm hover:bg-slate-50"
          >
            <input
              type="checkbox"
              checked={!!selected[m.key]}
              onChange={(e) =>
                setSelected((s) => ({ ...s, [m.key]: e.target.checked }))
              }
              className="mt-0.5"
            />
            <span>
              <span className="font-medium">{m.name}</span>
              <span className="block text-xs text-slate-500">
                {m.description}
              </span>
            </span>
          </label>
        ))}
      </div>

      <label className="mb-4 flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-200">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
          className="mt-0.5"
        />
        <span>
          I confirm I own this target or have explicit written permission to
          test it. Unauthorized scanning may be illegal.
        </span>
      </label>

      {error && (
        <div className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
          {error}
        </div>
      )}

      <button
        disabled={busy}
        className="w-full rounded-lg bg-slate-900 py-2.5 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50"
      >
        {busy ? "Starting…" : "Start scan"}
      </button>
    </form>
  );
}
