import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import NewScanForm from "./components/NewScanForm";
import ScanList from "./components/ScanList";
import ScanDetail from "./components/ScanDetail";

export default function App() {
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const pollRef = useRef(null);

  const refreshList = useCallback(async () => {
    try {
      setScans(await api.listScans());
    } catch (_) {}
  }, []);

  const refreshDetail = useCallback(async (id) => {
    if (!id) return;
    try {
      setDetail(await api.getScan(id));
    } catch (_) {}
  }, []);

  // Poll: list + currently-selected scan, every 1.5s. Keeps progress live.
  useEffect(() => {
    refreshList();
    pollRef.current = setInterval(() => {
      refreshList();
      if (selectedId) refreshDetail(selectedId);
    }, 1500);
    return () => clearInterval(pollRef.current);
  }, [refreshList, refreshDetail, selectedId]);

  useEffect(() => {
    refreshDetail(selectedId);
  }, [selectedId, refreshDetail]);

  function onCreated(scan) {
    setSelectedId(scan.id);
    refreshList();
  }

  function onDeleted() {
    setSelectedId(null);
    setDetail(null);
    refreshList();
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900 font-bold text-white">
              W
            </div>
            <div>
              <h1 className="text-lg font-bold leading-tight">WebVAST</h1>
              <p className="text-xs text-slate-500">
                Web Vulnerability Assessment &amp; Scanning Toolkit
              </p>
            </div>
          </div>
          <span className="rounded-full bg-amber-50 px-3 py-1 text-xs font-medium text-amber-800 ring-1 ring-amber-200">
            Authorized testing only
          </span>
        </div>
      </header>

      <main className="mx-auto grid max-w-6xl grid-cols-1 gap-5 px-6 py-6 lg:grid-cols-[320px_minmax(0,1fr)]">
        <div className="space-y-5">
          <NewScanForm onCreated={onCreated} />
          <div>
            <h2 className="mb-2 px-1 text-sm font-semibold text-slate-500">
              Scan history
            </h2>
            <ScanList
              scans={scans}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          </div>
        </div>
        <ScanDetail scan={detail} onDeleted={onDeleted} />
      </main>
    </div>
  );
}
