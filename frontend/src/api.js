// Thin API client. Uses relative /api paths (Vite proxies to the backend).

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
  modules: () => fetch("/api/modules").then(j),
  listScans: () => fetch("/api/scans").then(j),
  getScan: (id) => fetch(`/api/scans/${id}`).then(j),
  createScan: (payload) =>
    fetch("/api/scans", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    }).then(j),
  deleteScan: (id) => fetch(`/api/scans/${id}`, { method: "DELETE" }).then(j),
  reportHtmlUrl: (id) => `/api/scans/${id}/report.html`,
  reportJsonUrl: (id) => `/api/scans/${id}/report.json`,
};
