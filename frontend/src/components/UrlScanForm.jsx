import React, { useState } from "react";
import { Search, Globe2 } from "lucide-react";

export default function UrlScanForm({ onScan, loading }) {
  const [url, setUrl] = useState("");
  const [liveIntel, setLiveIntel] = useState(true);

  function submit(e) {
    e.preventDefault();
    if (!url.trim()) return;
    onScan(url.trim(), liveIntel);
  }

  return (
    <form onSubmit={submit} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/login"
            className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-3 py-2.5 text-sm outline-none focus:border-cyan-500 transition"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-medium text-sm transition"
        >
          Scan URL
        </button>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={liveIntel}
          onChange={(e) => setLiveIntel(e.target.checked)}
          className="accent-cyan-500 w-4 h-4"
        />
        <Globe2 className="w-3.5 h-3.5" />
        Live SSL / DNS / WHOIS / redirect / brand-similarity verification (recommended, needs internet)
      </label>
    </form>
  );
}
