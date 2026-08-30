import React from "react";

const RISK_COLORS = {
  Low: "text-risk-low",
  Medium: "text-risk-medium",
  High: "text-risk-high",
  Critical: "text-risk-critical",
};

export default function ScanHistoryTable({ rows }) {
  if (!rows || rows.length === 0) {
    return <p className="text-sm text-slate-500">No scans yet — run one from the Scan tab.</p>;
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-800/60 text-slate-400 text-xs uppercase">
          <tr>
            <th className="text-left px-4 py-2">URL</th>
            <th className="text-left px-4 py-2">Verdict</th>
            <th className="text-left px-4 py-2">Risk</th>
            <th className="text-left px-4 py-2">Probability</th>
            <th className="text-left px-4 py-2">Model</th>
            <th className="text-left px-4 py-2">Scanned</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-t border-slate-800/60">
              <td className="px-4 py-2 max-w-[260px] truncate text-slate-300">{r.url}</td>
              <td className="px-4 py-2">{r.prediction}</td>
              <td className={`px-4 py-2 font-medium ${RISK_COLORS[r.risk_level] || ""}`}>{r.risk_level}</td>
              <td className="px-4 py-2 text-slate-400">{Math.round(r.probability * 100)}%</td>
              <td className="px-4 py-2 text-slate-400">{r.model_used}</td>
              <td className="px-4 py-2 text-slate-500 text-xs">{r.created_at?.slice(0, 19).replace("T", " ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
