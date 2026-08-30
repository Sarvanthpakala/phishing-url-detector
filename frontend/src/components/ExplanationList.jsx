import React from "react";
import { ListChecks } from "lucide-react";

export default function ExplanationList({ reasons }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-center gap-2 mb-3">
        <ListChecks className="w-4 h-4 text-cyan-400" />
        <h3 className="font-semibold text-sm">Why this verdict?</h3>
      </div>
      <ul className="space-y-2">
        {reasons.map((r, i) => (
          <li key={i} className="text-sm text-slate-300 flex gap-2">
            <span className="text-cyan-500 mt-1">&bull;</span>
            <span>{r}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
