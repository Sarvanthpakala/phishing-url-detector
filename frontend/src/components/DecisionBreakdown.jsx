import React from "react";
import { Scale } from "lucide-react";

export default function DecisionBreakdown({ result }) {
  const { model_probability, final_score, ml_weight, live_weight, decision_breakdown, live_verification_performed } = result;

  if (!live_verification_performed) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 md:col-span-2">
        <p className="text-xs text-slate-500 italic">
          Live verification was skipped for this scan — the score shown is the raw ML structural prediction only.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 md:col-span-2 space-y-3">
      <div className="flex items-center gap-2">
        <Scale className="w-4 h-4 text-cyan-400" />
        <h3 className="font-semibold text-sm">Final Score Composition</h3>
      </div>
      <p className="text-xs text-slate-500">
        The verdict is not decided by the ML model alone: it blends the model's structural prediction (weight{" "}
        {Math.round(ml_weight * 100)}%) with a live-verification risk score (weight {Math.round(live_weight * 100)}%),
        then applies hard floors for near-certain signals (unresolvable domain, confirmed brand impersonation, or a
        threat-intel hit).
      </p>

      <div className="grid grid-cols-2 gap-3 text-sm">
        <div className="bg-slate-950/50 rounded-lg p-3">
          <p className="text-slate-500 text-xs mb-0.5">ML structural score</p>
          <p className="font-semibold">{Math.round(model_probability * 100)}%</p>
        </div>
        <div className="bg-slate-950/50 rounded-lg p-3">
          <p className="text-slate-500 text-xs mb-0.5">Final adjusted score</p>
          <p className="font-semibold">{Math.round(final_score * 100)}%</p>
        </div>
      </div>

      {decision_breakdown && decision_breakdown.length > 0 ? (
        <div>
          <p className="text-xs text-slate-500 mb-1.5">Live-verification rules that fired:</p>
          <ul className="space-y-1">
            {decision_breakdown.map((c, i) => (
              <li key={i} className="text-xs text-slate-300 flex justify-between gap-3 bg-slate-950/40 rounded px-2 py-1">
                <span>{c.detail}</span>
                <span className="text-cyan-400 shrink-0">+{Math.round(c.weight * 100)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-xs text-slate-600 italic">No live-verification risk rules fired for this URL.</p>
      )}
    </div>
  );
}
