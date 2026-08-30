import React from "react";
import { ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react";

const RISK_STYLES = {
  Low: { color: "text-risk-low", bg: "bg-risk-low/10", border: "border-risk-low/40", icon: ShieldCheck },
  Medium: { color: "text-risk-medium", bg: "bg-risk-medium/10", border: "border-risk-medium/40", icon: AlertTriangle },
  High: { color: "text-risk-high", bg: "bg-risk-high/10", border: "border-risk-high/40", icon: ShieldAlert },
  Critical: { color: "text-risk-critical", bg: "bg-risk-critical/10", border: "border-risk-critical/40", icon: ShieldAlert },
};

export default function RiskScoreCard({ result }) {
  const style = RISK_STYLES[result.risk_level] || RISK_STYLES.Medium;
  const Icon = style.icon;
  const pct = Math.round(result.displayed_probability * 100);

  return (
    <div className={`rounded-xl border ${style.border} ${style.bg} p-5 space-y-4`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={`w-5 h-5 ${style.color}`} />
          <span className={`font-semibold text-lg ${style.color}`}>{result.risk_level} Risk</span>
        </div>
        <span className="text-xs uppercase tracking-wide bg-slate-800 px-2 py-1 rounded-full text-slate-300">
          {result.verdict}
        </span>
      </div>

      <div>
        <div className="flex justify-between text-xs text-slate-400 mb-1">
          <span>Phishing probability</span>
          <span>{pct}%</span>
        </div>
        <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
          <div
            className={`h-full rounded-full ${style.color.replace("text-", "bg-")}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm">
        <div className="bg-slate-950/50 rounded-lg p-3">
          <p className="text-slate-500 text-xs mb-0.5">Model confidence</p>
          <p className="font-semibold">{Math.round(result.confidence * 100)}%</p>
        </div>
        <div className="bg-slate-950/50 rounded-lg p-3">
          <p className="text-slate-500 text-xs mb-0.5">Model used</p>
          <p className="font-semibold truncate">{result.model_used}</p>
        </div>
      </div>

      <p className="text-xs text-slate-500 break-all border-t border-slate-800 pt-3">{result.url}</p>
    </div>
  );
}
