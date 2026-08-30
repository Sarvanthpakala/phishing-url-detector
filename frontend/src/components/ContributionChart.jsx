import React from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { BarChart2 } from "lucide-react";

export default function ContributionChart({ contributions }) {
  if (!contributions || contributions.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 flex items-center justify-center text-sm text-slate-500">
        No per-feature contribution data available for this prediction.
      </div>
    );
  }

  const data = [...contributions]
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
    .slice(0, 8)
    .map((c) => ({ name: c.feature.replace(/_/g, " "), contribution: c.contribution }));

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 md:col-span-2">
      <div className="flex items-center gap-2 mb-3">
        <BarChart2 className="w-4 h-4 text-cyan-400" />
        <h3 className="font-semibold text-sm">Top feature contributions</h3>
      </div>
      <ResponsiveContainer width="100%" height={280}>
        <BarChart data={data} layout="vertical" margin={{ left: 100 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis type="number" stroke="#64748b" fontSize={11} />
          <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} width={140} />
          <Tooltip
            contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", fontSize: 12 }}
            labelStyle={{ color: "#e2e8f0" }}
          />
          <Bar dataKey="contribution" radius={[0, 4, 4, 0]}>
            {data.map((d, i) => (
              <Cell key={i} fill={d.contribution >= 0 ? "#dc2626" : "#16a34a"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <p className="text-xs text-slate-500 mt-2">Red pushes the score toward phishing, green pushes toward legitimate.</p>
    </div>
  );
}
