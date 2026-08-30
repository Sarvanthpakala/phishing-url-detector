import React, { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { ShieldCheck, ShieldAlert, History as HistoryIcon, Download, Loader2 } from "lucide-react";
import UrlScanForm from "./components/UrlScanForm.jsx";
import RiskScoreCard from "./components/RiskScoreCard.jsx";
import ExplanationList from "./components/ExplanationList.jsx";
import ContributionChart from "./components/ContributionChart.jsx";
import DomainIntelligencePanel from "./components/DomainIntelligencePanel.jsx";
import DecisionBreakdown from "./components/DecisionBreakdown.jsx";
import ScanHistoryTable from "./components/ScanHistoryTable.jsx";

const API_BASE = "/api";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("scan");
  const [history, setHistory] = useState([]);
  const [modelReady, setModelReady] = useState(true);

  useEffect(() => {
    axios.get(`${API_BASE}/health`).then((r) => setModelReady(r.data.model_ready)).catch(() => setModelReady(false));
  }, []);

  const refreshHistory = useCallback(() => {
    axios.get(`${API_BASE}/history?limit=100`).then((r) => setHistory(r.data)).catch(() => {});
  }, []);

  useEffect(() => {
    if (tab === "history") refreshHistory();
  }, [tab, refreshHistory]);

  async function handleScan(url, includeLiveIntel) {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const resp = await axios.post(`${API_BASE}/predict`, { url, live_intel: includeLiveIntel });
      setResult(resp.data);
    } catch (e) {
      setError(e?.response?.data?.error || "Something went wrong while scanning that URL.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-7 h-7 text-cyan-400" />
            <div>
              <h1 className="text-lg font-semibold tracking-tight">PhishGuard</h1>
              <p className="text-xs text-slate-400">AI-powered phishing URL detection &amp; prevention</p>
            </div>
          </div>
          <nav className="flex gap-1 bg-slate-800/60 rounded-lg p-1">
            <button
              onClick={() => setTab("scan")}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition ${tab === "scan" ? "bg-cyan-600 text-white" : "text-slate-300 hover:text-white"}`}
            >
              Scan
            </button>
            <button
              onClick={() => setTab("history")}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition flex items-center gap-1.5 ${tab === "history" ? "bg-cyan-600 text-white" : "text-slate-300 hover:text-white"}`}
            >
              <HistoryIcon className="w-3.5 h-3.5" /> History
            </button>
          </nav>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10">
        {!modelReady && (
          <div className="mb-6 rounded-lg border border-amber-700 bg-amber-950/40 text-amber-300 px-4 py-3 text-sm flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            No trained model found yet. Run <code className="mx-1 px-1 py-0.5 bg-black/30 rounded">python train.py</code> in the backend folder, then reload.
          </div>
        )}

        {tab === "scan" && (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-semibold mb-1">Check a URL</h2>
              <p className="text-slate-400 text-sm">
                Static lexical/structural analysis by default. Enable live intel for a real-time SSL / DNS / WHOIS / redirect check (requires internet on the server).
              </p>
            </div>

            <UrlScanForm onScan={handleScan} loading={loading} />

            {error && (
              <div className="rounded-lg border border-red-800 bg-red-950/40 text-red-300 px-4 py-3 text-sm">{error}</div>
            )}

            {loading && (
              <div className="flex items-center gap-2 text-slate-400 text-sm">
                <Loader2 className="w-4 h-4 animate-spin" /> Analyzing URL...
              </div>
            )}

            {result && !loading && (
              <div className="grid md:grid-cols-2 gap-6">
                <RiskScoreCard result={result} />
                <ExplanationList reasons={result.reasons} />
                <DecisionBreakdown result={result} />
                <ContributionChart contributions={result.feature_contributions} />
                {result.live_intel && (
                  <DomainIntelligencePanel intel={result.live_intel} brand={result.brand_similarity} threat={result.threat_intel} />
                )}
              </div>
            )}
          </div>
        )}

        {tab === "history" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-semibold">Scan History</h2>
              <a
                href={`${API_BASE}/history/csv`}
                className="inline-flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 transition"
              >
                <Download className="w-3.5 h-3.5" /> Download CSV
              </a>
            </div>
            <ScanHistoryTable rows={history} />
          </div>
        )}
      </main>

      <footer className="max-w-5xl mx-auto px-6 py-8 text-xs text-slate-600">
        PhishGuard is a student major project. Predictions are model estimates, not a guarantee — always verify suspicious links independently.
      </footer>
    </div>
  );
}
