import { useState } from "react";
import { Link } from "react-router-dom";
import { get, type IncidentSummary } from "../api";
import { ErrorBox, Loading, RiskBadge, Section, StatusBadge, fmtTime, pct, useApi } from "../components/ui";

export default function Incidents() {
  const [level, setLevel] = useState("");
  const [status, setStatus] = useState("");
  const [minRisk, setMinRisk] = useState("41");
  const { data, error, loading } = useApi(
    () => get<{ total: number; items: IncidentSummary[] }>("/api/incidents", { level, status, min_risk: minRisk, limit: 300 }),
    [level, status, minRisk]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Incidents</h1>
        <p className="text-sm text-slate-400">Alerts correlated across identity, network, compute and storage layers into attack narratives, ranked by explainable risk.</p>
      </div>
      <div className="card flex flex-wrap gap-2">
        <select className="input" value={level} onChange={(e) => setLevel(e.target.value)}>
          {["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"].map((l) => <option key={l} value={l}>{l || "all levels"}</option>)}
        </select>
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
          {["", "open", "investigating", "contained", "resolved", "false_positive"].map((s) => <option key={s} value={s}>{s || "all statuses"}</option>)}
        </select>
        <select className="input" value={minRisk} onChange={(e) => setMinRisk(e.target.value)}>
          <option value="">any risk</option><option value="41">risk ≥ 41 (MEDIUM+)</option><option value="61">risk ≥ 61 (HIGH+)</option><option value="81">risk ≥ 81 (CRITICAL)</option>
        </select>
      </div>
      {error ? <ErrorBox error={error} /> : loading && !data ? <Loading /> : (
        <Section title={`${data?.total} incidents`}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr><th className="th">Risk</th><th className="th">Incident</th><th className="th">Window</th><th className="th">Alerts / events</th><th className="th">Correlation</th><th className="th">Identities</th><th className="th">MITRE</th><th className="th">Status</th></tr></thead>
              <tbody>
                {data?.items.map((i) => (
                  <tr key={i.incident_id} className="border-t border-slate-800 hover:bg-slate-800/40">
                    <td className="td"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
                    <td className="td"><Link className="text-sky-300 hover:underline" to={`/incidents/${i.incident_id}`}>{i.title}</Link></td>
                    <td className="td whitespace-nowrap text-slate-400">{fmtTime(i.start)}</td>
                    <td className="td">{i.alert_count} / {i.event_count}</td>
                    <td className="td">{pct(i.correlation_score)}</td>
                    <td className="td mono">{i.actors.slice(0, 3).join(", ")}{i.actors.length > 3 && "…"}</td>
                    <td className="td text-xs text-slate-400">{i.mitre.slice(0, 3).map((m) => m.id).join(" ")}</td>
                    <td className="td"><StatusBadge status={i.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </div>
  );
}
