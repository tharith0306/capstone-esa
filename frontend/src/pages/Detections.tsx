import { useState } from "react";
import { Link } from "react-router-dom";
import { get, type Detection } from "../api";
import { Badge, ErrorBox, Loading, Section, fmtTime, human, useApi } from "../components/ui";

const CLASSES = ["", "brute_force", "credential_compromise", "reconnaissance", "privilege_escalation", "data_exfiltration", "defense_evasion", "resource_abuse"];

function Meter({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded bg-slate-800"><div className="h-1.5 rounded" style={{ width: `${value * 100}%`, background: color }} /></div>
      <span className="text-xs text-slate-400">{value.toFixed(2)}</span>
    </div>
  );
}

export default function Detections() {
  const [cls, setCls] = useState("");
  const [kind, setKind] = useState("");
  const { data, error, loading } = useApi(
    () => get<{ total: number; items: Detection[] }>("/api/detections", { predicted_class: cls, kind, limit: 300 }), [cls, kind]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Detections</h1>
        <p className="text-sm text-slate-400">
          Per-entity 15-minute windows scored by Isolation Forest (anomaly, ECDF vs. normal activity) and XGBoost (attack class),
          plus deterministic rules (logging tampering, GuardDuty findings).
        </p>
      </div>
      <div className="card flex flex-wrap gap-2">
        <select className="input" value={cls} onChange={(e) => setCls(e.target.value)}>{CLASSES.map((c) => <option key={c} value={c}>{c ? human(c) : "all classes"}</option>)}</select>
        <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">ML + rules</option><option value="model">ML only</option><option value="rule">rules only</option>
        </select>
      </div>
      {error ? <ErrorBox error={error} /> : loading && !data ? <Loading /> : (
        <Section title={`${data?.total} detections`}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr><th className="th">Window</th><th className="th">Entity</th><th className="th">Predicted</th><th className="th">Attack prob (XGBoost)</th><th className="th">Anomaly (IF)</th><th className="th">Source</th><th className="th">Incident</th></tr></thead>
              <tbody>
                {data?.items.map((d) => (
                  <tr key={d.detection_id} className="border-t border-slate-800 hover:bg-slate-800/40">
                    <td className="td whitespace-nowrap text-slate-400">{fmtTime(d.start)}</td>
                    <td className="td mono">{d.entity}</td>
                    <td className="td">{human(d.predicted_class)} <span className="text-xs text-slate-500">{d.class_probability.toFixed(2)}</span></td>
                    <td className="td"><Meter value={d.attack_probability} color="#fb923c" /></td>
                    <td className="td"><Meter value={d.anomaly_score} color="#a78bfa" /></td>
                    <td className="td">{d.kind === "model" ? <Badge className="bg-sky-500/10 text-sky-300 ring-sky-500/30">ML</Badge> : <Badge className="bg-pink-500/10 text-pink-300 ring-pink-500/30">{d.rule}</Badge>}</td>
                    <td className="td">{d.incident_id && <Link className="mono text-sky-300 hover:underline" to={`/incidents/${d.incident_id}`}>{d.incident_id.slice(0, 12)}…</Link>}</td>
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
