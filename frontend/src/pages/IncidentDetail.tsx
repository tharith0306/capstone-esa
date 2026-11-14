import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { get, patch, type Incident } from "../api";
import AttackGraph from "../components/AttackGraph";
import { ActionsPanel, RiskBreakdown, ShapPanel, Timeline } from "../components/IncidentPanels";
import { ErrorBox, Loading, RiskBadge, Section, StatusBadge, fmtTime, human, pct, useAnalyst, useApi } from "../components/ui";

const TABS = ["Summary", "Timeline", "Explainability", "Attack graph", "Evidence", "Response"] as const;
type Tab = (typeof TABS)[number];

interface Report { evidence_summary: { events: number; verified: number; all_verified: boolean }; audit_trail: { timestamp: string; actor: string; action: string; object_id: string }[] }

export default function IncidentDetail() {
  const { id } = useParams();
  const [tab, setTab] = useState<Tab>("Summary");
  const [onlyAttack, setOnlyAttack] = useState(true);
  const [analyst] = useAnalyst();
  const { data: inc, error, reload } = useApi(() => get<Incident>(`/api/incidents/${id}`), [id]);
  const report = useApi(() => (tab === "Evidence" ? get<Report>(`/api/incidents/${id}/report`) : Promise.resolve(null)), [id, tab]);
  const [notes, setNotes] = useState("");
  useEffect(() => setNotes(inc?.analyst_notes ?? ""), [inc?.analyst_notes]);

  if (error) return <ErrorBox error={error} />;
  if (!inc) return <Loading />;

  const update = async (body: Record<string, unknown>) => {
    await patch(`/api/incidents/${inc.incident_id}`, { ...body, analyst });
    reload();
  };

  return (
    <div className="space-y-4">
      <Link to="/incidents" className="text-xs text-sky-400">← Incidents</Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2"><RiskBadge level={inc.risk_level} score={inc.risk_score} /><StatusBadge status={inc.status} /></div>
          <h1 className="mt-2 text-xl font-semibold">{inc.title}</h1>
          <p className="text-sm text-slate-400">
            {fmtTime(inc.start)} → {fmtTime(inc.end)} · {inc.alert_count} alerts · {inc.event_count} events · correlation {pct(inc.correlation_score)} ·{" "}
            <span className="mono">{inc.incident_id}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {["investigating", "contained", "resolved", "false_positive"].map((s) => (
            <button key={s} className="btn-ghost py-1 text-xs" disabled={inc.status === s} onClick={() => update({ status: s })}>Mark {human(s).toLowerCase()}</button>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-slate-800">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === t ? "border-sky-400 text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
            {t}{t === "Response" && inc.actions.length ? ` (${inc.actions.length})` : ""}
          </button>
        ))}
      </div>

      {tab === "Summary" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Section title="Explainable risk score"><RiskBreakdown risk={inc.risk} /></Section>
          <div className="space-y-4">
            <Section title="Why this is suspicious">
              <ul className="list-disc space-y-1 pl-4 text-sm">{inc.explanation.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              {inc.explanation.reasons.length === 0 && <p className="text-sm text-slate-500">Rule-based incident (see timeline).</p>}
              <p className="mt-2 text-xs text-slate-500">Top risk drivers: {inc.risk.top_drivers.map(human).join(", ")}</p>
            </Section>
            <Section title="MITRE ATT&CK techniques">
              <div className="flex flex-wrap gap-2">
                {inc.mitre.map((m) => (
                  <a key={m.id} href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                     className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2 py-1 text-xs text-indigo-200 hover:bg-indigo-500/20">
                    <b>{m.id}</b> {m.name} <span className="text-indigo-400">· {m.tactic} ×{m.count}</span>
                  </a>
                ))}
              </div>
            </Section>
            <Section title="Entities involved">
              <dl className="grid grid-cols-[120px_1fr] gap-y-1 text-sm">
                <dt className="text-slate-500">Identities</dt><dd className="mono">{inc.actors.join(", ") || "—"}</dd>
                <dt className="text-slate-500">Source IPs</dt><dd className="mono">{inc.source_ips.join(", ") || "—"}</dd>
                <dt className="text-slate-500">Access keys</dt><dd className="mono break-all">{inc.access_keys.join(", ") || "—"}</dd>
                <dt className="text-slate-500">Resources</dt><dd className="mono break-all">{inc.resources.slice(0, 12).join(", ") || "—"}</dd>
              </dl>
            </Section>
            <Section title="Analyst notes" actions={<button className="btn-primary py-1 text-xs" onClick={() => update({ analyst_notes: notes })}>Save</button>}>
              <textarea className="input h-24 w-full" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Findings, hypotheses, next steps…" />
            </Section>
          </div>
          <Section title="Correlated detections" className="xl:col-span-2">
            <table className="w-full">
              <thead><tr><th className="th">Window</th><th className="th">Entity</th><th className="th">Class</th><th className="th">Attack p</th><th className="th">Anomaly</th><th className="th">Source</th></tr></thead>
              <tbody>{inc.detections.map((d) => (
                <tr key={d.detection_id} className="border-t border-slate-800">
                  <td className="td text-slate-400">{fmtTime(d.start)}</td><td className="td mono">{d.entity}</td><td className="td">{human(d.predicted_class)}</td>
                  <td className="td">{d.attack_probability.toFixed(2)}</td><td className="td">{d.anomaly_score.toFixed(3)}</td><td className="td">{d.kind === "model" ? "ML" : d.rule}</td>
                </tr>))}
              </tbody>
            </table>
            <p className="mt-2 text-xs text-slate-500">
              {inc.links.length} correlation links · C = 0.30·T + 0.25·I + 0.20·R + 0.15·N + 0.10·S
              {inc.links[0] && <> · e.g. {Object.entries(inc.links[0].components).map(([k, v]) => `${k}=${v}`).join(" ")} → {inc.links[0].score}</>}
            </p>
          </Section>
        </div>
      )}

      {tab === "Timeline" && (
        <Section title="Forensic timeline (stages decoded by the HMM)" actions={
          <label className="flex items-center gap-2 text-xs text-slate-400"><input type="checkbox" checked={onlyAttack} onChange={(e) => setOnlyAttack(e.target.checked)} />attack-relevant only</label>}>
          <Timeline items={inc.timeline} onlyAttack={onlyAttack} />
        </Section>
      )}

      {tab === "Explainability" && <Section title="SHAP explanation"><ShapPanel explanation={inc.explanation} /></Section>}

      {tab === "Attack graph" && <Section title="Attack graph (NetworkX, ranked)"><AttackGraph nodes={inc.graph.nodes} edges={inc.graph.edges} /></Section>}

      {tab === "Evidence" && (
        <div className="space-y-4">
          <Section title="Evidence manifest">
            <div className="grid gap-1 text-sm md:grid-cols-2">
              <div>Manifest SHA-256: <span className="mono break-all">{inc.evidence_manifest.manifest_sha256}</span></div>
              <div>Model version: <span className="mono">{inc.evidence_manifest.model_version}</span> · run <span className="mono">{inc.evidence_manifest.analysis_run_id}</span></div>
              <div>
                Raw evidence integrity:{" "}
                {report.data ? (report.data.evidence_summary.all_verified
                  ? <span className="text-emerald-300">all {report.data.evidence_summary.events} records verified</span>
                  : <span className="text-rose-300">{report.data.evidence_summary.verified}/{report.data.evidence_summary.events} verified</span>) : "checking…"}
              </div>
              <div><a className="text-sky-400 hover:underline" href={`/api/incidents/${inc.incident_id}/report`} target="_blank" rel="noreferrer">Download full forensic report (JSON)</a></div>
            </div>
            <div className="mt-3 max-h-[420px] overflow-auto">
              <table className="w-full">
                <thead><tr><th className="th">Time</th><th className="th">Source</th><th className="th">Raw reference</th><th className="th">SHA-256</th></tr></thead>
                <tbody>{inc.evidence_manifest.events.map((e) => (
                  <tr key={e.event_id} className="border-t border-slate-800">
                    <td className="td whitespace-nowrap text-slate-400">{fmtTime(e.timestamp)}</td><td className="td">{e.source}</td>
                    <td className="td mono">{e.raw_reference}</td><td className="td mono text-slate-500">{e.raw_sha256.slice(0, 20)}…</td>
                  </tr>))}
                </tbody>
              </table>
            </div>
          </Section>
          <Section title="Audit trail">
            <ul className="space-y-1 text-sm">{(report.data?.audit_trail ?? []).map((a, i) => (
              <li key={i}><span className="text-slate-500">{fmtTime(a.timestamp)}</span> <b>{a.actor}</b> {a.action} <span className="mono text-slate-500">{a.object_id}</span></li>))}
              {report.data && report.data.audit_trail.length === 0 && <li className="text-slate-500">No analyst actions yet.</li>}
            </ul>
          </Section>
        </div>
      )}

      {tab === "Response" && <Section title="Recommended response (policy-based, human-approved)"><ActionsPanel actions={inc.actions} onChange={reload} /></Section>}
    </div>
  );
}
