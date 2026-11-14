import { useState } from "react";
import { Link } from "react-router-dom";
import { get, type AuditEntry, type ResponseAction } from "../api";
import { ActionsPanel } from "../components/IncidentPanels";
import { ErrorBox, Loading, RiskBadge, Section, fmtTime, useApi } from "../components/ui";

export default function Response() {
  const [status, setStatus] = useState("proposed");
  const mode = useApi(() => get<{ mode: string; responder_profile_configured: boolean; two_person_rule: boolean }>("/api/response/mode"));
  const actions = useApi(() => get<ResponseAction[]>("/api/response/actions", { status }), [status]);
  const audit = useApi(() => get<AuditEntry[]>("/api/response/audit", { limit: 100 }));
  const reload = () => { actions.reload(); audit.reload(); };

  const byIncident = (actions.data ?? []).reduce<Record<string, ResponseAction[]>>((acc, a) => {
    (acc[a.incident_id] ||= []).push(a);
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">Response management</h1>
          <p className="text-sm text-slate-400">Every action needs analyst approval. Execution is recorded in the audit trail.</p>
        </div>
        {mode.data && (
          <div className={`rounded-lg border px-3 py-2 text-sm ${mode.data.mode === "live" ? "border-rose-500/50 bg-rose-500/10 text-rose-200" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"}`}>
            Execution mode: <b>{mode.data.mode === "live" ? "LIVE (AWS API calls are sent)" : "dry run (no AWS calls)"}</b>
            {mode.data.two_person_rule && <span className="ml-2 text-xs">· two-person rule: executor ≠ approver</span>}
          </div>
        )}
      </div>
      <div className="card flex gap-2">
        {["proposed", "approved", "executed", "rejected", "rolled_back", "failed", ""].map((s) => (
          <button key={s} className={status === s ? "btn-primary py-1" : "btn-ghost py-1"} onClick={() => setStatus(s)}>{s ? s.replace("_", " ") : "all"}</button>
        ))}
      </div>
      {actions.error ? <ErrorBox error={actions.error} /> : !actions.data ? <Loading /> : (
        <div className="space-y-4">
          {Object.entries(byIncident).map(([incidentId, list]) => (
            <Section key={incidentId} title={
              <span className="flex items-center gap-2">
                {list[0].risk_level && <RiskBadge level={list[0].risk_level} score={list[0].risk_score} />}
                <Link className="text-sky-300 hover:underline" to={`/incidents/${incidentId}`}>{list[0].incident_title}</Link>
              </span>}>
              <ActionsPanel actions={list} onChange={reload} />
            </Section>
          ))}
          {Object.keys(byIncident).length === 0 && <p className="text-sm text-slate-500">No {status} actions.</p>}
        </div>
      )}
      <Section title="Audit trail">
        <div className="max-h-80 overflow-auto">
          <table className="w-full">
            <thead><tr><th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Object</th><th className="th">Details</th></tr></thead>
            <tbody>{(audit.data ?? []).map((a) => (
              <tr key={a.id} className="border-t border-slate-800">
                <td className="td whitespace-nowrap text-slate-400">{fmtTime(a.timestamp)}</td><td className="td">{a.actor}</td><td className="td">{a.action}</td>
                <td className="td mono">{a.object_id}</td><td className="td mono max-w-[480px] truncate text-slate-500" title={JSON.stringify(a.details)}>{JSON.stringify(a.details)}</td>
              </tr>))}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}
