import { useState } from "react";
import { Bar, BarChart, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { post, type Incident, type ResponseAction, type TimelineItem } from "../api";
import { Badge, LAYER_COLOR, STAGE_COLOR, StatusBadge, fmtTime, fmtTimeShort, human, pct, useAnalyst } from "./ui";

const tooltipStyle = { background: "#0f172a", border: "1px solid #334155", borderRadius: 8, fontSize: 12 };

export function RiskBreakdown({ risk }: { risk: Incident["risk"] }) {
  return (
    <div className="space-y-3">
      <div className="mono text-slate-400">{risk.formula}</div>
      {risk.components.map((c) => (
        <div key={c.symbol}>
          <div className="flex justify-between text-xs">
            <span><b className="text-slate-200">{c.symbol}</b> · {c.description}</span>
            <span className="text-slate-400">{c.value.toFixed(2)} × {c.weight} = <b className="text-slate-100">{c.contribution.toFixed(1)}</b></span>
          </div>
          <div className="mt-1 h-2 rounded bg-slate-800">
            <div className="h-2 rounded bg-gradient-to-r from-sky-500 to-rose-500" style={{ width: `${(c.contribution / (c.weight * 100)) * 100}%` }} />
          </div>
        </div>
      ))}
      <div className="flex justify-between border-t border-slate-800 pt-2 text-sm"><span>Total</span><b>{risk.score} / 100 · {risk.level}</b></div>
    </div>
  );
}

export function ShapPanel({ explanation }: { explanation: Incident["explanation"] }) {
  if (!explanation.shap) return <p className="text-sm text-slate-500">This incident was raised by rules only (no ML window to explain).</p>;
  const data = explanation.shap.features.map((f) => ({ ...f, name: f.description || f.feature }));
  const probs = Object.entries(explanation.probabilities).sort((a, b) => b[1] - a[1]);
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
      <div>
        <p className="mb-2 text-sm text-slate-300">
          Why XGBoost classified the highest-scoring window as <b>{human(explanation.shap.explained_class)}</b>
          {explanation.class_probability !== null && <> (p = {explanation.class_probability.toFixed(2)})</>}:
        </p>
        <div className="h-[340px]">
          <ResponsiveContainer>
            <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
              <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis type="category" dataKey="name" width={260} tick={{ fill: "#cbd5e1", fontSize: 11 }} />
              <ReferenceLine x={0} stroke="#475569" />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1e293b" }}
                formatter={(v: number, _n, p) => [`SHAP ${v.toFixed(3)} (feature value ${Number(p.payload.value).toPrecision(3)})`, p.payload.feature]} />
              <Bar dataKey="shap">{data.map((d) => <Cell key={d.feature} fill={d.shap >= 0 ? "#f43f5e" : "#38bdf8"} />)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <p className="text-xs text-slate-500">{explanation.note} Red pushes towards the class, blue away from it.</p>
      </div>
      <div className="space-y-4">
        <div>
          <div className="mb-1 text-xs font-semibold uppercase text-slate-400">Class probabilities</div>
          {probs.map(([cls, p]) => (
            <div key={cls} className="mb-1">
              <div className="flex justify-between text-xs"><span>{human(cls)}</span><span>{pct(p, 1)}</span></div>
              <div className="h-1.5 rounded bg-slate-800"><div className="h-1.5 rounded bg-orange-400" style={{ width: `${p * 100}%` }} /></div>
            </div>
          ))}
        </div>
        <div>
          <div className="mb-1 text-xs font-semibold uppercase text-slate-400">Plain-language reasons</div>
          <ul className="list-disc space-y-1 pl-4 text-xs text-slate-300">{explanation.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </div>
      </div>
    </div>
  );
}

export function Timeline({ items, onlyAttack }: { items: TimelineItem[]; onlyAttack: boolean }) {
  const shown = onlyAttack ? items.filter((t) => t.stage !== "NORMAL" || t.in_alert) : items;
  const stages = Array.from(new Set(items.map((t) => t.stage)));
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        {stages.map((s) => <span key={s} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full" style={{ background: STAGE_COLOR[s] }} />{human(s)}</span>)}
      </div>
      <ol className="relative max-h-[640px] space-y-2 overflow-auto border-l border-slate-800 pl-5">
        {shown.map((t) => (
          <li key={t.event_id} className="relative">
            <span className="absolute -left-[27px] top-1.5 h-3 w-3 rounded-full ring-4 ring-slate-950" style={{ background: STAGE_COLOR[t.stage] }} />
            <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
              <span className="mono text-slate-500">{fmtTimeShort(t.timestamp)}</span>
              <span className={t.stage === "NORMAL" ? "text-slate-400" : "text-slate-100"}>{t.description}</span>
            </div>
            <div className="mt-0.5 flex flex-wrap gap-1.5 text-[11px]">
              <Badge className="bg-slate-800 text-slate-300 ring-slate-700"><span className="mr-1 h-1.5 w-1.5 rounded-full" style={{ background: LAYER_COLOR[t.layer] }} />{t.layer}</Badge>
              <Badge className="bg-slate-800 text-slate-300 ring-slate-700" >HMM: {human(t.stage)} ({pct(t.stage_confidence)})</Badge>
              {t.mitre && <Badge className="bg-indigo-500/10 text-indigo-300 ring-indigo-500/30">{t.mitre.id} {t.mitre.name}</Badge>}
              {t.in_alert && <Badge className="bg-orange-500/10 text-orange-300 ring-orange-500/30">in alert</Badge>}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function ActionsPanel({ actions, onChange }: { actions: ResponseAction[]; onChange: () => void }) {
  const [analyst] = useAnalyst();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(a: ResponseAction, verb: "approve" | "reject" | "execute" | "rollback") {
    if (verb === "execute" && !window.confirm(`Execute ${a.action_type}?\n\n${a.description}\n\nAPI: ${a.api_call}`)) return;
    setBusy(a.action_id + verb);
    setError(null);
    try {
      await post(`/api/response/actions/${a.action_id}/${verb}`, { analyst, note: verb === "approve" ? "approved from incident view" : undefined });
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  if (!actions.length) return <p className="text-sm text-slate-500">No actions: risk is below HIGH, so the policy only monitors / notifies.</p>;
  return (
    <div className="space-y-2">
      {error && <div className="rounded border border-rose-500/40 bg-rose-500/10 p-2 text-sm text-rose-200">{error}</div>}
      {actions.map((a) => (
        <div key={a.action_id} className="rounded-lg border border-slate-800 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-sm font-medium">{a.description}</div>
              <div className="text-xs text-slate-400">{a.rationale}</div>
              <div className="mono mt-1 text-slate-500">{a.api_call} · {a.automatable ? (a.reversible ? "automatable, reversible" : "automatable") : "manual"}</div>
            </div>
            <div className="flex items-center gap-2">
              <StatusBadge status={a.status} />
              {a.status === "proposed" && <>
                <button className="btn-ghost py-1" disabled={!!busy} onClick={() => run(a, "reject")}>Reject</button>
                <button className="btn-primary py-1" disabled={!!busy} onClick={() => run(a, "approve")}>Approve</button>
              </>}
              {a.status === "approved" && a.automatable && <button className="btn-danger py-1" disabled={!!busy} onClick={() => run(a, "execute")}>Execute</button>}
              {a.status === "executed" && a.reversible && <button className="btn-ghost py-1" disabled={!!busy} onClick={() => run(a, "rollback")}>Roll back</button>}
            </div>
          </div>
          {(a.decided_by || a.execution) && (
            <div className="mt-2 text-xs text-slate-500">
              {a.decided_by && <>Decided by {a.decided_by} {fmtTime(a.decided_at)}. </>}
              {a.execution && <>Executed ({String(a.execution.mode)}) {fmtTime(a.executed_at)}: <span className="mono">{String(a.execution.service)}.{String(a.execution.operation)}({JSON.stringify(a.execution.params)})</span></>}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
