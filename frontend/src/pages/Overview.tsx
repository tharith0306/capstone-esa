import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { get, post, type IncidentSummary, type Overview as OverviewT } from "../api";
import {
  ErrorBox, LEVEL_COLOR, LAYER_COLOR, Loading, RiskBadge, Section, Stat, StatusBadge, fmtTime, human, pct, useApi,
} from "../components/ui";

interface Trend { time: string; events: number; detections: number; incidents: number; max_risk: number }
interface RiskDist { levels: { level: string; count: number }[]; classes: { class: string; count: number }[] }
interface TopEntities { actors: { entity: string; risk_sum: number }[]; ips: { entity: string; risk_sum: number }[]; resources: { entity: string; risk_sum: number }[] }
interface LayerCount { layer: string; source: string; count: number }

const tooltipStyle = { background: "#0f172a", border: "1px solid #334155", borderRadius: 8, fontSize: 12 };

export default function Overview() {
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const overview = useApi(() => get<OverviewT>("/api/dashboard/overview"));
  const trends = useApi(() => get<Trend[]>("/api/dashboard/threat-trends", { bucket: "hour" }));
  const dist = useApi(() => get<RiskDist>("/api/dashboard/risk-distribution"));
  const top = useApi(() => get<TopEntities>("/api/dashboard/top-entities"));
  const layers = useApi(() => get<LayerCount[]>("/api/dashboard/layers"));
  const incidents = useApi(() => get<{ items: IncidentSummary[] }>("/api/incidents", { limit: 8, min_risk: 41 }));

  const reloadAll = () => [overview, trends, dist, top, layers, incidents].forEach((x) => x.reload());

  async function act(kind: "analyze" | "simulate") {
    setBusy(kind);
    setMessage(null);
    try {
      if (kind === "simulate") {
        const r = await post<{ scenarios: unknown[] }>("/api/simulation/run", { seed: Math.floor(Math.random() * 10000), days: 3, attacks_per_day: 1.5 });
        setMessage(`Simulated 3 days with ${r.scenarios.length} attack scenarios. Run analysis to detect them.`);
      } else {
        const r = await post<{ n_detections: number; n_incidents: number; seconds: number; status: string; error?: string }>("/api/analysis/run", {});
        setMessage(r.status === "completed" ? `Analysis: ${r.n_detections} detections → ${r.n_incidents} incidents in ${r.seconds}s.` : `Analysis failed: ${r.error}`);
      }
      reloadAll();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  if (overview.error) return <ErrorBox error={overview.error} />;
  if (!overview.data) return <Loading />;
  const o = overview.data;

  const layerTotals = Object.entries(
    (layers.data ?? []).reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.layer]: (acc[l.layer] ?? 0) + l.count }), {}),
  ).map(([layer, count]) => ({ layer, count }));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Security overview</h1>
          <p className="text-sm text-slate-400">
            Events {fmtTime(o.events_from)} → {fmtTime(o.events_to)}
            {o.last_analysis && <> · last analysis {fmtTime(o.last_analysis.finished_at)} ({o.last_analysis.seconds}s, model {o.last_analysis.model_version})</>}
          </p>
        </div>
        <div className="flex gap-2">
          <button className="btn-ghost" disabled={!!busy} onClick={() => act("simulate")}>
            {busy === "simulate" ? "Simulating…" : "Simulate attack data"}
          </button>
          <button className="btn-primary" disabled={!!busy} onClick={() => act("analyze")}>
            {busy === "analyze" ? "Analysing…" : "Run analysis"}
          </button>
        </div>
      </div>
      {message && <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-3 text-sm text-sky-200">{message}</div>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Events monitored" value={o.total_events.toLocaleString()} hint="CloudTrail · VPC Flow · GuardDuty" />
        <Stat label="Detections" value={o.detections.toLocaleString()} hint={`${o.model_detections} ML · ${o.detections - o.model_detections} rule`} />
        <Stat label="Incidents" value={o.incidents} hint={`alert reduction ${pct(o.alert_reduction)}`} />
        <Stat label="Active incidents" value={o.active_incidents} accent="text-amber-300" />
        <Stat label="Critical" value={o.critical_incidents} accent="text-rose-400" />
        <Stat label="Resources at risk" value={o.resources_at_risk} hint="in active HIGH/CRITICAL incidents" />
        <Stat label="Pending actions" value={o.pending_actions} hint="awaiting approval / execution" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Section title="Activity and detections per hour" className="xl:col-span-2">
          <div className="h-64">
            <ResponsiveContainer>
              <AreaChart data={trends.data ?? []}>
                <CartesianGrid stroke="#1e293b" />
                <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 11 }} tickFormatter={(t) => new Date(t).toLocaleDateString(undefined, { day: "2-digit", month: "short" })} minTickGap={40} />
                <YAxis yAxisId="e" tick={{ fill: "#64748b", fontSize: 11 }} />
                <YAxis yAxisId="d" orientation="right" tick={{ fill: "#64748b", fontSize: 11 }} />
                <Tooltip contentStyle={tooltipStyle} labelFormatter={(t) => fmtTime(String(t))} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Area yAxisId="e" type="monotone" dataKey="events" stroke="#64748b" fill="#33415566" name="Events" />
                <Area yAxisId="d" type="monotone" dataKey="detections" stroke="#fb923c" fill="#fb923c33" name="Detections" />
                <Area yAxisId="d" type="monotone" dataKey="incidents" stroke="#f43f5e" fill="#f43f5e33" name="Incidents" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Section>
        <Section title="Incidents by risk level">
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={dist.data?.levels ?? []} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="level" tick={{ fill: "#94a3b8", fontSize: 11 }} width={70} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1e293b" }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {(dist.data?.levels ?? []).map((l) => <Cell key={l.level} fill={LEVEL_COLOR[l.level]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Section>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Section title="Highest-risk incidents" className="xl:col-span-2" actions={<Link className="text-xs text-sky-400" to="/incidents">All incidents →</Link>}>
          <table className="w-full">
            <thead><tr><th className="th">Risk</th><th className="th">Incident</th><th className="th">Start</th><th className="th">Alerts</th><th className="th">Status</th></tr></thead>
            <tbody>
              {(incidents.data?.items ?? []).map((i) => (
                <tr key={i.incident_id} className="border-t border-slate-800 hover:bg-slate-800/40">
                  <td className="td"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
                  <td className="td"><Link className="text-sky-300 hover:underline" to={`/incidents/${i.incident_id}`}>{i.title}</Link></td>
                  <td className="td text-slate-400">{fmtTime(i.start)}</td>
                  <td className="td">{i.alert_count}</td>
                  <td className="td"><StatusBadge status={i.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {incidents.data?.items.length === 0 && <p className="p-4 text-sm text-slate-500">No MEDIUM+ incidents. Simulate data and run analysis.</p>}
        </Section>
        <div className="space-y-4">
          <Section title="Events by cloud layer">
            <div className="h-40">
              <ResponsiveContainer>
                <BarChart data={layerTotals}>
                  <XAxis dataKey="layer" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1e293b" }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>{layerTotals.map((l) => <Cell key={l.layer} fill={LAYER_COLOR[l.layer] ?? "#64748b"} />)}</Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Section>
          <Section title="Riskiest identities (Σ incident risk)">
            <ul className="space-y-1 text-sm">
              {(top.data?.actors ?? []).slice(0, 6).map((a) => (
                <li key={a.entity} className="flex justify-between"><span className="mono">{a.entity}</span><span className="text-slate-400">{a.risk_sum}</span></li>
              ))}
            </ul>
          </Section>
          <Section title="Incident types">
            <ul className="space-y-1 text-sm">
              {(dist.data?.classes ?? []).map((c) => (
                <li key={c.class} className="flex justify-between"><span>{human(c.class)}</span><span className="text-slate-400">{c.count}</span></li>
              ))}
            </ul>
          </Section>
        </div>
      </div>
    </div>
  );
}
