import { useState } from "react";
import { get, type SecurityEvent } from "../api";
import { Badge, ErrorBox, LAYER_COLOR, Loading, Section, bytes, fmtTime, useApi } from "../components/ui";

const LAYERS = ["", "identity", "network", "compute", "storage", "management", "application"];
const SOURCES = ["", "cloudtrail", "vpc_flow", "guardduty"];
const PAGE = 50;

export default function Events() {
  const [filters, setFilters] = useState({ layer: "", source: "", actor_id: "", source_ip: "", min_severity: "" });
  const [applied, setApplied] = useState(filters);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const { data, error, loading } = useApi(
    () => get<{ total: number; items: SecurityEvent[] }>("/api/events", { ...applied, limit: PAGE, offset }),
    [applied, offset],
  );
  const raw = useApi(
    () => (selected ? get<{ verified: boolean; raw: unknown; sha256: string }>(`/api/events/${selected.event_id}/raw`) : Promise.resolve(null)),
    [selected?.event_id],
  );

  const set = (k: keyof typeof filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setFilters({ ...filters, [k]: e.target.value });

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Live security events</h1>
      <form className="card flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); setOffset(0); setApplied(filters); }}>
        <select className="input" value={filters.layer} onChange={set("layer")}>{LAYERS.map((l) => <option key={l} value={l}>{l || "all layers"}</option>)}</select>
        <select className="input" value={filters.source} onChange={set("source")}>{SOURCES.map((s) => <option key={s} value={s}>{s || "all sources"}</option>)}</select>
        <input className="input" placeholder="actor" value={filters.actor_id} onChange={set("actor_id")} />
        <input className="input" placeholder="source IP" value={filters.source_ip} onChange={set("source_ip")} />
        <input className="input w-36" placeholder="min severity 0-1" value={filters.min_severity} onChange={set("min_severity")} />
        <button className="btn-primary">Filter</button>
      </form>
      {error ? <ErrorBox error={error} /> : loading && !data ? <Loading /> : (
        <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
          <Section title={`${data?.total.toLocaleString()} events`} actions={
            <div className="flex items-center gap-2 text-xs">
              <button className="btn-ghost py-1" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Prev</button>
              <span className="text-slate-400">{offset + 1}–{Math.min(offset + PAGE, data?.total ?? 0)}</span>
              <button className="btn-ghost py-1" disabled={offset + PAGE >= (data?.total ?? 0)} onClick={() => setOffset(offset + PAGE)}>Next</button>
            </div>}>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead><tr><th className="th">Time</th><th className="th">Layer</th><th className="th">Type</th><th className="th">Actor</th><th className="th">Source IP</th><th className="th">Resource</th><th className="th">Sev</th></tr></thead>
                <tbody>
                  {data?.items.map((e) => (
                    <tr key={e.event_id} onClick={() => setSelected(e)} className={`cursor-pointer border-t border-slate-800 hover:bg-slate-800/40 ${selected?.event_id === e.event_id ? "bg-slate-800/60" : ""}`}>
                      <td className="td whitespace-nowrap text-slate-400">{fmtTime(e.timestamp)}</td>
                      <td className="td"><span className="inline-block h-2 w-2 rounded-full" style={{ background: LAYER_COLOR[e.layer] }} /> {e.layer}</td>
                      <td className="td">{e.event_type}{e.outcome === "failure" && <Badge className="ml-1 bg-rose-500/10 text-rose-300 ring-rose-500/30">fail</Badge>}</td>
                      <td className="td mono">{e.actor_id ?? "—"}</td>
                      <td className="td mono">{e.source_ip ?? "—"}</td>
                      <td className="td mono max-w-[260px] truncate" title={e.resource_id ?? ""}>{e.resource_id ?? "—"}</td>
                      <td className="td">{e.base_severity.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
          <Section title="Event detail & raw evidence">
            {!selected ? <p className="text-sm text-slate-500">Select an event.</p> : (
              <div className="space-y-3 text-sm">
                <div className="grid grid-cols-[110px_1fr] gap-y-1">
                  <span className="text-slate-500">Event</span><span>{selected.event_name} ({selected.event_source})</span>
                  <span className="text-slate-500">Action</span><span className="mono">{selected.action}</span>
                  <span className="text-slate-500">Outcome</span><span>{selected.outcome}</span>
                  <span className="text-slate-500">Access key</span><span className="mono">{selected.access_key_id ?? "—"}</span>
                  <span className="text-slate-500">Bytes</span><span>{selected.bytes_transferred ? bytes(selected.bytes_transferred) : "—"}</span>
                  <span className="text-slate-500">Evidence</span>
                  <span>
                    {raw.data ? (raw.data.verified ? <Badge className="bg-emerald-500/10 text-emerald-300 ring-emerald-500/30">SHA-256 verified</Badge> : <Badge className="bg-rose-500/10 text-rose-300 ring-rose-500/30">hash mismatch</Badge>) : "…"}
                  </span>
                </div>
                <div className="mono break-all text-slate-500">{selected.raw_event_hash}</div>
                <pre className="max-h-[420px] overflow-auto rounded-lg bg-slate-950 p-3 text-[11px] text-slate-300">{JSON.stringify(raw.data?.raw ?? selected.attributes, null, 2)}</pre>
              </div>
            )}
          </Section>
        </div>
      )}
    </div>
  );
}
