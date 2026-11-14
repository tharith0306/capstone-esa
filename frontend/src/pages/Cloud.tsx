import { useState } from "react";
import { get, post } from "../api";
import { ErrorBox, Loading, Section, canAct, fmtTime, useApi, useUser } from "../components/ui";

interface Resource { resource_id: string; resource_type: string; region: string | null; name: string | null; source: string; attributes: Record<string, unknown>; last_seen: string }
interface Health { sources: { source: string; events: number; last_event: string; lag_hours: number }[]; checkpoints: { collector: string; cursor: string; updated_at: string }[]; inventory_resources: number }
interface Account { cloud_provider: string; account_id: string | null; events: number; last_event: string }

const COLLECTORS = ["cloudtrail", "cloudtrail_s3", "guardduty", "vpc_flow", "cloudwatch", "sqs"];

export default function Cloud() {
  const user = useUser();
  const [type, setType] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const health = useApi(() => get<Health>("/api/cloud/health"));
  const accounts = useApi(() => get<Account[]>("/api/cloud/accounts"));
  const resources = useApi(() => get<Resource[]>("/api/cloud/resources", { resource_type: type }), [type]);

  async function run(path: string, body: unknown, label: string) {
    setBusy(true);
    setMessage(null);
    try {
      const r = await post<Record<string, unknown>>(path, body);
      setMessage(`${label}: ${JSON.stringify(r).slice(0, 300)}`);
      health.reload();
      resources.reload();
    } catch (e) {
      setMessage(`${label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Cloud integration</h1>
        <p className="text-sm text-slate-400">Connected accounts, telemetry freshness per source, collector checkpoints and the asset inventory used to link network flows to instances.</p>
      </div>
      {canAct(user, "admin") && (
        <div className="card flex flex-wrap items-center gap-2">
          <span className="text-sm text-slate-400">Collect now from AWS:</span>
          {COLLECTORS.map((c) => <button key={c} className="btn-ghost py-1 text-xs" disabled={busy} onClick={() => run("/api/cloud/collect", { source: c }, `collect ${c}`)}>{c}</button>)}
          <button className="btn-primary py-1 text-xs" disabled={busy} onClick={() => run("/api/cloud/inventory/refresh", {}, "inventory refresh")}>Refresh inventory</button>
        </div>
      )}
      {message && <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-3 text-sm text-sky-200 break-all">{message}</div>}
      <div className="grid gap-4 xl:grid-cols-3">
        <Section title="Accounts / subscriptions / projects">
          {accounts.error ? <ErrorBox error={accounts.error} /> : (
            <table className="w-full"><thead><tr><th className="th">Cloud</th><th className="th">Account</th><th className="th">Events</th><th className="th">Last event</th></tr></thead>
              <tbody>{(accounts.data ?? []).map((a) => (
                <tr key={`${a.cloud_provider}${a.account_id}`} className="border-t border-slate-800"><td className="td uppercase">{a.cloud_provider}</td><td className="td mono">{a.account_id ?? "—"}</td><td className="td">{a.events.toLocaleString()}</td><td className="td text-slate-400">{fmtTime(a.last_event)}</td></tr>))}
              </tbody></table>)}
        </Section>
        <Section title="Telemetry sources">
          <table className="w-full"><thead><tr><th className="th">Source</th><th className="th">Events</th><th className="th">Last event</th></tr></thead>
            <tbody>{(health.data?.sources ?? []).map((s) => (
              <tr key={s.source} className="border-t border-slate-800"><td className="td">{s.source}</td><td className="td">{s.events.toLocaleString()}</td><td className="td text-slate-400">{fmtTime(s.last_event)}</td></tr>))}
            </tbody></table>
        </Section>
        <Section title="Collector checkpoints">
          {(health.data?.checkpoints ?? []).length === 0 ? <p className="text-sm text-slate-500">No AWS collection has run yet (demo data is simulated).</p> : (
            <ul className="space-y-1 text-sm">{health.data!.checkpoints.map((c) => <li key={c.collector}><span className="mono">{c.collector}</span> <span className="text-slate-400">→ {fmtTime(c.cursor)}</span></li>)}</ul>)}
        </Section>
      </div>
      <Section title={`Asset inventory (${health.data?.inventory_resources ?? "…"})`} actions={
        <select className="input py-1 text-xs" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">all types</option><option value="ec2_instance">EC2 instances</option><option value="s3_bucket">S3 buckets</option><option value="iam_user">IAM users</option>
        </select>}>
        {resources.error ? <ErrorBox error={resources.error} /> : !resources.data ? <Loading /> : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full"><thead><tr><th className="th">Resource</th><th className="th">Type</th><th className="th">Region</th><th className="th">Details</th><th className="th">Source</th></tr></thead>
              <tbody>{resources.data.map((r) => (
                <tr key={r.resource_id} className="border-t border-slate-800">
                  <td className="td mono">{r.resource_id}</td><td className="td">{r.resource_type}</td><td className="td">{r.region ?? "—"}</td>
                  <td className="td mono max-w-[420px] truncate text-slate-500" title={JSON.stringify(r.attributes)}>{JSON.stringify(r.attributes)}</td>
                  <td className="td text-slate-400">{r.source}</td>
                </tr>))}
              </tbody></table>
          </div>)}
      </Section>
    </div>
  );
}
