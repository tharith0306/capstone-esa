import { FormEvent, useState } from "react";
import { get, post } from "../api";
import { ErrorBox, Loading, Section, fmtTime, useApi, useUser } from "../components/ui";

interface UserRow { username: string; role: string; active: boolean; last_login: string | null; created_at: string }

export default function Admin() {
  const me = useUser();
  const users = useApi(() => get<UserRow[]>("/api/auth/users"));
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const [message, setMessage] = useState<string | null>(null);

  if (me?.role !== "admin") return <ErrorBox error="Only administrators can manage users." />;

  async function create(e: FormEvent) {
    e.preventDefault();
    setMessage(null);
    try {
      await post("/api/auth/register", form);
      setMessage(`Created ${form.username} (${form.role}).`);
      setForm({ username: "", password: "", role: "analyst" });
      users.reload();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Users & roles</h1>
      <p className="text-sm text-slate-400">viewer: read only · analyst: run analysis, approve/reject, execute in dry-run · admin: users, simulation, AWS collection, live execution. In live mode the executor must differ from the approver.</p>
      <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
        <Section title="Accounts">
          {users.error ? <ErrorBox error={users.error} /> : !users.data ? <Loading /> : (
            <table className="w-full"><thead><tr><th className="th">User</th><th className="th">Role</th><th className="th">Last login</th><th className="th">Created</th></tr></thead>
              <tbody>{users.data.map((u) => (
                <tr key={u.username} className="border-t border-slate-800"><td className="td">{u.username}</td><td className="td">{u.role}</td><td className="td text-slate-400">{fmtTime(u.last_login)}</td><td className="td text-slate-400">{fmtTime(u.created_at)}</td></tr>))}
              </tbody></table>)}
        </Section>
        <Section title="Create user">
          <form onSubmit={create} className="space-y-3 text-sm">
            <input className="input w-full" placeholder="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            <input className="input w-full" type="password" placeholder="password (min 10 chars)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <select className="input w-full" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="admin">admin</option>
            </select>
            <button className="btn-primary" disabled={form.username.length < 3 || form.password.length < 10}>Create</button>
            {message && <p className="text-slate-300">{message}</p>}
          </form>
        </Section>
      </div>
    </div>
  );
}
