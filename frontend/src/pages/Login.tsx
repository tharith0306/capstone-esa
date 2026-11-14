import { FormEvent, useState } from "react";
import { login, type SessionUser } from "../api";

export default function Login({ onLogin }: { onLogin: (u: SessionUser) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await login(username, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="card w-full max-w-sm space-y-4">
        <div className="flex items-center gap-2">
          <svg viewBox="0 0 24 24" className="h-7 w-7 text-sky-400" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <div>
            <div className="text-lg font-semibold">CloudShield</div>
            <div className="text-xs text-slate-400">Sign in to the security console</div>
          </div>
        </div>
        <label className="block text-sm">
          <span className="text-slate-400">Username</span>
          <input className="input mt-1 w-full" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="block text-sm">
          <span className="text-slate-400">Password</span>
          <input className="input mt-1 w-full" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <div className="rounded border border-rose-500/40 bg-rose-500/10 p-2 text-sm text-rose-200">{error}</div>}
        <button className="btn-primary w-full justify-center" disabled={busy || !password}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="text-xs text-slate-500">
          First run: the admin password is set by CLOUDSHIELD_BOOTSTRAP_ADMIN_PASSWORD, or printed once in the backend log.
        </p>
      </form>
    </div>
  );
}
