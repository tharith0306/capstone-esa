import { ReactNode, createContext, useCallback, useContext, useEffect, useState } from "react";
import type { Level, SessionUser } from "../api";

export const LEVEL_STYLE: Record<string, string> = {
  CRITICAL: "bg-rose-500/15 text-rose-300 ring-rose-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  MEDIUM: "bg-amber-400/15 text-amber-200 ring-amber-400/40",
  LOW: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
  MINIMAL: "bg-slate-500/15 text-slate-300 ring-slate-500/40",
};
export const LEVEL_COLOR: Record<string, string> = {
  CRITICAL: "#f43f5e", HIGH: "#fb923c", MEDIUM: "#fbbf24", LOW: "#38bdf8", MINIMAL: "#64748b",
};
export const STAGE_COLOR: Record<string, string> = {
  NORMAL: "#475569",
  CREDENTIAL_ACCESS: "#a78bfa",
  INITIAL_ACCESS: "#f472b6",
  DISCOVERY: "#38bdf8",
  PERSISTENCE: "#facc15",
  PRIVILEGE_ESCALATION: "#fb923c",
  DEFENSE_EVASION: "#c084fc",
  EXFILTRATION: "#f43f5e",
  IMPACT: "#ef4444",
};
export const LAYER_COLOR: Record<string, string> = {
  identity: "#a78bfa", network: "#38bdf8", compute: "#34d399", storage: "#fbbf24", management: "#f472b6", application: "#94a3b8",
};

export function Badge({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${className}`}>
      {children}
    </span>
  );
}

export function RiskBadge({ level, score }: { level: Level | string; score?: number }) {
  return (
    <Badge className={LEVEL_STYLE[level] ?? LEVEL_STYLE.MINIMAL}>
      {level}
      {score !== undefined && <span className="ml-1 opacity-80">{score.toFixed(1)}</span>}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const style: Record<string, string> = {
    open: "bg-rose-500/10 text-rose-300 ring-rose-500/30",
    investigating: "bg-amber-400/10 text-amber-200 ring-amber-400/30",
    contained: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
    resolved: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
    false_positive: "bg-slate-500/10 text-slate-300 ring-slate-500/30",
    proposed: "bg-slate-500/10 text-slate-200 ring-slate-500/30",
    approved: "bg-amber-400/10 text-amber-200 ring-amber-400/30",
    rejected: "bg-slate-600/10 text-slate-400 ring-slate-600/30",
    executed: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
    failed: "bg-rose-500/10 text-rose-300 ring-rose-500/30",
    rolled_back: "bg-violet-500/10 text-violet-300 ring-violet-500/30",
  };
  return <Badge className={style[status] ?? style.proposed}>{status.replace("_", " ")}</Badge>;
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string }) {
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${accent ?? "text-slate-100"}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function Section({ title, actions, children, className = "" }: { title: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Loading() {
  return <div className="p-8 text-center text-sm text-slate-500">Loading…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  return (
    <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="p-6 text-center text-sm text-slate-500">{children}</div>;
}

export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(fn, deps);
  const reload = useCallback(() => {
    setLoading(true);
    load()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch(setError)
      .finally(() => setLoading(false));
  }, [load]);
  useEffect(reload, [reload]);
  return { data, error, loading, reload };
}

export const fmtTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
export const fmtTimeShort = (iso: string) =>
  new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const pct = (v: number | null | undefined, digits = 0) => (v === null || v === undefined ? "—" : `${(v * 100).toFixed(digits)}%`);
export const human = (s: string) => s.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
export const bytes = (n: number) => {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
};

export const UserContext = createContext<SessionUser | null>(null);
export const useUser = () => useContext(UserContext);
export const canAct = (user: SessionUser | null, minimum: "analyst" | "admin") =>
  !!user && (user.role === "admin" || (minimum === "analyst" && user.role === "analyst"));
