// Thin typed client for the CloudShield FastAPI backend.

const BASE = import.meta.env.VITE_API_URL ?? "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------- auth token
const TOKEN_KEY = "cloudshield.token";
export interface SessionUser { username: string; role: "viewer" | "analyst" | "admin" }

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
export function setToken(token: string | null) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: token lives only in memory for this page */
  }
  memoryToken = token;
}
let memoryToken: string | null = getToken();
export const UNAUTHORIZED_EVENT = "cloudshield:unauthorized";

function authHeaders(): Record<string, string> {
  const token = memoryToken ?? getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(username: string, password: string): Promise<SessionUser> {
  const res = await request<{ access_token: string; user: SessionUser }>("/api/auth/login", {
    method: "POST", body: JSON.stringify({ username, password }),
  });
  setToken(res.access_token);
  return res.user;
}
export async function logout() {
  try {
    await request("/api/auth/logout", { method: "POST" });
  } finally {
    setToken(null);
  }
}

/** Download a protected file (PDF / Cypher) with the bearer token and save it. */
export async function download(path: string, filename: string) {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new ApiError(res.status, (await res.json().catch(() => ({}))).detail ?? res.statusText);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...(init?.headers ?? {}) },
  });
  if (res.status === 401 && !path.startsWith("/api/auth/login")) {
    setToken(null);
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const get = <T>(path: string, params?: Record<string, string | number | undefined | null>) => {
  const qs = params
    ? "?" +
      new URLSearchParams(
        Object.entries(params)
          .filter(([, v]) => v !== undefined && v !== null && v !== "")
          .map(([k, v]) => [k, String(v)]),
      ).toString()
    : "";
  return request<T>(path + (qs === "?" ? "" : qs));
};
export const post = <T>(path: string, body: unknown = {}) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) });
export const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "PATCH", body: JSON.stringify(body) });

// ---------------------------------------------------------------- types
export type Level = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL";

export interface Overview {
  total_events: number;
  detections: number;
  model_detections: number;
  incidents: number;
  active_incidents: number;
  critical_incidents: number;
  alert_reduction: number | null;
  resources_at_risk: number;
  resources_at_risk_list: string[];
  pending_actions: number;
  average_active_risk: number | null;
  events_from: string | null;
  events_to: string | null;
  last_analysis: { run_id: string; status: string; finished_at: string; seconds: number; model_version: string } | null;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_source: string;
  event_name: string;
  event_type: string;
  layer: string;
  action: string;
  outcome: string;
  actor_id: string | null;
  access_key_id: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  resource_id: string | null;
  resource_type: string | null;
  bytes_transferred: number | null;
  base_severity: number;
  attributes: Record<string, unknown>;
  raw_event_reference: string;
  raw_event_hash: string;
}

export interface Detection {
  detection_id: string;
  incident_id: string | null;
  kind: "model" | "rule";
  rule: string | null;
  entity: string;
  start: string;
  end: string;
  predicted_class: string;
  class_probability: number;
  attack_probability: number;
  anomaly_score: number;
  score: number;
  probabilities: Record<string, number>;
  entities: { actors: string[]; keys: string[]; ips: string[]; resources: string[] };
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  status: string;
  primary_class: string;
  risk_score: number;
  risk_level: Level;
  start: string;
  end: string;
  alert_count: number;
  event_count: number;
  correlation_score: number;
  actors: string[];
  source_ips: string[];
  resources: string[];
  access_keys: string[];
  mitre: Mitre[];
  analyst_notes: string | null;
}

export interface Mitre {
  id: string;
  name: string;
  tactic: string;
  count?: number;
  first_seen?: string;
}

export interface RiskComponent {
  symbol: string;
  name: string;
  description: string;
  value: number;
  weight: number;
  contribution: number;
}

export interface ShapFeature {
  feature: string;
  description: string;
  value: number;
  shap: number;
}

export interface TimelineItem {
  event_id: string;
  timestamp: string;
  layer: string;
  source: string;
  event_type: string;
  actor: string | null;
  source_ip: string | null;
  resource: string | null;
  description: string;
  severity: number;
  stage: string;
  stage_confidence: number;
  mitre: Mitre | null;
  in_alert: boolean;
}

export interface GraphNode {
  id: string;
  type: "ip" | "host" | "identity" | "key" | "resource" | "finding";
  label: string;
  column: number;
  rank: number;
  sensitivity: number;
  suspicion_out: number;
  suspicion_in: number;
  pagerank: number;
  degree: number;
  first_seen: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  count: number;
  suspicion: number;
  bytes: number;
  first_seen: string;
  last_seen: string;
  event_ids: string[];
}

export interface ResponseAction {
  action_id: string;
  incident_id: string;
  action_type: string;
  target: Record<string, unknown>;
  description: string;
  rationale: string;
  api_call: string;
  automatable: boolean;
  reversible: boolean;
  status: "proposed" | "approved" | "rejected" | "executed" | "failed" | "rolled_back";
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  executed_at: string | null;
  execution: Record<string, unknown> | null;
  error: string | null;
  incident_title?: string;
  risk_level?: Level;
  risk_score?: number;
}

export interface Incident extends IncidentSummary {
  risk: { score: number; level: Level; formula: string; components: RiskComponent[]; top_drivers: string[] };
  explanation: {
    alert_id: string | null;
    predicted_class: string | null;
    class_probability: number | null;
    probabilities: Record<string, number>;
    shap: { explained_class: string; base_value: number; features: ShapFeature[] } | null;
    reasons: string[];
    risk_drivers: string[];
    note: string;
  };
  graph: { nodes: GraphNode[]; edges: GraphEdge[]; top_nodes: string[] };
  timeline: TimelineItem[];
  sequence: { event_id: string; observation: string; stage: string; confidence: number }[];
  links: { from: string; to: string; score: number; components: Record<string, number> }[];
  evidence_manifest: {
    incident_id: string;
    generated_at: string;
    analysis_run_id: string;
    model_version: string;
    manifest_sha256: string;
    events: { event_id: string; source: string; source_event_id: string; timestamp: string; raw_reference: string; raw_sha256: string }[];
  };
  detections: Detection[];
  actions: ResponseAction[];
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  object_type: string;
  object_id: string;
  details: Record<string, unknown>;
}
