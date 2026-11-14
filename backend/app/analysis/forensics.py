"""Layer 8: attack graph, suspicious-node ranking, forensic timeline and MITRE ATT&CK mapping.

Node ranking (adapted from the forensic-ready IDS paper):
    R(v) = 0.4·S_out(v) + 0.3·S_in(v) + 0.2·PageRank(v) + 0.1·Degree(v), each min-max normalised.
It ranks *structural importance in the incident*, not proof that a node is malicious.
"""

from datetime import datetime, timezone

import networkx as nx

from app.analysis.sensitivity import resource_sensitivity
from app.ml.features import EventRow, is_internal
from app.ml.taxonomy import LOGIN_FAILURE_TECHNIQUE, MITRE_TECHNIQUES
from app.schemas.event import SecurityEvent

COLUMNS = {"ip": 0, "host": 0, "identity": 1, "key": 2, "resource": 3, "finding": 3}
RELATIONS = {
    "POLICY_ATTACHED": "MODIFIED_POLICY",
    "INLINE_POLICY_ADDED": "MODIFIED_POLICY",
    "POLICY_VERSION_CHANGED": "MODIFIED_POLICY",
    "GROUP_MEMBERSHIP_ADDED": "MODIFIED_POLICY",
    "ROLE_TRUST_POLICY_CHANGED": "MODIFIED_POLICY",
    "OBJECT_DOWNLOADED": "DOWNLOADED_OBJECT",
    "OBJECT_LISTING": "ENUMERATED",
    "SECURITY_GROUP_INGRESS_OPENED": "MODIFIED_FIREWALL",
    "SECURITY_GROUP_EGRESS_OPENED": "MODIFIED_FIREWALL",
    "AUDIT_LOGGING_STOPPED": "DISABLED_LOGGING",
    "AUDIT_TRAIL_MODIFIED": "DISABLED_LOGGING",
    "THREAT_DETECTION_DISABLED": "DISABLED_LOGGING",
    "INSTANCE_LAUNCHED": "LAUNCHED",
    "IAM_USER_CREATED": "CREATED_USER",
    "LOGIN_PROFILE_CHANGED": "MODIFIED_CREDENTIALS",
    "BUCKET_POLICY_CHANGED": "MODIFIED_BUCKET_POLICY",
}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_attack_graph(rows: list[EventRow], events: dict[str, SecurityEvent], event_scores: dict[str, float]) -> dict:
    G = nx.DiGraph()

    def node(nid: str, ntype: str, label: str, ts: float, resource_type: str | None = None) -> str:
        if nid not in G:
            sens = resource_sensitivity(label, resource_type) if ntype == "resource" else 0.0
            G.add_node(nid, type=ntype, label=label, column=COLUMNS[ntype], first_seen=ts, sensitivity=sens)
        return nid

    def edge(u: str, v: str, relation: str, r: EventRow, suspicion: float) -> None:
        if u == v:
            return
        if G.has_edge(u, v) and G.edges[u, v]["relation"] == relation:
            d = G.edges[u, v]
            d["count"] += 1
            d["last_seen"] = r.ts
            d["suspicion"] = max(d["suspicion"], suspicion)
            d["bytes"] += r.nbytes
            if len(d["event_ids"]) < 50:
                d["event_ids"].append(r.event_id)
        else:
            G.add_edge(u, v, relation=relation, count=1, first_seen=r.ts, last_seen=r.ts,
                       suspicion=suspicion, bytes=r.nbytes, event_ids=[r.event_id])

    for r in rows:
        susp = round(0.5 * r.severity + 0.5 * event_scores.get(r.event_id, 0.0), 4)
        if r.source == "vpc_flow":
            src = node(f"ip:{r.src_ip}", "host" if is_internal(r.src_ip) else "ip", r.src_ip, r.ts)
            dst = node(f"ip:{r.dst_ip}", "host" if is_internal(r.dst_ip) else "ip", r.dst_ip, r.ts)
            edge(src, dst, "CONNECTED_TO" if r.outcome == "success" else "CONNECTION_REJECTED", r, susp)
            continue
        if r.source == "guardduty":
            finding = node(f"finding:{events[r.event_id].event_name}", "finding", events[r.event_id].event_name, r.ts)
            target = (f"identity:{r.actor}" if r.actor else f"res:{r.resource_key}" if r.resource_key else None)
            if target:
                node(target, "identity" if r.actor else "resource", r.actor or r.resource_key, r.ts, r.resource_type)
                edge(finding, target, "FLAGGED", r, susp)
            continue
        if not r.actor:
            continue
        actor = node(f"identity:{r.actor}", "identity", r.actor, r.ts)
        if r.src_ip:
            ip = node(f"ip:{r.src_ip}", "host" if is_internal(r.src_ip) else "ip", r.src_ip, r.ts)
            if r.event_type == "CONSOLE_LOGIN":
                edge(ip, actor, "AUTHENTICATED_FROM" if r.outcome == "success" else "FAILED_LOGIN", r, susp)
            else:
                edge(ip, actor, "API_CALLS_FROM", r, susp)
        principal = actor
        if r.key and r.key.startswith("AKIA"):
            principal = node(f"key:{r.key}", "key", r.key, r.ts)
            edge(actor, principal, "USED_KEY", r, susp)
        if r.created_key:
            created = node(f"key:{r.created_key}", "key", r.created_key, r.ts)
            edge(actor, created, "CREATED_ACCESS_KEY", r, susp)
        if r.resource_key and r.resource_key != r.actor:
            res = node(f"res:{r.resource_key}", "resource", r.resource_key, r.ts, r.resource_type)
            edge(principal, res, RELATIONS.get(r.event_type, "ACCESSED_RESOURCE"), r, susp)

    _rank(G)
    nodes = [{"id": n, **{k: v for k, v in d.items() if k != "first_seen"}, "first_seen": _iso(d["first_seen"])}
             for n, d in G.nodes(data=True)]
    nodes.sort(key=lambda n: -n["rank"])
    edges = [{"id": f"{u}->{v}", "source": u, "target": v, **{
        k: (_iso(val) if k in ("first_seen", "last_seen") else val) for k, val in d.items()}}
             for u, v, d in G.edges(data=True)]
    return {"nodes": nodes, "edges": edges, "top_nodes": [n["id"] for n in nodes[:5]]}


def _rank(G: nx.DiGraph) -> None:
    if G.number_of_nodes() == 0:
        return
    s_out = {n: sum(d["suspicion"] for _, _, d in G.out_edges(n, data=True)) for n in G}
    s_in = {n: sum(d["suspicion"] for _, _, d in G.in_edges(n, data=True)) for n in G}
    try:
        pr = nx.pagerank(G, weight="suspicion") if G.number_of_edges() else {n: 1.0 for n in G}
    except nx.PowerIterationFailedConvergence:
        pr = {n: 1.0 for n in G}
    deg = dict(G.degree())

    def norm(values: dict) -> dict:
        hi = max(values.values()) or 1.0
        return {k: v / hi for k, v in values.items()}

    s_out, s_in, pr, deg = norm(s_out), norm(s_in), norm(pr), norm(deg)
    for n in G:
        G.nodes[n].update(
            rank=round(0.4 * s_out[n] + 0.3 * s_in[n] + 0.2 * pr[n] + 0.1 * deg[n], 4),
            suspicion_out=round(s_out[n], 4), suspicion_in=round(s_in[n], 4),
            pagerank=round(pr[n], 4), degree=round(deg[n], 4))


def technique_for(row: EventRow) -> tuple[str, str, str] | None:
    if row.event_type == "CONSOLE_LOGIN" and row.outcome == "failure":
        return LOGIN_FAILURE_TECHNIQUE
    return MITRE_TECHNIQUES.get(row.event_type)


def describe(row: EventRow, event: SecurityEvent) -> str:
    who = row.actor or row.src_ip or "unknown"
    a = event.attributes or {}
    t = row.event_type
    if row.source == "vpc_flow":
        verb = "connection" if row.outcome == "success" else "rejected connection"
        return f"{verb} {row.src_ip} → {row.dst_ip}:{row.dst_port} ({row.nbytes:,} bytes)"
    if row.source == "guardduty":
        return f"GuardDuty: {a.get('title') or event.event_name}"
    if t == "CONSOLE_LOGIN":
        if row.outcome == "success":
            return f"{who} signed in to the console from {row.src_ip}" + ("" if a.get("mfa_used") else " without MFA")
        return f"Failed console login for {who} from {row.src_ip}"
    if t == "ACCESS_KEY_CREATED":
        return f"{who} created access key {a.get('created_access_key_id', '')} for {row.resource_id or who}"
    if a.get("policy_arn"):
        return f"{who} attached {a['policy_arn'].rsplit('/', 1)[-1]} to {row.resource_id}"
    if t == "SECURITY_GROUP_INGRESS_OPENED":
        return f"{who} opened {row.resource_id} to {', '.join(a.get('cidrs', []))} on port(s) {', '.join(a.get('ports', []))}"
    if t == "OBJECT_DOWNLOADED":
        return f"{who} downloaded {row.resource_id} ({row.nbytes / 1048576:.1f} MB)"
    if t == "INSTANCE_LAUNCHED":
        return f"{who} launched {a.get('instance_count', 1)} × {a.get('instance_type')} in {row.region}"
    action = event.event_name + (" (denied)" if row.access_denied else "")
    return f"{who} called {action}" + (f" on {row.resource_id}" if row.resource_id else "")


def build_timeline(rows: list[EventRow], events: dict[str, SecurityEvent], stages: dict[str, tuple[str, float]],
                   alert_events: set[str]) -> list[dict]:
    timeline = []
    for r in rows:
        tech = technique_for(r)
        stage, confidence = stages.get(r.event_id, ("NORMAL", 0.0))
        timeline.append({
            "event_id": r.event_id,
            "timestamp": _iso(r.ts),
            "layer": r.layer,
            "source": r.source,
            "event_type": r.event_type,
            "actor": r.actor,
            "source_ip": r.src_ip,
            "resource": r.resource_id,
            "description": describe(r, events[r.event_id]),
            "severity": r.severity,
            "stage": stage,
            "stage_confidence": round(confidence, 3),
            "mitre": {"id": tech[0], "name": tech[1], "tactic": tech[2]} if tech else None,
            "in_alert": r.event_id in alert_events,
        })
    return timeline


def mitre_summary(timeline: list[dict]) -> list[dict]:
    found: dict[str, dict] = {}
    for item in timeline:
        tech = item["mitre"]
        if not tech or (item["stage"] == "NORMAL" and not item["in_alert"]):
            continue
        entry = found.setdefault(tech["id"], {**tech, "count": 0, "first_seen": item["timestamp"]})
        entry["count"] += 1
    return sorted(found.values(), key=lambda t: t["first_seen"])
