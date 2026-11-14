"""Layer 4: turn normalized events into per-entity, per-time-window feature vectors.

An *entity* is an identity (IAM user / role session) or, for network flows, an internal host.
Each window is compared with that entity's own history (IPs, user agents, hours, resources, peers),
so the same action can look normal for one principal and anomalous for another.

Identifiers (IP addresses, user names, key IDs) are deliberately NOT model features: they are kept as
window metadata for correlation and graph building, which avoids models memorising entities.
"""

import ipaddress
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

from app.analysis.sensitivity import resource_sensitivity
from app.ml.taxonomy import EVENT_TYPE_OBSERVATION, STAGE_CLASS, STAGE_PRIORITY
from app.schemas.event import SecurityEvent

FEATURES = [
    # identity
    "failed_login_count", "successful_login_count", "login_without_mfa", "access_key_created_count",
    "privilege_change_count", "user_creation_count", "role_assumption_count", "discovery_count",
    "access_denied_count",
    # behaviour relative to the entity's own baseline
    "event_count", "api_calls_per_minute", "unique_event_types", "unique_resources", "write_ratio",
    "new_ip_ratio", "unique_source_ips", "off_hours_ratio", "new_event_type_ratio", "new_resource_ratio",
    "new_user_agent", "new_region_count", "activity_deviation", "hours_since_prev_activity",
    # compute and network configuration
    "instance_launch_count", "instances_launched", "instance_change_count", "key_pair_created_count",
    "sg_change_count", "sg_open_to_internet_count",
    # storage
    "object_download_count", "bytes_downloaded", "unique_objects", "sensitive_access_count",
    "object_delete_count", "bucket_policy_change_count",
    # management plane
    "logging_tamper_count",
    # network flows
    "flow_count", "rejected_flow_ratio", "unique_dst_ports", "unique_external_peers", "bytes_out_external",
    "bytes_in_external", "new_external_peer_ratio", "uncommon_port_flows", "inbound_ssh_accepted",
]
RATIO_FEATURES = {
    "write_ratio", "new_ip_ratio", "off_hours_ratio", "new_event_type_ratio", "new_resource_ratio",
    "rejected_flow_ratio", "new_external_peer_ratio", "new_user_agent",
}

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_COMMON_OUT_PORTS = {80, 443, 53, 123, 5432, 3306}
_GLOBAL_REGIONS = {"us-east-1"}
_DEFAULT_WORK_HOURS = range(3, 15)  # UTC; used until an entity has enough history of its own

_PRIV = {"POLICY_ATTACHED", "INLINE_POLICY_ADDED", "POLICY_VERSION_CHANGED", "GROUP_MEMBERSHIP_ADDED",
         "ROLE_TRUST_POLICY_CHANGED"}
_DISCOVERY = {"IDENTITY_DISCOVERY", "IAM_ENUMERATION", "STORAGE_ENUMERATION", "COMPUTE_ENUMERATION",
              "OBJECT_LISTING"}
_TAMPER = {"AUDIT_LOGGING_STOPPED", "AUDIT_TRAIL_MODIFIED", "THREAT_DETECTION_DISABLED", "FLOW_LOGS_DELETED"}
_INSTANCE_CHANGE = {"INSTANCE_TERMINATED", "INSTANCE_STOPPED", "INSTANCE_MODIFIED"}
_SG_CHANGE = {"SECURITY_GROUP_CREATED", "SECURITY_GROUP_INGRESS_OPENED", "SECURITY_GROUP_EGRESS_OPENED",
              "SECURITY_GROUP_RULE_REVOKED"}


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def ua_family(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    ua = user_agent.lower()
    if "aws internal" in ua:
        return "aws-internal"
    if ua.startswith("mozilla") or "console" in ua:
        kind = "browser"
    elif ua.startswith("aws-cli"):
        kind = "aws-cli"
    elif "boto" in ua:
        kind = "python-sdk"
    else:
        kind = ua.split("/")[0]
    os_name = next((o for o in ("kali", "linux", "darwin", "mac os", "windows") if o in ua), "")
    return f"{kind}:{os_name}"


@dataclass(slots=True)
class EventRow:
    event_id: str
    ts: float
    source: str
    event_type: str
    layer: str
    outcome: str
    actor: str | None
    key: str | None
    created_key: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    resource_id: str | None
    resource_type: str | None
    resource_key: str | None
    nbytes: int
    severity: float
    read_only: bool
    mfa_used: bool | None
    open_internet: bool
    access_denied: bool
    ua: str | None
    region: str | None
    instance_count: int
    entity: str
    observation: str


def _resource_key(resource_id: str | None, resource_type: str | None) -> str | None:
    """Correlate at bucket level, not per object."""
    if resource_type == "s3_object" and resource_id:
        return resource_id.split("/", 1)[0]
    return resource_id


def observation_symbol(source: str, event_type: str, outcome: str, access_denied: bool,
                       nbytes: int, dst_internal: bool) -> str:
    if source == "guardduty":
        return "THREAT_FINDING"
    if source == "vpc_flow":
        if outcome == "failure":
            return "FLOW_REJECTED"
        if nbytes > 10_000_000 and not dst_internal:
            return "FLOW_LARGE_OUT"
        return "FLOW_NORMAL"
    if access_denied:
        return "ACCESS_DENIED"
    if event_type == "CONSOLE_LOGIN":
        return "LOGIN_SUCCESS" if outcome == "success" else "LOGIN_FAILURE"
    return EVENT_TYPE_OBSERVATION.get(event_type, "ROUTINE_WRITE")


def to_rows(events: list[SecurityEvent]) -> list[EventRow]:
    rows = []
    for e in events:
        a = e.attributes or {}
        source = e.event_source.value
        if e.actor_id:
            entity = f"actor:{e.actor_id}"
        elif source == "vpc_flow":
            host = e.source_ip if is_internal(e.source_ip) else e.destination_ip if is_internal(e.destination_ip) else e.source_ip
            entity = f"host:{host}"
        elif e.resource_id:
            entity = f"resource:{e.resource_id}"
        else:
            entity = "unknown"
        nbytes = int(e.bytes_transferred or 0)
        access_denied = bool(a.get("access_denied"))
        rows.append(EventRow(
            event_id=e.event_id,
            ts=e.timestamp.timestamp(),
            source=source,
            event_type=e.event_type,
            layer=e.layer.value,
            outcome=e.outcome.value,
            actor=e.actor_id,
            key=e.access_key_id,
            created_key=a.get("created_access_key_id") or a.get("issued_access_key_id"),
            src_ip=e.source_ip,
            dst_ip=e.destination_ip,
            dst_port=e.destination_port,
            resource_id=e.resource_id,
            resource_type=e.resource_type,
            resource_key=_resource_key(e.resource_id, e.resource_type),
            nbytes=nbytes,
            severity=e.base_severity,
            read_only=bool(a.get("read_only")),
            mfa_used=a.get("mfa_used"),
            open_internet=bool(a.get("open_to_internet")),
            access_denied=access_denied,
            ua=ua_family(e.user_agent),
            region=e.region,
            instance_count=int(a.get("instance_count") or 0),
            entity=entity,
            observation=observation_symbol(source, e.event_type, e.outcome.value, access_denied, nbytes,
                                           is_internal(e.destination_ip)),
        ))
    rows.sort(key=lambda r: r.ts)
    return rows


@dataclass(slots=True)
class _History:
    ips: set = field(default_factory=set)
    uas: set = field(default_factory=set)
    types: set = field(default_factory=set)
    resources: set = field(default_factory=set)
    regions: set = field(default_factory=set)
    peers: set = field(default_factory=set)
    hours: list = field(default_factory=lambda: [0] * 24)
    n_events: int = 0
    n_windows: int = 0
    mean_events: float = 0.0
    last_ts: float | None = None

    def update(self, win: list[EventRow]) -> None:
        for e in win:
            if e.src_ip:
                self.ips.add(e.src_ip)
            if e.ua:
                self.uas.add(e.ua)
            self.types.add(e.event_type)
            if e.resource_key:
                self.resources.add(e.resource_key)
            if e.region:
                self.regions.add(e.region)
            for ip in (e.src_ip, e.dst_ip):
                if e.source == "vpc_flow" and ip and not is_internal(ip):
                    self.peers.add(ip)
            self.hours[int((e.ts % 86400) // 3600)] += 1
        n = len(win)
        self.n_events += n
        self.n_windows += 1
        self.mean_events = n if self.n_windows == 1 else 0.9 * self.mean_events + 0.1 * n
        self.last_ts = win[-1].ts


def _off_hours(e: EventRow, h: _History) -> bool:
    hour = int((e.ts % 86400) // 3600)
    if h.n_events >= 30:
        return h.hours[hour] / h.n_events < 0.02
    return hour not in _DEFAULT_WORK_HOURS


def _window_features(win: list[EventRow], h: _History) -> dict[str, float]:
    f = dict.fromkeys(FEATURES, 0.0)
    n = len(win)
    span_min = max(1.0, (win[-1].ts - win[0].ts) / 60)
    types, resources, src_ips, objects, dst_ports, peers = set(), set(), set(), set(), set(), set()
    writes = new_ip = with_ip = off = new_type = new_res = with_res = new_region = 0
    flows = rejected = new_peer = 0

    for e in win:
        t = e.event_type
        types.add(t)
        if e.resource_key:
            resources.add(e.resource_key)
            with_res += 1
            new_res += e.resource_key not in h.resources
        if e.src_ip and e.source != "vpc_flow":
            src_ips.add(e.src_ip)
            with_ip += 1
            new_ip += e.src_ip not in h.ips
        off += _off_hours(e, h)
        new_type += t not in h.types
        if e.region and e.region not in _GLOBAL_REGIONS and e.region not in h.regions:
            new_region += 1
        if e.source == "cloudtrail" and not e.read_only:
            writes += 1
        f["access_denied_count"] += e.access_denied

        if t == "CONSOLE_LOGIN":
            if e.outcome == "success":
                f["successful_login_count"] += 1
                f["login_without_mfa"] += e.mfa_used is False
            else:
                f["failed_login_count"] += 1
        elif t == "ACCESS_KEY_CREATED":
            f["access_key_created_count"] += 1
        elif t in _PRIV:
            f["privilege_change_count"] += 1
        elif t in ("IAM_USER_CREATED", "LOGIN_PROFILE_CHANGED"):
            f["user_creation_count"] += 1
        elif t == "ROLE_ASSUMED":
            f["role_assumption_count"] += 1
        elif t == "INSTANCE_LAUNCHED":
            f["instance_launch_count"] += 1
            f["instances_launched"] += e.instance_count
        elif t in _INSTANCE_CHANGE:
            f["instance_change_count"] += 1
        elif t == "KEY_PAIR_CREATED":
            f["key_pair_created_count"] += 1
        elif t == "OBJECT_DOWNLOADED":
            f["object_download_count"] += 1
            f["bytes_downloaded"] += e.nbytes
            objects.add(e.resource_id)
        elif t == "OBJECT_DELETED":
            f["object_delete_count"] += 1
        elif t in ("BUCKET_POLICY_CHANGED", "BUCKET_ACL_CHANGED", "PUBLIC_ACCESS_BLOCK_CHANGED"):
            f["bucket_policy_change_count"] += 1
        elif t in _TAMPER:
            f["logging_tamper_count"] += 1
        if t in _DISCOVERY or e.event_type == "API_CALL_READ" and e.source == "cloudtrail" and "Describe" in t:
            f["discovery_count"] += 1
        if t in _SG_CHANGE:
            f["sg_change_count"] += 1
            f["sg_open_to_internet_count"] += e.open_internet
        if e.resource_key and resource_sensitivity(e.resource_key, e.resource_type) >= 0.8 and e.source == "cloudtrail":
            f["sensitive_access_count"] += 1

        if e.source == "vpc_flow":
            flows += 1
            rejected += e.outcome == "failure"
            if e.dst_port is not None:
                dst_ports.add(e.dst_port)
            src_in, dst_in = is_internal(e.src_ip), is_internal(e.dst_ip)
            peer = e.dst_ip if src_in and not dst_in else e.src_ip if dst_in and not src_in else None
            if peer:
                peers.add(peer)
                new_peer += peer not in h.peers
            if src_in and not dst_in and e.outcome == "success":
                f["bytes_out_external"] += e.nbytes
                if e.dst_port not in _COMMON_OUT_PORTS:
                    f["uncommon_port_flows"] += 1
            if dst_in and not src_in and e.outcome == "success":
                f["bytes_in_external"] += e.nbytes
                if e.dst_port == 22:
                    f["inbound_ssh_accepted"] += 1

    f["event_count"] = n
    f["api_calls_per_minute"] = n / span_min
    f["unique_event_types"] = len(types)
    f["unique_resources"] = len(resources)
    f["unique_objects"] = len(objects)
    f["write_ratio"] = writes / n
    f["new_ip_ratio"] = new_ip / with_ip if with_ip else 0.0
    f["unique_source_ips"] = len(src_ips)
    f["off_hours_ratio"] = off / n
    f["new_event_type_ratio"] = new_type / n
    f["new_resource_ratio"] = new_res / with_res if with_res else 0.0
    f["new_user_agent"] = float(any(e.ua and e.ua not in h.uas for e in win if e.source == "cloudtrail"))
    f["new_region_count"] = new_region
    f["activity_deviation"] = n / (h.mean_events + 1.0) if h.n_windows else n / 6.0
    gap_h = (win[0].ts - h.last_ts) / 3600 if h.last_ts else 168.0
    f["hours_since_prev_activity"] = min(168.0, gap_h)
    f["flow_count"] = flows
    f["rejected_flow_ratio"] = rejected / flows if flows else 0.0
    f["unique_dst_ports"] = len(dst_ports)
    f["unique_external_peers"] = len(peers)
    f["new_external_peer_ratio"] = new_peer / max(1, len(peers)) if peers else 0.0
    return f


def _window_label(win: list[EventRow], labels) -> tuple[str, list[str], list[str]]:
    stages, scenarios = set(), set()
    for e in win:
        lab = labels.get(e.event_id)
        if lab is not None and lab.stage != "NORMAL":
            stages.add(lab.stage)
            scenarios.add(lab.scenario_id)
    if not stages:
        return "normal", [], []
    top = next(s for s in STAGE_PRIORITY if s in stages)
    return STAGE_CLASS[top], sorted(stages), sorted(scenarios)


def build_windows(
    rows: list[EventRow],
    window_minutes: int = 15,
    score_from: datetime | None = None,
    labels: dict | None = None,
) -> pd.DataFrame:
    """One row per (entity, window) with features + metadata. Events before `score_from` only build
    history. If `labels` (event_id -> Label) is given, adds label / stages / scenario_ids."""
    width = window_minutes * 60
    cutoff = score_from.timestamp() if score_from else None
    by_entity: dict[str, list[EventRow]] = defaultdict(list)
    for r in rows:
        by_entity[r.entity].append(r)

    out = []
    for entity, evs in by_entity.items():
        hist = _History()
        i = 0
        while i < len(evs):
            start = math.floor(evs[i].ts / width) * width
            j = i
            while j < len(evs) and evs[j].ts < start + width:
                j += 1
            win = evs[i:j]
            if cutoff is None or start >= cutoff:
                record = _window_features(win, hist)
                ips = {ip for e in win for ip in (e.src_ip, e.dst_ip) if ip}
                record.update(
                    entity=entity,
                    window_start=datetime.fromtimestamp(start, tz=timezone.utc),
                    window_end=datetime.fromtimestamp(start + width, tz=timezone.utc),
                    first_ts=win[0].ts,
                    last_ts=win[-1].ts,
                    event_ids=[e.event_id for e in win],
                    actors=sorted({e.actor for e in win if e.actor}),
                    keys=sorted({k for e in win for k in (e.key, e.created_key) if k}),
                    ips=sorted(ips),
                    resources=sorted({e.resource_key for e in win if e.resource_key}),
                    max_severity=max(e.severity for e in win),
                )
                if labels is not None:
                    record["label"], record["stages"], record["scenario_ids"] = _window_label(win, labels)
                out.append(record)
            hist.update(win)
            i = j
    frame = pd.DataFrame(out)
    if not frame.empty:
        frame = frame.sort_values(["window_start", "entity"]).reset_index(drop=True)
    return frame


def model_matrix(windows: pd.DataFrame) -> pd.DataFrame:
    """Model input: counts and bytes are log-scaled, ratios kept as-is."""
    X = windows[FEATURES].astype(float).copy()
    for col in FEATURES:
        if col not in RATIO_FEATURES:
            X[col] = X[col].clip(lower=0).map(math.log1p)
    return X
