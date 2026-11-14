"""Layer 6: cross-layer alert correlation.

C(Ai, Aj) = 0.30·T + 0.25·I + 0.20·R + 0.15·N + 0.10·S

T  temporal proximity      exp(-gap / tau)
I  identity overlap        actors and access keys (incl. keys one alert *created* and another *used*)
R  resource overlap        bucket / instance / security group / IAM user / trail
N  network overlap         IP addresses
S  attack-stage compatibility (kill-chain order of the predicted classes)

Overlaps use the overlap coefficient |A∩B| / min(|A|,|B|). Entities shared by many identities in the
analysed period (office NAT IPs, popular buckets) carry no evidence of a common attack and are
ignored ("commonness filter"). Two alerts are linked only if C ≥ threshold AND they share at least
one identity, resource or network entity, so temporal proximity alone never merges alerts.
Incidents are the connected components of the resulting alert graph.
"""

import math
from collections import Counter
from dataclasses import dataclass, field

from app.analysis.alerts import Alert

WEIGHTS = {"T": 0.30, "I": 0.25, "R": 0.20, "N": 0.15, "S": 0.10}


@dataclass
class CorrelationConfig:
    # Tuned by grid search on a separate tuning organisation (seed 8), never on the test sets.
    threshold: float = 0.4
    tau_minutes: float = 120.0
    max_gap_minutes: float = 360.0
    common_entity_limit: int = 3  # entities used by more identities than this are ignored
    use_temporal: bool = True
    use_entities: bool = True
    use_stage: bool = True
    require_shared_entity: bool = True


@dataclass
class Link:
    a: int
    b: int
    score: float
    components: dict[str, float]


@dataclass
class CorrelatedGroup:
    alert_indices: list[int]
    links: list[Link] = field(default_factory=list)

    @property
    def correlation_score(self) -> float:
        return round(sum(l.score for l in self.links) / len(self.links), 4) if self.links else 0.0


def _overlap(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def _common_entities(alerts: list[Alert], limit: int) -> set[str]:
    """IPs/resources seen with more than `limit` distinct identities across the alerts' entities."""
    owners: dict[str, set[str]] = {}
    for al in alerts:
        for ent in al.ips | al.resources:
            owners.setdefault(ent, set()).add(al.entity)
    return {ent for ent, who in owners.items() if len(who) > limit}


def stage_compatibility(earlier: Alert, later: Alert) -> float:
    a, b = earlier.stage_order, later.stage_order
    if a is None or b is None:
        return 0.5
    if b >= a:
        return 1.0
    return 0.5 if a - b == 1 else 0.2


def pair_score(a: Alert, b: Alert, common: set[str], cfg: CorrelationConfig) -> tuple[float, dict[str, float], bool]:
    first, second = (a, b) if a.start <= b.start else (b, a)
    gap = max(0.0, (second.start - first.end).total_seconds())
    T = math.exp(-gap / (cfg.tau_minutes * 60)) if cfg.use_temporal else 0.0
    if cfg.use_entities:
        I = _overlap(a.actors | a.keys, b.actors | b.keys)
        R = _overlap(a.resources - common, b.resources - common)
        N = _overlap(a.ips - common, b.ips - common)
    else:
        I = R = N = 0.0
    S = stage_compatibility(first, second) if cfg.use_stage else 0.0
    parts = {"T": round(T, 4), "I": round(I, 4), "R": round(R, 4), "N": round(N, 4), "S": round(S, 4)}
    score = sum(WEIGHTS[k] * v for k, v in parts.items())
    return round(score, 4), parts, (I > 0 or R > 0 or N > 0)


def correlate(alerts: list[Alert], cfg: CorrelationConfig | None = None) -> list[CorrelatedGroup]:
    cfg = cfg or CorrelationConfig()
    order = sorted(range(len(alerts)), key=lambda i: alerts[i].start)
    common = _common_entities(alerts, cfg.common_entity_limit) if cfg.use_entities else set()
    parent = list(range(len(alerts)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    links: list[Link] = []
    max_gap = cfg.max_gap_minutes * 60
    for pos, i in enumerate(order):
        for j in order[pos + 1:]:
            if (alerts[j].start - alerts[i].end).total_seconds() > max_gap:
                break
            score, parts, shared = pair_score(alerts[i], alerts[j], common, cfg)
            if score >= cfg.threshold and (shared or not cfg.require_shared_entity):
                links.append(Link(i, j, score, parts))
                parent[find(i)] = find(j)

    groups: dict[int, CorrelatedGroup] = {}
    for i in order:
        groups.setdefault(find(i), CorrelatedGroup([])).alert_indices.append(i)
    for link in links:
        groups[find(link.a)].links.append(link)
    return list(groups.values())


def dominant_class(alerts: list[Alert]) -> str:
    """Most advanced kill-chain class among confident alerts (falls back to the most common)."""
    classes = [a.predicted_class for a in alerts if a.predicted_class not in ("unknown", "normal")]
    if not classes:
        return "suspicious_activity"
    counts = Counter(classes)
    return max(counts, key=lambda c: (CLASS_ORDER_FALLBACK.get(c, 0), counts[c]))


CLASS_ORDER_FALLBACK = {
    "data_exfiltration": 6, "resource_abuse": 6, "defense_evasion": 5, "privilege_escalation": 4,
    "credential_compromise": 3, "brute_force": 2, "reconnaissance": 1,
}
