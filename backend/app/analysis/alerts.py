"""Turn scored windows and high-severity events into alerts (detections)."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from app.ml.features import EventRow
from app.ml.taxonomy import ATTACK_CLASSES, CLASS_ORDER
from app.processing.hashing import sha256_hex

RULE_SEVERITY_THRESHOLD = 0.9


@dataclass
class Alert:
    alert_id: str
    kind: str  # "model" | "rule"
    entity: str
    start: datetime
    end: datetime
    event_ids: list[str]
    actors: set[str]
    keys: set[str]
    ips: set[str]
    resources: set[str]
    predicted_class: str
    class_probability: float
    attack_probability: float
    anomaly_score: float
    score: float  # max(attack probability, anomaly score) for models; rule confidence for rules
    rule: str | None = None
    explanation: dict | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    window_index: int | None = None
    available_at: datetime | None = None  # when the detection could be raised (window close / event time)

    @property
    def stage_order(self) -> int | None:
        return CLASS_ORDER.get(self.predicted_class)


def _alert_id(*parts: str) -> str:
    return "det_" + sha256_hex("|".join(parts).encode())[:20]


def model_alerts(
    windows: pd.DataFrame,
    anomaly: np.ndarray,
    proba: np.ndarray,
    model_version: str,
    attack_threshold: float,
    anomaly_threshold: float,
) -> list[Alert]:
    alerts = []
    attack_prob = 1.0 - proba[:, 0]
    for i in np.flatnonzero((attack_prob >= attack_threshold) | (anomaly >= anomaly_threshold)):
        row = windows.iloc[i]
        cls_idx = int(proba[i].argmax())
        if cls_idx == 0:  # anomaly-only alert: report the most likely attack class
            cls_idx = int(proba[i, 1:].argmax()) + 1
        alerts.append(Alert(
            alert_id=_alert_id(model_version, row["entity"], row["window_start"].isoformat()),
            kind="model",
            entity=row["entity"],
            start=datetime.fromtimestamp(row["first_ts"], tz=timezone.utc),
            end=datetime.fromtimestamp(row["last_ts"], tz=timezone.utc),
            event_ids=list(row["event_ids"]),
            actors=set(row["actors"]),
            keys=set(row["keys"]),
            ips=set(row["ips"]),
            resources=set(row["resources"]),
            predicted_class=ATTACK_CLASSES[cls_idx],
            class_probability=round(float(proba[i, cls_idx]), 4),
            attack_probability=round(float(attack_prob[i]), 4),
            anomaly_score=round(float(anomaly[i]), 4),
            score=round(float(max(attack_prob[i], anomaly[i])), 4),
            probabilities={c: round(float(p), 4) for c, p in zip(ATTACK_CLASSES, proba[i])},
            window_index=int(i),
            available_at=row["window_end"].to_pydatetime(),
        ))
    return alerts


_RULE_CLASS = {
    "AUDIT_LOGGING_STOPPED": "defense_evasion",
    "THREAT_DETECTION_DISABLED": "defense_evasion",
    "FLOW_LOGS_DELETED": "defense_evasion",
}


def rule_alerts(rows: list[EventRow], since: datetime | None) -> list[Alert]:
    """Deterministic detections that must not depend on a model: tampering with logging/detection,
    and every GuardDuty finding (as an external threat-intelligence signal)."""
    cutoff = since.timestamp() if since else None
    alerts = []
    for r in rows:
        if cutoff is not None and r.ts < cutoff:
            continue
        if r.source == "guardduty":
            rule, cls, conf = "GUARDDUTY_FINDING", None, r.severity
        elif r.severity >= RULE_SEVERITY_THRESHOLD and r.event_type in _RULE_CLASS:
            rule, cls, conf = f"RULE_{r.event_type}", _RULE_CLASS[r.event_type], r.severity
        else:
            continue
        ts = datetime.fromtimestamp(r.ts, tz=timezone.utc)
        alerts.append(Alert(
            alert_id=_alert_id("rule", r.event_id),
            kind="rule",
            entity=r.entity,
            start=ts,
            end=ts,
            event_ids=[r.event_id],
            actors={r.actor} if r.actor else set(),
            keys={k for k in (r.key, r.created_key) if k},
            ips={ip for ip in (r.src_ip, r.dst_ip) if ip},
            resources={r.resource_key} if r.resource_key else set(),
            predicted_class=cls or "unknown",
            class_probability=conf,
            attack_probability=conf if cls else 0.0,
            anomaly_score=0.0,
            score=conf,
            rule=rule,
            available_at=ts,
        ))
    return alerts
