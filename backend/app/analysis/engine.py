"""In-memory analysis engine: events → windows → detections → incidents (with HMM stages, SHAP
explanations, risk, attack graph, timeline, MITRE mapping, response recommendations).

It is deliberately free of database code so the same engine powers the API pipeline and the
offline experiments."""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

from app.analysis.alerts import Alert, model_alerts, rule_alerts
from app.analysis.correlation import CorrelationConfig, correlate, dominant_class
from app.analysis.forensics import build_attack_graph, build_timeline, mitre_summary
from app.analysis.risk import RiskInputs, compute_risk
from app.analysis.sensitivity import resource_sensitivity
from app.ml.explain import FEATURE_DESCRIPTIONS, Explainer
from app.ml.features import EventRow, build_windows, model_matrix, to_rows
from app.ml.hmm import sequence_severity
from app.ml.models import ModelBundle
from app.processing.hashing import sha256_hex
from app.response.policies import recommend_actions
from app.schemas.event import SecurityEvent

CLASS_TITLES = {
    "brute_force": "Brute-force login attempts",
    "credential_compromise": "Possible credential compromise",
    "reconnaissance": "Cloud reconnaissance",
    "privilege_escalation": "Privilege escalation",
    "data_exfiltration": "Possible data exfiltration",
    "defense_evasion": "Defense evasion (logging/firewall tampering)",
    "resource_abuse": "Resource hijacking (e.g. cryptomining)",
    "suspicious_activity": "Suspicious activity",
}


@dataclass
class AnalysisConfig:
    window_minutes: int = 15
    attack_threshold: float = 0.5
    anomaly_threshold: float = 0.995
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    explain: bool = True


@dataclass
class Incident:
    incident_id: str
    title: str
    primary_class: str
    start: datetime
    end: datetime
    alerts: list[Alert]
    event_ids: list[str]
    actors: list[str]
    source_ips: list[str]
    resources: list[str]
    access_keys: list[str]
    correlation_score: float
    links: list[dict]
    sequence: list[dict]
    risk: dict
    explanation: dict
    graph: dict
    timeline: list[dict]
    mitre: list[dict]
    recommendations: list[dict]


@dataclass
class AnalysisResult:
    windows: pd.DataFrame
    alerts: list[Alert]
    incidents: list[Incident]
    n_events: int


class AnalysisEngine:
    def __init__(self, bundle: ModelBundle, config: AnalysisConfig | None = None):
        self.bundle = bundle
        self.config = config or AnalysisConfig()
        self.explainer = Explainer(bundle) if self.config.explain else None

    def detect(self, rows: list[EventRow], score_from: datetime | None) -> tuple[pd.DataFrame, list[Alert]]:
        cfg = self.config
        windows = build_windows(rows, cfg.window_minutes, score_from=score_from)
        if windows.empty:
            return windows, rule_alerts(rows, score_from)
        X = model_matrix(windows)
        anomaly = self.bundle.anomaly_score(X)
        proba = self.bundle.class_proba(X)
        windows = windows.assign(anomaly_score=anomaly, attack_probability=1 - proba[:, 0],
                                 predicted_class=[self.bundle.classes[i] for i in proba.argmax(1)])
        alerts = model_alerts(windows, anomaly, proba, self.bundle.version, cfg.attack_threshold, cfg.anomaly_threshold)
        if self.explainer and alerts:
            idx = [a.window_index for a in alerts]
            classes = [self.bundle.classes.index(a.predicted_class) for a in alerts]
            for alert, expl in zip(alerts, self.explainer.explain(X.iloc[idx], windows.iloc[idx], classes)):
                alert.explanation = expl
        return windows, alerts + rule_alerts(rows, score_from)

    def analyze(self, events: list[SecurityEvent], score_from: datetime | None = None) -> AnalysisResult:
        rows = to_rows(events)
        windows, alerts = self.detect(rows, score_from)
        groups = correlate(alerts, self.config.correlation)
        events_by_id = {e.event_id: e for e in events}
        rows_by_id = {r.event_id: r for r in rows}
        incidents = [self._incident(alerts, g, rows_by_id, events_by_id) for g in groups]
        incidents.sort(key=lambda inc: -inc.risk["score"])
        return AnalysisResult(windows, alerts, incidents, len(events))

    def _incident(self, all_alerts: list[Alert], group, rows_by_id, events_by_id) -> Incident:
        alerts = sorted((all_alerts[i] for i in group.alert_indices), key=lambda a: a.start)
        event_ids = sorted({eid for a in alerts for eid in a.event_ids}, key=lambda e: rows_by_id[e].ts)
        rows = [rows_by_id[e] for e in event_ids]

        stages, confidences = self.bundle.hmm.decode([r.observation for r in rows])
        stage_by_event = {r.event_id: (s, c) for r, s, c in zip(rows, stages, confidences)}
        seq_severity = sequence_severity(stages)

        model = [a for a in alerts if a.kind == "model"]
        event_score = {}
        for a in alerts:
            for eid in a.event_ids:
                event_score[eid] = max(event_score.get(eid, 0.0), a.score)
        risk = compute_risk(RiskInputs(
            anomaly=max((a.anomaly_score for a in model), default=0.0),
            attack_probability=max((a.attack_probability for a in alerts), default=0.0),
            correlation=group.correlation_score,
            sequence_severity=seq_severity,
            threat_intel=max((r.severity for r in rows if r.source == "guardduty"), default=0.0),
            resource_sensitivity=max((resource_sensitivity(r.resource_key, r.resource_type) for r in rows), default=0.0),
        ))

        primary = dominant_class(alerts)
        actors = Counter(r.actor for r in rows if r.actor)
        main_actor = actors.most_common(1)[0][0] if actors else (alerts[0].entity.split(":", 1)[-1])
        timeline = build_timeline(rows, events_by_id, stage_by_event, {e for a in alerts for e in a.event_ids})
        graph = build_attack_graph(rows, events_by_id, event_score)
        explanation = self._explanation(model, risk)
        incident_id = "inc_" + sha256_hex("|".join(sorted(a.alert_id for a in alerts)).encode())[:16]
        incident = Incident(
            incident_id=incident_id,
            title=f"{CLASS_TITLES.get(primary, primary)}: {main_actor}",
            primary_class=primary,
            start=alerts[0].start,
            end=max(a.end for a in alerts),
            alerts=alerts,
            event_ids=event_ids,
            actors=sorted(actors),
            source_ips=sorted({r.src_ip for r in rows if r.src_ip}),
            resources=sorted({r.resource_key for r in rows if r.resource_key}),
            access_keys=sorted({k for r in rows for k in (r.key, r.created_key) if k}),
            correlation_score=group.correlation_score,
            links=[{"from": all_alerts[l.a].alert_id, "to": all_alerts[l.b].alert_id,
                    "score": l.score, "components": l.components} for l in group.links],
            sequence=[{"event_id": r.event_id, "observation": r.observation, "stage": s, "confidence": round(c, 3)}
                      for r, s, c in zip(rows, stages, confidences)],
            risk=risk,
            explanation=explanation,
            graph=graph,
            timeline=timeline,
            mitre=mitre_summary(timeline),
            recommendations=[],
        )
        incident.recommendations = recommend_actions(incident, rows, events_by_id)
        return incident

    def _explanation(self, model_alerts_: list[Alert], risk: dict) -> dict:
        top = max(model_alerts_, key=lambda a: a.score, default=None)
        reasons = []
        if top and top.explanation:
            for f in top.explanation["features"]:
                if f["shap"] > 0 and len(reasons) < 5:
                    reasons.append(f"{FEATURE_DESCRIPTIONS.get(f['feature'], f['feature'])} "
                                   f"(value {f['value']:.3g}, SHAP +{f['shap']:.2f})")
        return {
            "alert_id": top.alert_id if top else None,
            "predicted_class": top.predicted_class if top else None,
            "class_probability": top.class_probability if top else None,
            "probabilities": top.probabilities if top else {},
            "shap": top.explanation if top else None,
            "reasons": reasons,
            "risk_drivers": risk["top_drivers"],
            "note": "SHAP values explain the XGBoost classification in log-odds space; the risk score is "
                    "a separate, transparent fusion rule.",
        }
