"""Layer 7b: explainable incident risk score (a transparent fusion rule, not an ML model).

R = 100 · (0.20·A + 0.25·P + 0.20·C + 0.15·S + 0.10·T + 0.10·D), every term in [0, 1].
"""

from dataclasses import dataclass

COMPONENTS = [
    ("A", "anomaly", 0.20, "Isolation Forest anomaly (ECDF vs. normal activity)"),
    ("P", "attack_probability", 0.25, "Classifier attack probability or rule confidence"),
    ("C", "correlation", 0.20, "Cross-layer correlation strength × mean attack evidence of linked alerts"),
    ("S", "sequence_severity", 0.15, "Kill-chain progress decoded by the HMM"),
    ("T", "threat_intel", 0.10, "External threat intelligence (GuardDuty severity)"),
    ("D", "resource_sensitivity", 0.10, "Sensitivity of the most sensitive resource involved"),
]
LEVELS = [(81, "CRITICAL"), (61, "HIGH"), (41, "MEDIUM"), (21, "LOW"), (0, "MINIMAL")]


@dataclass
class RiskInputs:
    anomaly: float
    attack_probability: float
    correlation: float
    sequence_severity: float
    threat_intel: float
    resource_sensitivity: float


def risk_level(score: float) -> str:
    return next(level for floor, level in LEVELS if score >= floor)


def compute_risk(inputs: RiskInputs) -> dict:
    breakdown = []
    total = 0.0
    for symbol, name, weight, description in COMPONENTS:
        value = min(1.0, max(0.0, float(getattr(inputs, name))))
        contribution = 100 * weight * value
        total += contribution
        breakdown.append({"symbol": symbol, "name": name, "description": description, "value": round(value, 4),
                          "weight": weight, "contribution": round(contribution, 2)})
    score = round(total, 1)
    drivers = [b for b in sorted(breakdown, key=lambda b: -b["contribution"]) if b["contribution"] > 0]
    return {
        "score": score,
        "level": risk_level(score),
        "formula": "R = 100 * (0.20A + 0.25P + 0.20C + 0.15S + 0.10T + 0.10D)",
        "components": breakdown,
        "top_drivers": [d["name"] for d in drivers[:3]],
    }
