"""Reinforcement-learning response *simulator* (research extension, offline only).

Formulation: each incident is one decision, so this is a contextual bandit, the one-step special
case of RL. State = (risk level, primary attack class); actions = abstract response strategies.
A tabular Q-learner with epsilon-greedy exploration learns from labelled training incidents under
the explicit reward model below, then is compared with the CloudShield policy engine on held-out
incidents.

The reward model is an assumption made for the experiment, not a measurement. The learned policy is
never used to execute anything: CloudShield's real response path stays policy-based and approved.
"""

import random
from dataclasses import dataclass, field

ACTIONS = ["MONITOR", "NOTIFY", "CONTAIN_IDENTITY", "CONTAIN_NETWORK", "FULL_CONTAINMENT"]
LEVELS = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Damage an attack of each class causes if left alone (arbitrary units).
DAMAGE = {"data_exfiltration": 10, "privilege_escalation": 8, "defense_evasion": 7, "credential_compromise": 6,
          "resource_abuse": 6, "reconnaissance": 3, "brute_force": 2, "suspicious_activity": 3}
IDENTITY_CENTRIC = {"credential_compromise", "privilege_escalation", "data_exfiltration", "defense_evasion",
                    "reconnaissance", "brute_force", "suspicious_activity"}
# Share of the damage each action prevents.
EFFECT = {
    "MONITOR": lambda c: 0.0,
    "NOTIFY": lambda c: 0.3,  # an analyst eventually acts, after a delay
    "CONTAIN_IDENTITY": lambda c: 0.9 if c in IDENTITY_CENTRIC else 0.4,
    "CONTAIN_NETWORK": lambda c: 0.9 if c == "resource_abuse" else 0.5 if c == "data_exfiltration" else 0.2,
    "FULL_CONTAINMENT": lambda c: 0.95,
}
OPERATING_COST = {"MONITOR": 0.0, "NOTIFY": 0.5, "CONTAIN_IDENTITY": 1.0, "CONTAIN_NETWORK": 1.0, "FULL_CONTAINMENT": 2.0}
# Extra cost of acting on a benign incident (locking out a legitimate user, breaking a service).
DISRUPTION = {"MONITOR": 0.0, "NOTIFY": 0.0, "CONTAIN_IDENTITY": 4.0, "CONTAIN_NETWORK": 3.0, "FULL_CONTAINMENT": 6.0}

IDENTITY_ACTIONS = {"DEACTIVATE_ACCESS_KEY", "DETACH_USER_POLICY", "ATTACH_DENY_ALL", "REMOVE_USER_FROM_GROUP",
                    "DELETE_INLINE_POLICY"}
NETWORK_ACTIONS = {"REVOKE_SECURITY_GROUP_INGRESS", "STOP_INSTANCES", "BLOCK_PUBLIC_ACCESS"}


@dataclass
class IncidentCase:
    level: str
    primary_class: str
    is_attack: bool
    true_class: str | None
    recommended: list[str] = field(default_factory=list)

    @property
    def state(self) -> tuple[str, str]:
        return self.level, self.primary_class


def reward(case: IncidentCase, action: str) -> float:
    if case.is_attack:
        cls = case.true_class or case.primary_class
        return DAMAGE.get(cls, 3) * EFFECT[action](cls) - OPERATING_COST[action]
    return -OPERATING_COST[action] - DISRUPTION[action]


def policy_engine_action(case: IncidentCase) -> str:
    """What CloudShield's rule-based policy would do if every proposed action were approved."""
    ident = any(a in IDENTITY_ACTIONS for a in case.recommended)
    net = any(a in NETWORK_ACTIONS for a in case.recommended)
    if ident and net:
        return "FULL_CONTAINMENT"
    if ident:
        return "CONTAIN_IDENTITY"
    if net:
        return "CONTAIN_NETWORK"
    if case.recommended:
        return "NOTIFY"
    return "MONITOR"


class QPolicy:
    def __init__(self, alpha: float = 0.1, epsilon: float = 0.2, seed: int = 0):
        self.q: dict[tuple, dict[str, float]] = {}
        self.alpha, self.epsilon = alpha, epsilon
        self.rng = random.Random(seed)

    def _row(self, state) -> dict[str, float]:
        return self.q.setdefault(state, {a: 0.0 for a in ACTIONS})

    def act(self, state, explore: bool = False) -> str:
        row = self._row(state)
        if explore and self.rng.random() < self.epsilon:
            return self.rng.choice(ACTIONS)
        if state not in self.q or all(v == 0.0 for v in row.values()):
            return "NOTIFY"  # unseen state: ask a human
        return max(row, key=row.get)

    def train(self, cases: list[IncidentCase], episodes: int = 200) -> "QPolicy":
        for _ in range(episodes):
            for case in self.rng.sample(cases, len(cases)):
                a = self.act(case.state, explore=True)
                row = self._row(case.state)
                row[a] += self.alpha * (reward(case, a) - row[a])
        return self

    def table(self) -> list[dict]:
        return [{"level": s[0], "class": s[1], "best_action": max(r, key=r.get),
                 **{a: round(v, 2) for a, v in r.items()}} for s, r in sorted(self.q.items())]


def evaluate(cases: list[IncidentCase], choose) -> dict:
    total = 0.0
    contained_attacks = attacks = disrupted_benign = benign = 0
    for case in cases:
        a = choose(case)
        total += reward(case, a)
        containing = a in ("CONTAIN_IDENTITY", "CONTAIN_NETWORK", "FULL_CONTAINMENT")
        if case.is_attack:
            attacks += 1
            contained_attacks += containing
        else:
            benign += 1
            disrupted_benign += containing
    return {"mean_reward": round(total / max(1, len(cases)), 3),
            "attack_containment_rate": round(contained_attacks / max(1, attacks), 3),
            "benign_disruption_rate": round(disrupted_benign / max(1, benign), 3)}
