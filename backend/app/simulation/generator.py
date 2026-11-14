"""Generate a labelled dataset: normal organisation activity plus injected attack scenarios."""

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.processing.hashing import canonical_json, sha256_hex
from app.processing.normalizers import NormalizationError, SkipRecord, get_normalizer
from app.schemas.event import EventSource, EvidenceRef, SecurityEvent
from app.simulation.attacks import SCENARIOS, AttackBuilder, ScenarioInfo
from app.simulation.builders import Label, RecordFactory, SimRecord
from app.simulation.environment import attacker_ip, build_environment
from app.simulation.normal import NormalActivity


@dataclass
class SimulatedDataset:
    seed: int
    start: datetime
    end: datetime
    warmup_days: int
    records: list[SimRecord]
    scenarios: list[ScenarioInfo]

    def by_source(self) -> dict[EventSource, list[dict]]:
        grouped: dict[EventSource, list[dict]] = {s: [] for s in EventSource}
        for rec in self.records:
            grouped[rec.source].append(rec.raw)
        return grouped


def generate_dataset(
    seed: int = 7,
    days: int = 14,
    attacks_per_day: float = 3.0,
    stealthy_fraction: float = 0.2,
    warmup_days: int = 3,
    start: datetime | None = None,
    scenario_kinds: list[str] | None = None,
) -> SimulatedDataset:
    rng = random.Random(seed)
    start = (start or datetime(2026, 10, 1, tzinfo=timezone.utc)).replace(hour=0, minute=0, second=0, microsecond=0)
    env = build_environment(rng)
    factory = RecordFactory(rng)

    normal = NormalActivity(rng, env, factory)
    for d in range(days):
        normal.day(start + timedelta(days=d))

    kinds = scenario_kinds or list(SCENARIOS)
    weights = [SCENARIOS[k][1] for k in kinds]
    builder = AttackBuilder(rng, env, factory)
    records, scenarios = list(normal.out), []
    attack_days = max(0, days - warmup_days)
    n_attacks = round(attacks_per_day * attack_days)
    for i in range(n_attacks):
        kind = rng.choices(kinds, weights)[0]
        if kind == "insider_exfiltration":
            victim = rng.choice(env.of_kind("analyst"))
        else:
            victim = rng.choice(env.of_kind("developer", "admin", "analyst"))
        day = start + timedelta(days=warmup_days + rng.randrange(attack_days))
        off_hours = rng.random() < 0.5 and kind != "insider_exfiltration"
        hour = rng.uniform(15, 23) if off_hours else rng.uniform(victim.work_start, victim.work_end - 1)
        stealthy = kind != "brute_force_then_access" and rng.random() < stealthy_fraction
        out, info = builder.build(f"SCN-{seed}-{i:03d}", kind, victim, day + timedelta(hours=hour),
                                  attacker_ip(rng), stealthy)
        records.extend(out)
        scenarios.append(info)

    records.sort(key=lambda r: r.timestamp)
    return SimulatedDataset(seed, start, start + timedelta(days=days), warmup_days, records, scenarios)


def normalize_dataset(dataset: SimulatedDataset) -> tuple[list[SecurityEvent], dict[str, Label]]:
    """Run every simulated record through the production normalizers (no DB) and keep labels."""
    events: list[SecurityEvent] = []
    labels: dict[str, Label] = {}
    for rec in dataset.records:
        normalizer = get_normalizer(rec.source)
        data = canonical_json(rec.raw)
        evidence = EvidenceRef(reference=f"sim://{rec.source.value}", sha256=sha256_hex(data))
        try:
            event = normalizer.normalize(rec.raw, evidence)
        except (SkipRecord, NormalizationError):
            continue
        events.append(event)
        labels[event.event_id] = rec.label
    events.sort(key=lambda e: e.timestamp)
    return events, labels
