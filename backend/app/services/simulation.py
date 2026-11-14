"""Seed the database with a simulated organisation under attack (demo / evaluation)."""

import json
from datetime import datetime
from pathlib import Path

from app.schemas.event import EventSource
from app.services.ingestion import IngestionService
from app.simulation.generator import generate_dataset


def seed_demo(ingestion: IngestionService, reports_dir: str, seed: int = 2026, days: int = 7,
              attacks_per_day: float = 1.5, start: datetime | None = None, session_factory=None) -> dict:
    dataset = generate_dataset(seed=seed, days=days, attacks_per_day=attacks_per_day, warmup_days=2,
                               stealthy_fraction=0.15, start=start)
    if session_factory is not None:
        from app.services.inventory import save_inventory

        save_inventory(session_factory, dataset.inventory, "simulation")
    results = {}
    for source, records in dataset.by_source().items():
        if records:
            results[source.value] = ingestion.ingest(EventSource(source), records).model_dump(mode="json")
    truth = [
        {"scenario_id": s.scenario_id, "kind": s.kind, "victim": s.victim, "attacker_ip": s.attacker_ip,
         "start": s.start.isoformat(), "end": s.end.isoformat(), "stealthy": s.stealthy, "stages": s.stages}
        for s in dataset.scenarios
    ]
    path = Path(reports_dir)
    path.mkdir(parents=True, exist_ok=True)
    (path / "demo_ground_truth.json").write_text(json.dumps(truth, indent=2))
    return {"seed": seed, "days": days, "start": dataset.start.isoformat(), "end": dataset.end.isoformat(),
            "ingest": results, "scenarios": truth}
