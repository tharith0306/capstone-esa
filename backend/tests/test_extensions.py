"""RL simulator, public-dataset loader, sequence models, migrations."""

import numpy as np
import pandas as pd
import pytest
from sqlalchemy import create_engine, inspect, text

from app.response import rl


def test_rl_learns_to_contain_attacks_and_spare_benign():
    attack = rl.IncidentCase("CRITICAL", "data_exfiltration", True, "data_exfiltration")
    benign = rl.IncidentCase("MEDIUM", "privilege_escalation", False, None)
    q = rl.QPolicy(seed=1).train([attack] * 20 + [benign] * 20, episodes=50)
    assert q.act(attack.state) in ("CONTAIN_IDENTITY", "FULL_CONTAINMENT")
    assert q.act(benign.state) in ("MONITOR", "NOTIFY")
    assert q.act(("LOW", "never_seen")) == "NOTIFY"
    ev = rl.evaluate([attack, benign], lambda c: q.act(c.state))
    assert ev["attack_containment_rate"] == 1.0 and ev["benign_disruption_rate"] == 0.0


def test_policy_engine_mapping():
    case = rl.IncidentCase("CRITICAL", "x", True, None, ["DEACTIVATE_ACCESS_KEY", "STOP_INSTANCES"])
    assert rl.policy_engine_action(case) == "FULL_CONTAINMENT"
    assert rl.policy_engine_action(rl.IncidentCase("MEDIUM", "x", False, None, ["NOTIFY_ANALYST"])) == "NOTIFY"


def test_public_dataset_pipeline_on_unsw_format(tmp_path):
    from app.experiments.public_datasets import run_public_experiment

    rng = np.random.default_rng(0)
    n = 600
    label = (rng.random(n) < 0.3).astype(int)
    frame = pd.DataFrame({
        "id": range(n), "dur": rng.exponential(1, n) + label * 3, "proto": rng.choice(["tcp", "udp"], n),
        "sbytes": rng.integers(100, 5000, n) + label * 20000, "dbytes": rng.integers(100, 5000, n),
        "attack_cat": np.where(label == 1, "Exploits", "Normal"), "label": label,
    })
    frame.iloc[:400].to_csv(tmp_path / "UNSW_NB15_training-set.csv", index=False)
    frame.iloc[400:].to_csv(tmp_path / "UNSW_NB15_testing-set.csv", index=False)
    report = run_public_experiment("unsw", tmp_path, tmp_path / "out")
    assert {m["model"] for m in report["models"]} >= {"XGBoost", "Random Forest"}
    assert report["models"][-1]["roc_auc"] > 0.9
    assert (tmp_path / "out" / "public_unsw.md").exists()


def test_sequence_tagger_trains_and_decodes():
    from app.ml import sequence
    if not sequence.available():
        pytest.skip("PyTorch not installed")
    from app.ml.training import build_labelled_data

    data = build_labelled_data(5, 4, 4.0, 0.0, 15)
    model, info = sequence.train_tagger(data.rows, data.labels, arch="transformer", epochs=1)
    pred = sequence.decode(model, data.rows[:300])
    assert len(pred) == 300 and info["parameters"] > 0


def test_migrations_upgrade_and_legacy_stamp(tmp_path):
    from app.database.models import Base
    from app.database.session import init_db

    fresh = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    init_db(fresh)
    tables = set(inspect(fresh).get_table_names())
    assert {"users", "incidents", "cloud_resources", "alembic_version"} <= tables

    legacy = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    Base.metadata.tables["security_events"].metadata.create_all(legacy, tables=[Base.metadata.tables["raw_events"]])
    init_db(legacy)  # tables exist without alembic_version: create missing ones and stamp
    with legacy.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0001"
    assert "users" in inspect(legacy).get_table_names()
