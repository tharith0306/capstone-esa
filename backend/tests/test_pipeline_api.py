"""End-to-end: train a small bundle, seed a simulated organisation, analyse, investigate, respond."""

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.ml.training import TrainingConfig, train


@pytest.fixture(scope="session")
def model_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("models")
    train(TrainingConfig(seed=7, days=12, attacks_per_day=8)).save(directory)
    return directory


@pytest.fixture(scope="session")
def seeded(tmp_path_factory, model_dir):
    root = tmp_path_factory.mktemp("pipeline")
    settings = Settings(database_url=f"sqlite:///{root / 'db.sqlite'}", evidence_dir=str(root / "evidence"),
                        reports_dir=str(root / "reports"), model_dir=str(model_dir), log_level="WARNING")
    with TestClient(create_app(settings)) as client:
        sim = client.post("/api/simulation/run", json={"seed": 42, "days": 4, "attacks_per_day": 3})
        assert sim.status_code == 200, sim.text
        run = client.post("/api/analysis/run", json={})
        assert run.status_code == 200 and run.json()["status"] == "completed", run.text
        yield client, sim.json(), run.json()


def test_analysis_produces_incidents(seeded):
    client, sim, run = seeded
    assert run["n_detections"] > 0 and run["n_incidents"] > 0
    overview = client.get("/api/dashboard/overview").json()
    assert overview["incidents"] == run["n_incidents"]
    assert 0 <= overview["alert_reduction"] < 1
    top = client.get("/api/incidents", params={"limit": 5}).json()["items"]
    assert top == sorted(top, key=lambda i: -i["risk_score"])


def test_incident_detail_has_all_layers(seeded):
    client, _, _ = seeded
    inc_id = client.get("/api/incidents", params={"limit": 1}).json()["items"][0]["incident_id"]
    inc = client.get(f"/api/incidents/{inc_id}").json()
    assert inc["risk"]["formula"].startswith("R = 100")
    assert len(inc["risk"]["components"]) == 6
    assert inc["graph"]["nodes"] and inc["timeline"]
    assert inc["detections"]
    assert inc["evidence_manifest"]["manifest_sha256"]
    assert {s["stage"] for s in inc["sequence"]} - {"NORMAL"}  # HMM found attack stages
    if inc["explanation"]["shap"]:
        assert inc["explanation"]["shap"]["features"]


def test_report_verifies_evidence(seeded):
    client, _, _ = seeded
    inc_id = client.get("/api/incidents", params={"limit": 1}).json()["items"][0]["incident_id"]
    report = client.get(f"/api/incidents/{inc_id}/report").json()
    assert report["evidence_summary"]["all_verified"] is True


def test_response_workflow_dry_run(seeded):
    client, _, _ = seeded
    actions = [a for a in client.get("/api/response/actions").json() if a["automatable"]]
    assert actions, "a HIGH/CRITICAL simulated attack should yield automatable actions"
    aid = actions[0]["action_id"]
    assert client.post(f"/api/response/actions/{aid}/execute", json={"analyst": "t"}).status_code == 409
    assert client.post(f"/api/response/actions/{aid}/approve", json={"analyst": "alice", "note": "ok"}).json()["status"] == "approved"
    executed = client.post(f"/api/response/actions/{aid}/execute", json={"analyst": "alice"}).json()
    assert executed["status"] == "executed" and executed["execution"]["mode"] == "dry_run"
    if executed["reversible"]:
        assert client.post(f"/api/response/actions/{aid}/rollback", json={"analyst": "alice"}).json()["status"] == "rolled_back"
    audit = client.get("/api/response/audit").json()
    assert {"approve", "execute"} <= {a["action"] for a in audit}


def test_reanalysis_keeps_analyst_decisions(seeded):
    client, _, _ = seeded
    decided = [a for a in client.get("/api/response/actions").json() if a["status"] != "proposed"]
    client.post("/api/analysis/run", json={})
    after = {a["action_id"]: a["status"] for a in client.get("/api/response/actions").json()}
    for a in decided:
        assert after.get(a["action_id"]) == a["status"]


def test_dashboard_endpoints(seeded):
    client, _, _ = seeded
    assert client.get("/api/dashboard/threat-trends").json()
    assert sum(l["count"] for l in client.get("/api/dashboard/risk-distribution").json()["levels"]) > 0
    assert client.get("/api/dashboard/top-entities").json()["actors"]
    assert client.get("/api/models").json()["version"]
    assert client.get("/api/detections", params={"limit": 3}).json()["total"] > 0
