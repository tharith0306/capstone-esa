"""End-to-end: train a small bundle, seed a simulated organisation, analyse, investigate, respond."""

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.ml.training import TrainingConfig, train
from tests.conftest import TEST_ADMIN_PASSWORD, login


@pytest.fixture(scope="session")
def model_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("models")
    train(TrainingConfig(seed=7, days=12, attacks_per_day=8)).save(directory)
    return directory


@pytest.fixture(scope="session")
def seeded(tmp_path_factory, model_dir):
    root = tmp_path_factory.mktemp("pipeline")
    settings = Settings(database_url=f"sqlite:///{root / 'db.sqlite'}", evidence_dir=str(root / "evidence"),
                        reports_dir=str(root / "reports"), model_dir=str(model_dir), log_level="WARNING",
                        jwt_secret="pipeline-test-secret-pipeline-tests-32b", bootstrap_admin_password=TEST_ADMIN_PASSWORD)
    with TestClient(create_app(settings)) as client:
        login(client)
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
    criteria = inc["flag_criteria"]
    assert 0 < criteria["attack_probability_threshold"] < 1
    assert [lvl["level"] for lvl in criteria["risk_levels"]][0] == "CRITICAL"
    assert all(d["kind"] == "rule" or d["attack_probability"] >= criteria["attack_probability_threshold"]
               or d["anomaly_score"] >= criteria["anomaly_threshold"] for d in inc["detections"])
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
    assert client.post(f"/api/response/actions/{aid}/execute").status_code == 409
    approved = client.post(f"/api/response/actions/{aid}/approve", json={"note": "ok"}).json()
    assert approved["status"] == "approved" and approved["decided_by"] == "admin"
    executed = client.post(f"/api/response/actions/{aid}/execute").json()
    assert executed["status"] == "executed" and executed["execution"]["mode"] == "dry_run"
    if executed["reversible"]:
        assert client.post(f"/api/response/actions/{aid}/rollback").json()["status"] == "rolled_back"
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


def _top_ml_incident(client):
    for inc in client.get("/api/incidents", params={"limit": 20}).json()["items"]:
        detail = client.get(f"/api/incidents/{inc['incident_id']}").json()
        if any(d["kind"] == "model" for d in detail["detections"]):
            return inc["incident_id"]
    raise AssertionError("no ML incident")


def test_forensics_endpoints(seeded):
    client, _, _ = seeded
    inc_id = _top_ml_incident(client)
    assert client.get(f"/api/forensics/{inc_id}/graph").json()["nodes"]
    assert client.get(f"/api/forensics/{inc_id}/timeline").json()
    assert client.get(f"/api/forensics/{inc_id}/evidence").json()["manifest_sha256"]

    lime = client.get(f"/api/forensics/{inc_id}/lime").json()
    assert lime["features"] and "local_r2" in lime
    cf = client.get(f"/api/forensics/{inc_id}/counterfactual").json()
    assert cf["method"].startswith("DiCE") and "counterfactuals" in cf

    pdf = client.get(f"/api/forensics/{inc_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-" and len(pdf.content) > 3000

    cypher = client.get(f"/api/forensics/{inc_id}/graph.cypher").text
    assert cypher.count("MERGE") > 3 and inc_id in cypher
    assert client.post(f"/api/forensics/{inc_id}/neo4j").status_code == 400  # not configured


def test_cloud_endpoints(seeded):
    client, _, _ = seeded
    resources = client.get("/api/cloud/resources").json()
    assert {"ec2_instance", "s3_bucket", "iam_user"} <= {r["resource_type"] for r in resources}
    health = client.get("/api/cloud/health").json()
    assert {s["source"] for s in health["sources"]} >= {"cloudtrail", "vpc_flow", "cloudwatch"}
    assert client.get("/api/cloud/accounts").json()[0]["account_id"] == "111122223333"
