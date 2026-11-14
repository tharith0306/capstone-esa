from app.processing.hashing import canonical_json
from app.schemas.event import EventSource
from app.services.record_files import load_records
from tests.conftest import GUARDDUTY_SAMPLE, VPC_SAMPLE


def ingest(client, source, records):
    response = client.post("/api/events/ingest", json={"source": source, "records": records})
    assert response.status_code == 200, response.text
    return response.json()


def test_health(client):
    assert client.get("/api/health").json()["database"] == "ok"


def test_ingest_is_idempotent(client, cloudtrail_records):
    first = ingest(client, "cloudtrail", cloudtrail_records)
    assert (first["received"], first["stored"], first["failed"]) == (14, 14, 0)
    assert first["latest_event_time"].startswith("2026-11-04T10:45:00")

    second = ingest(client, "cloudtrail", cloudtrail_records)
    assert (second["stored"], second["duplicates"]) == (0, 14)


def test_duplicates_within_one_batch(client, cloudtrail_records):
    result = ingest(client, "cloudtrail", [cloudtrail_records[0], cloudtrail_records[0]])
    assert (result["stored"], result["duplicates"]) == (1, 1)


def test_bad_records_are_reported_not_fatal(client, cloudtrail_records):
    bad = {"eventID": "broken-1", "eventName": "ListUsers", "eventTime": "garbage"}
    result = ingest(client, "cloudtrail", [cloudtrail_records[0], bad, {"no": "id"}])
    assert (result["stored"], result["failed"]) == (1, 2)
    assert len(result["errors"]) == 2


def test_cross_source_ingest_and_filters(client, cloudtrail_records):
    ingest(client, "cloudtrail", cloudtrail_records)
    vpc = ingest(client, "vpc_flow", load_records(VPC_SAMPLE, EventSource.VPC_FLOW))
    assert (vpc["stored"], vpc["skipped"]) == (4, 1)
    ingest(client, "guardduty", load_records(GUARDDUTY_SAMPLE, EventSource.GUARDDUTY))

    # Everything touching the attacker IP, across identity, network and storage layers.
    page = client.get("/api/events", params={"source_ip": "203.0.113.50", "limit": 50}).json()
    layers = {item["layer"] for item in page["items"]}
    assert {"identity", "network", "storage", "management"} <= layers
    timestamps = [item["timestamp"] for item in page["items"]]
    assert timestamps == sorted(timestamps, reverse=True)

    bob = client.get("/api/events", params={"actor_id": "bob", "limit": 50}).json()
    assert bob["total"] == 11  # 10 CloudTrail + 1 GuardDuty

    high = client.get("/api/events", params={"min_severity": 0.9}).json()
    assert {i["event_type"] for i in high["items"]} == {"AUDIT_LOGGING_STOPPED"}

    window = client.get("/api/events", params={
        "start": "2026-11-04T10:30:00Z", "end": "2026-11-04T10:35:00Z", "source": "cloudtrail"}).json()
    assert window["total"] == 4

    paged = client.get("/api/events", params={"limit": 5, "offset": 5}).json()
    assert paged["total"] == 19 and len(paged["items"]) == 5


def test_statistics(client, cloudtrail_records):
    ingest(client, "cloudtrail", cloudtrail_records)
    stats = client.get("/api/events/statistics").json()
    assert stats["total_events"] == 14
    by_layer = {b["key"]: b["count"] for b in stats["by_layer"]}
    assert by_layer["identity"] == 6
    assert stats["first_event_at"].startswith("2026-11-04T09:15:02")
    assert stats["top_event_types"][0] == {"key": "CONSOLE_LOGIN", "count": 3}


def test_get_event_and_verified_raw(client, cloudtrail_by_id, settings):
    ingest(client, "cloudtrail", [cloudtrail_by_id["12"]])
    event_id = client.get("/api/events").json()["items"][0]["event_id"]

    event = client.get(f"/api/events/{event_id}").json()
    assert event["event_type"] == "AUDIT_LOGGING_STOPPED"

    raw = client.get(f"/api/events/{event_id}/raw").json()
    assert raw["verified"] is True
    assert raw["raw"] == cloudtrail_by_id["12"]

    # Tamper with the stored evidence: the API must report it.
    path = f"{settings.evidence_dir}/{raw['reference'].removeprefix('local://')}"
    tampered = dict(cloudtrail_by_id["12"], eventName="DescribeTrails")
    with open(path, "wb") as fh:
        fh.write(canonical_json(tampered))
    assert client.get(f"/api/events/{event_id}/raw").json()["verified"] is False


def test_unknown_event_404(client):
    assert client.get("/api/events/evt_missing").status_code == 404


def test_batch_limit(client, settings):
    settings.max_ingest_batch = 1
    response = client.post("/api/events/ingest", json={"source": "cloudtrail", "records": [{}, {}]})
    assert response.status_code == 413


def test_empty_batch_rejected(client):
    assert client.post("/api/events/ingest", json={"source": "cloudtrail", "records": []}).status_code == 422
    assert client.post("/api/events/ingest", json={"source": "nope", "records": [{}]}).status_code == 422
