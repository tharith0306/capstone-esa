from pathlib import Path

import pytest

from app.processing.normalizers import NormalizationError, get_normalizer
from app.schemas.event import EventSource, Layer, Outcome
from app.services.record_files import load_records
from tests.conftest import DUMMY_EVIDENCE, SAMPLE_DIR


def normalize_file(name: str, source: EventSource):
    normalizer = get_normalizer(source)
    return [normalizer.normalize(r, DUMMY_EVIDENCE) for r in load_records(Path(SAMPLE_DIR) / name, source)]


def test_azure_activity_log():
    events = normalize_file("azure_activity.json", EventSource.AZURE_ACTIVITY)
    role, keys, diag, read = events
    assert role.cloud_provider == "azure"
    assert role.event_type == "POLICY_ATTACHED" and role.layer is Layer.IDENTITY
    assert role.actor_id == "bob@contoso.example" and role.source_ip == "203.0.113.50"
    assert role.account_id == "00000000-0000-0000-0000-000000000001"
    assert keys.event_type == "STORAGE_KEYS_LISTED" and keys.layer is Layer.STORAGE
    assert diag.event_type == "AUDIT_LOGGING_STOPPED" and diag.base_severity >= 0.9
    # REST-API schema variant: nested operationName / status, caller field
    assert read.event_type == "API_CALL_READ" and read.outcome is Outcome.FAILURE and read.actor_id == "carol@contoso.example"


def test_gcp_audit_log():
    key, firewall, sink = normalize_file("gcp_audit.json", EventSource.GCP_AUDIT)
    assert key.cloud_provider == "gcp" and key.event_type == "ACCESS_KEY_CREATED"
    assert key.actor_id == "bob@example.com" and key.account_id == "example-prod"
    assert firewall.event_type == "SECURITY_GROUP_INGRESS_OPENED" and firewall.attributes["open_to_internet"]
    assert firewall.base_severity >= 0.8
    assert sink.event_type == "AUDIT_LOGGING_STOPPED" and sink.outcome is Outcome.FAILURE
    assert sink.attributes["access_denied"] is True


def test_cross_cloud_events_share_one_schema():
    events = normalize_file("azure_activity.json", EventSource.AZURE_ACTIVITY) + normalize_file(
        "gcp_audit.json", EventSource.GCP_AUDIT)
    assert {e.source_ip for e in events if e.actor_id and e.actor_id.startswith("bob")} == {"203.0.113.50"}


def test_cloudwatch_metric():
    normalizer = get_normalizer(EventSource.CLOUDWATCH)
    raw = {"instance_id": "i-0abc", "metric": "CPUUtilization", "value": 97.5, "unit": "Percent",
           "timestamp": "2026-11-04T10:40:00Z", "region": "ap-south-1", "private_ip": "10.9.0.12"}
    event = normalizer.normalize(raw, DUMMY_EVIDENCE)
    assert event.event_type == "METRIC_CPU_HIGH" and event.layer is Layer.COMPUTE
    assert normalizer.normalize({**raw, "value": 12}, DUMMY_EVIDENCE).event_type == "METRIC_SAMPLE"
    with pytest.raises(NormalizationError):
        normalizer.normalize({**raw, "value": "n/a"}, DUMMY_EVIDENCE)


def test_inventory_links_flows_to_instances():
    from app.analysis.inventory import Inventory
    from app.ml.features import build_windows, to_rows

    flow = get_normalizer(EventSource.VPC_FLOW).normalize(
        {"message": "2 111122223333 eni-0mine 10.9.0.12 203.0.113.250 50000 3333 6 100 400000 1793788800 1793792400 ACCEPT OK"},
        DUMMY_EVIDENCE)
    inv = Inventory.from_records([{"resource_id": "i-0miner", "resource_type": "ec2_instance",
                                   "attributes": {"enis": ["eni-0mine"], "private_ips": ["10.9.0.12"]}}])
    windows = build_windows(to_rows([flow], inv))
    assert "i-0miner" in windows.iloc[0]["resources"]
    assert "i-0miner" not in build_windows(to_rows([flow])).iloc[0]["resources"]
