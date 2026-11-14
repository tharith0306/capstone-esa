from datetime import datetime, timezone

import pytest

from app.processing.normalizers import NormalizationError, SkipRecord
from app.processing.normalizers.guardduty import GuardDutyNormalizer
from app.processing.normalizers.vpc_flow import VpcFlowNormalizer
from app.schemas.event import EventSource, Layer, Outcome
from app.services.record_files import load_records
from tests.conftest import DUMMY_EVIDENCE, GUARDDUTY_SAMPLE, VPC_SAMPLE

vpc = VpcFlowNormalizer()
guardduty = GuardDutyNormalizer()


@pytest.fixture
def flow_lines():
    return load_records(VPC_SAMPLE, EventSource.VPC_FLOW)


def test_flow_file_loader_drops_header(flow_lines):
    assert len(flow_lines) == 5
    assert not flow_lines[0]["message"].startswith("version")


def test_accepted_flow(flow_lines):
    event = vpc.normalize(flow_lines[3], DUMMY_EVIDENCE)
    assert event.event_type == "NETWORK_FLOW_ACCEPTED"
    assert event.layer is Layer.NETWORK
    assert event.outcome is Outcome.SUCCESS
    assert (event.source_ip, event.destination_ip) == ("10.0.1.25", "203.0.113.50")
    assert (event.source_port, event.destination_port, event.protocol) == (49210, 443, "TCP")
    assert event.bytes_transferred == 52_428_800
    assert event.resource_id == "eni-0a1b2c3d4e5f60001"
    assert event.timestamp == datetime(2026, 11, 4, 10, 40, tzinfo=timezone.utc)
    assert event.attributes["duration_seconds"] == 60


def test_rejected_flow(flow_lines):
    event = vpc.normalize(flow_lines[1], DUMMY_EVIDENCE)
    assert event.event_type == "NETWORK_FLOW_REJECTED"
    assert event.outcome is Outcome.FAILURE
    assert event.destination_port == 3389


def test_nodata_flow_is_skipped(flow_lines):
    with pytest.raises(SkipRecord):
        vpc.normalize(flow_lines[4], DUMMY_EVIDENCE)


def test_malformed_flow():
    with pytest.raises(NormalizationError):
        vpc.normalize({"message": "2 111122223333 eni-1 too short"}, DUMMY_EVIDENCE)
    with pytest.raises(NormalizationError):
        vpc.source_event_id({})


def test_guardduty_access_key_finding():
    finding = load_records(GUARDDUTY_SAMPLE, EventSource.GUARDDUTY)[0]
    event = guardduty.normalize(finding, DUMMY_EVIDENCE)
    assert event.event_type == "GUARDDUTY_FINDING"
    assert event.event_name == "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"
    assert event.layer is Layer.IDENTITY
    assert event.actor_id == "bob"
    assert event.access_key_id == "ASIAEXAMPLEBOBCON01"
    assert event.source_ip == "203.0.113.50"
    assert event.base_severity == pytest.approx(0.5)
    assert event.timestamp == datetime(2026, 11, 4, 10, 30, tzinfo=timezone.utc)


def test_guardduty_outbound_connection_sets_destination():
    finding = {
        "Id": "f-2", "Type": "Backdoor:EC2/C&CActivity.B", "Severity": 8, "CreatedAt": "2026-11-04T10:41:00Z",
        "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-0a1b2c3d4e5f60001"}},
        "Service": {"Action": {"ActionType": "NETWORK_CONNECTION", "NetworkConnectionAction": {
            "ConnectionDirection": "OUTBOUND", "RemoteIpDetails": {"IpAddressV4": "203.0.113.50"}}}},
    }
    event = guardduty.normalize(finding, DUMMY_EVIDENCE)
    assert event.layer is Layer.NETWORK
    assert event.destination_ip == "203.0.113.50"
    assert event.source_ip is None
    assert event.resource_id == "i-0a1b2c3d4e5f60001"
