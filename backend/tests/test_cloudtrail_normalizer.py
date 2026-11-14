from datetime import datetime, timezone

import pytest

from app.processing.normalizers import NormalizationError
from app.processing.normalizers.cloudtrail import CloudTrailNormalizer
from app.schemas.event import Layer, Outcome
from tests.conftest import DUMMY_EVIDENCE

normalizer = CloudTrailNormalizer()


def norm(record):
    return normalizer.normalize(record, DUMMY_EVIDENCE)


def test_successful_console_login(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["05"])
    assert event.event_type == "CONSOLE_LOGIN"
    assert event.layer is Layer.IDENTITY
    assert event.outcome is Outcome.SUCCESS
    assert event.actor_id == "bob"
    assert event.actor_type == "IAMUser"
    assert event.source_ip == "203.0.113.50"
    assert event.timestamp == datetime(2026, 11, 4, 10, 30, tzinfo=timezone.utc)
    assert event.attributes["mfa_used"] is False
    assert event.action == "signin:ConsoleLogin"


def test_failed_console_login_raises_severity(cloudtrail_by_id):
    ok, failed = norm(cloudtrail_by_id["05"]), norm(cloudtrail_by_id["04"])
    assert failed.outcome is Outcome.FAILURE
    assert failed.base_severity > ok.base_severity
    assert failed.attributes["error_message"] == "Failed authentication"


def test_create_access_key_links_new_key_to_later_activity(cloudtrail_by_id):
    created = norm(cloudtrail_by_id["07"])
    escalation = norm(cloudtrail_by_id["08"])
    assert created.event_type == "ACCESS_KEY_CREATED"
    assert created.session_id == "ASIAEXAMPLEBOBCON01"  # temporary console credentials
    new_key = created.attributes["created_access_key_id"]
    # The correlation engine can follow the attacker from the console session to the new key.
    assert escalation.access_key_id == new_key
    assert escalation.session_id is None  # AKIA* is a long-lived key, not a session


def test_policy_attachment_targets_the_user(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["08"])
    assert event.event_type == "POLICY_ATTACHED"
    assert (event.resource_id, event.resource_type) == ("bob", "iam_user")
    assert event.attributes["policy_arn"].endswith("AdministratorAccess")
    assert event.base_severity == pytest.approx(0.7)


def test_security_group_open_to_internet(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["09"])
    assert event.layer is Layer.NETWORK
    assert (event.resource_id, event.resource_type) == ("sg-0a1b2c3d4e5f60001", "security_group")
    assert event.attributes["open_to_internet"] is True
    assert event.attributes["cidrs"] == ["0.0.0.0/0"]
    assert event.attributes["ports"] == ["22"]
    assert event.base_severity >= 0.8


def test_s3_download_carries_bytes_and_object(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["11"])
    assert event.event_type == "OBJECT_DOWNLOADED"
    assert event.layer is Layer.STORAGE
    assert event.resource_id == "arn:aws:s3:::customer-data/exports/customers-2026-11.csv"
    assert event.resource_type == "s3_object"
    assert event.bytes_transferred == 52_428_800
    assert event.attributes["event_category"] == "Data"


def test_stop_logging_is_management_and_critical(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["12"])
    assert event.event_type == "AUDIT_LOGGING_STOPPED"
    assert event.layer is Layer.MANAGEMENT
    assert event.resource_type == "cloudtrail_trail"
    assert event.base_severity >= 0.9


def test_assumed_role_actor_and_non_ip_source(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["14"])
    assert event.actor_id == "app-server-role/i-0a1b2c3d4e5f60001"
    assert event.actor_type == "AssumedRole"
    assert event.source_ip is None
    assert event.attributes["source_address"] == "AWS Internal"
    assert event.resource_id.startswith("arn:aws:kms:")


def test_unknown_event_uses_service_fallback(cloudtrail_by_id):
    event = norm(cloudtrail_by_id["13"])  # DescribeVpcs has no explicit rule
    assert event.event_type == "API_CALL_READ"
    assert event.layer is Layer.COMPUTE


def test_event_id_is_deterministic(cloudtrail_by_id):
    assert norm(cloudtrail_by_id["07"]).event_id == norm(cloudtrail_by_id["07"]).event_id


def test_access_denied_is_failure():
    record = {
        "eventID": "x-1", "eventTime": "2026-11-04T11:00:00Z", "eventName": "ListUsers",
        "eventSource": "iam.amazonaws.com", "errorCode": "AccessDenied",
        "userIdentity": {"type": "IAMUser", "userName": "bob"},
    }
    event = norm(record)
    assert event.outcome is Outcome.FAILURE
    assert event.attributes["access_denied"] is True
    assert event.event_type == "IAM_ENUMERATION"


@pytest.mark.parametrize(
    "record",
    [
        {"eventTime": "2026-11-04T11:00:00Z", "eventName": "ListUsers"},
        {"eventID": "x-2", "eventTime": "2026-11-04T11:00:00Z"},
        {"eventID": "x-3", "eventName": "ListUsers", "eventTime": "not-a-time"},
    ],
)
def test_malformed_records_raise(record):
    with pytest.raises(NormalizationError):
        norm(record)
