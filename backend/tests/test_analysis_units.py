from datetime import datetime, timedelta, timezone

import pytest

from app.analysis.alerts import Alert
from app.analysis.correlation import CorrelationConfig, correlate
from app.analysis.risk import RiskInputs, compute_risk, risk_level
from app.analysis.sensitivity import resource_sensitivity
from app.ml.features import FEATURES, build_windows, is_internal, to_rows, ua_family
from app.ml.hmm import StageHMM, sequence_severity
from app.processing.normalizers.cloudtrail import CloudTrailNormalizer
from app.response.executor import ExecutionError, ResponseExecutor
from app.core.config import Settings
from app.simulation.generator import generate_dataset, normalize_dataset
from tests.conftest import DUMMY_EVIDENCE

T0 = datetime(2026, 11, 4, 10, 0, tzinfo=timezone.utc)


def alert(i, minutes, actors=(), keys=(), ips=(), resources=(), cls="credential_compromise", entity=None):
    start = T0 + timedelta(minutes=minutes)
    return Alert(alert_id=f"a{i}", kind="model", entity=entity or f"actor:{(actors or ('x',))[0]}",
                 start=start, end=start + timedelta(minutes=5), event_ids=[f"e{i}"], actors=set(actors),
                 keys=set(keys), ips=set(ips), resources=set(resources), predicted_class=cls,
                 class_probability=0.9, attack_probability=0.9, anomaly_score=0.5, score=0.9)


# ---------- simulation ----------
def test_simulation_is_deterministic_and_normalizes_cleanly():
    a = generate_dataset(seed=3, days=4, attacks_per_day=2, warmup_days=1)
    b = generate_dataset(seed=3, days=4, attacks_per_day=2, warmup_days=1)
    assert [r.raw for r in a.records[:50]] == [r.raw for r in b.records[:50]]
    events, labels = normalize_dataset(a)
    skipped = len(a.records) - len(events)
    assert skipped == 0
    assert any(l.attack_class != "normal" for l in labels.values())
    assert len(a.scenarios) == 6


# ---------- features ----------
def test_identifiers_are_not_model_features():
    for banned in ("ip", "user", "actor", "key_id", "arn"):
        assert not any(f == banned or f.endswith(f"_{banned}") for f in FEATURES)


def test_internal_ip_check_handles_documentation_ranges():
    assert is_internal("10.0.1.25")
    # Python's ipaddress marks RFC 5737 ranges "private"; CloudShield must treat them as external.
    assert not is_internal("203.0.113.50")
    assert not is_internal("198.51.100.10")


def test_user_agent_family_distinguishes_os():
    assert ua_family("aws-cli/2.15 Python/3.11 Darwin/23") != ua_family("aws-cli/2.13 Python/3.11 Linux/6.5.0-kali3")


def test_new_ip_is_relative_to_entity_history(cloudtrail_records):
    events = [CloudTrailNormalizer().normalize(r, DUMMY_EVIDENCE) for r in cloudtrail_records]
    windows = build_windows(to_rows(events), window_minutes=15)
    bob = windows[windows["entity"] == "actor:bob"].iloc[0]
    assert bob["new_ip_ratio"] == 1.0  # bob has no history at all
    assert bob["failed_login_count"] == 1


# ---------- correlation ----------
def test_same_identity_close_in_time_is_merged():
    groups = correlate([alert(1, 0, actors=["bob"]), alert(2, 10, actors=["bob"], cls="privilege_escalation")])
    assert len(groups) == 1 and groups[0].correlation_score > 0.4


def test_time_alone_never_merges():
    groups = correlate([alert(1, 0, actors=["bob"]), alert(2, 1, actors=["carol"])])
    assert len(groups) == 2


def test_created_key_links_backdoor_identity():
    a = alert(1, 0, actors=["bob"], keys=["AKIANEWKEY"])  # bob created AKIANEWKEY
    b = alert(2, 20, actors=["svc-backup"], keys=["AKIANEWKEY"], cls="privilege_escalation")
    assert len(correlate([a, b])) == 1


def test_shared_office_ip_is_ignored_by_commonness_filter():
    office = "198.51.100.10"
    alerts = [alert(i, i, actors=[f"user{i}"], ips=[office]) for i in range(5)]
    assert len(correlate(alerts)) == 5
    assert len(correlate(alerts, CorrelationConfig(common_entity_limit=100))) == 1


# ---------- risk ----------
def test_risk_formula_matches_design_example():
    risk = compute_risk(RiskInputs(0.90, 0.95, 0.90, 0.85, 0.80, 0.90))
    assert risk["score"] == pytest.approx(89.5)
    assert risk["level"] == "CRITICAL"
    assert sum(c["contribution"] for c in risk["components"]) == pytest.approx(89.5, abs=0.05)


@pytest.mark.parametrize("score,level", [(0, "MINIMAL"), (20.9, "MINIMAL"), (21, "LOW"), (41, "MEDIUM"),
                                         (61, "HIGH"), (81, "CRITICAL")])
def test_risk_bands(score, level):
    assert risk_level(score) == level


def test_resource_sensitivity():
    assert resource_sensitivity("arn:aws:s3:::customer-data") == 1.0
    assert resource_sensitivity("arn:aws:s3:::app-assets", "s3_bucket") == 0.3
    assert resource_sensitivity(None) == 0.0


# ---------- HMM ----------
def test_hmm_uses_context():
    normal = (["LOGIN_SUCCESS", "ROUTINE_READ", "ROUTINE_READ"], ["NORMAL"] * 3)
    attack = (["LOGIN_SUCCESS", "DISCOVERY", "PRIVILEGE_CHANGE"], ["INITIAL_ACCESS", "DISCOVERY", "PRIVILEGE_ESCALATION"])
    model = StageHMM.fit_supervised([normal] * 20 + [attack] * 10)
    stages, conf = model.decode(["LOGIN_SUCCESS", "DISCOVERY", "PRIVILEGE_CHANGE"])
    assert stages[-1] == "PRIVILEGE_ESCALATION"
    assert model.decode(["LOGIN_SUCCESS", "ROUTINE_READ"])[0] == ["NORMAL", "NORMAL"]
    assert all(0 <= c <= 1 for c in conf)


def test_sequence_severity():
    assert sequence_severity(["NORMAL"]) == 0.0
    assert sequence_severity(["INITIAL_ACCESS", "PRIVILEGE_ESCALATION", "EXFILTRATION"]) > sequence_severity(["DISCOVERY"])


# ---------- response executor ----------
def test_executor_dry_run_never_calls_aws():
    def boom(*_):
        raise AssertionError("AWS must not be called in dry-run")
    ex = ResponseExecutor(Settings(response_mode="dry_run"), client_factory=boom)
    result = ex.execute("DEACTIVATE_ACCESS_KEY", {"user": "bob", "access_key_id": "AKIAEXAMPLE"})
    assert result["executed"] is False
    assert result["params"] == {"UserName": "bob", "AccessKeyId": "AKIAEXAMPLE", "Status": "Inactive"}


def test_executor_live_with_stub_and_verification():
    calls = []

    class StubIAM:
        def update_access_key(self, **kw):
            calls.append(kw)
            return {"ResponseMetadata": {}}

        def list_access_keys(self, UserName):
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE", "Status": "Inactive"}]}

    ex = ResponseExecutor(Settings(response_mode="live"), client_factory=lambda svc, region: StubIAM())
    result = ex.execute("DEACTIVATE_ACCESS_KEY", {"user": "bob", "access_key_id": "AKIAEXAMPLE"})
    assert result["executed"] and result["verified"] is True
    assert calls == [{"UserName": "bob", "AccessKeyId": "AKIAEXAMPLE", "Status": "Inactive"}]


def test_manual_actions_cannot_be_executed():
    with pytest.raises(ExecutionError):
        ResponseExecutor(Settings()).plan("REVIEW_DATA_ACCESS", {})
