from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.evidence.store import LocalEvidenceStore
from app.main import create_app
from app.schemas.event import EventSource, EvidenceRef
from app.services.record_files import load_records

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
CLOUDTRAIL_SAMPLE = SAMPLE_DIR / "cloudtrail_credential_compromise.json"
VPC_SAMPLE = SAMPLE_DIR / "vpc_flow_sample.log"
GUARDDUTY_SAMPLE = SAMPLE_DIR / "guardduty_findings.json"

DUMMY_EVIDENCE = EvidenceRef(reference="local://test/aa/test.json", sha256="a" * 64)
TEST_ADMIN_PASSWORD = "test-admin-password"


def login(client: TestClient, username: str = "admin", password: str = TEST_ADMIN_PASSWORD) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"


@pytest.fixture
def cloudtrail_records() -> list[dict]:
    return load_records(CLOUDTRAIL_SAMPLE, EventSource.CLOUDTRAIL)


@pytest.fixture
def cloudtrail_by_id(cloudtrail_records) -> dict[str, dict]:
    """Records keyed by the last two digits of their eventID (01..14)."""
    return {r["eventID"][-2:]: r for r in cloudtrail_records}


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_backend="local",
        evidence_dir=str(tmp_path / "evidence"),
        log_level="WARNING",
        jwt_secret="test-secret-test-secret-test-secret",
        bootstrap_admin_password=TEST_ADMIN_PASSWORD,
    )


@pytest.fixture
def client(settings) -> TestClient:
    with TestClient(create_app(settings)) as test_client:
        login(test_client)
        yield test_client


@pytest.fixture
def evidence_store(tmp_path) -> LocalEvidenceStore:
    return LocalEvidenceStore(tmp_path / "evidence-unit")
