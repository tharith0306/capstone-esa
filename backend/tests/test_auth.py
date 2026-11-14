from fastapi.testclient import TestClient

from app.core.security import hash_password, verify_password
from tests.conftest import login


def test_password_hashing():
    encoded = hash_password("correct horse battery")
    assert encoded.startswith("scrypt$")
    assert verify_password("correct horse battery", encoded)
    assert not verify_password("wrong", encoded)
    assert hash_password("same") != hash_password("same")  # salted


def test_requires_token(client):
    anonymous = TestClient(client.app)
    assert anonymous.get("/api/health").status_code == 200  # open
    assert anonymous.get("/api/events").status_code == 401
    assert anonymous.get("/api/incidents").status_code == 401
    bad = TestClient(client.app, headers={"Authorization": "Bearer not-a-jwt"})
    assert bad.get("/api/events").status_code == 401


def test_bad_password(client):
    r = TestClient(client.app).post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    audit = client.get("/api/response/audit").json()
    assert any(a["action"] == "login_failed" for a in audit)


def test_roles_and_user_management(client):
    me = client.get("/api/auth/me").json()
    assert me == {**me, "username": "admin", "role": "admin"}
    assert client.post("/api/auth/register", json={"username": "vic", "password": "short", "role": "viewer"}).status_code == 422
    assert client.post("/api/auth/register", json={"username": "vic", "password": "viewer-password-1", "role": "viewer"}).status_code == 200
    assert client.post("/api/auth/register", json={"username": "vic", "password": "viewer-password-1", "role": "viewer"}).status_code == 400

    viewer = TestClient(client.app)
    login(viewer, "vic", "viewer-password-1")
    assert viewer.get("/api/events").status_code == 200
    assert viewer.post("/api/events/ingest", json={"source": "cloudtrail", "records": [{}]}).status_code == 403
    assert viewer.post("/api/auth/register", json={"username": "x" * 5, "password": "y" * 12}).status_code == 403
    assert {u["username"] for u in client.get("/api/auth/users").json()} == {"admin", "vic"}


def test_logout_revokes_token(client):
    other = TestClient(client.app)
    login(other)
    assert other.post("/api/auth/logout").status_code == 200
    assert other.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me").status_code == 200  # other sessions unaffected


def test_actor_comes_from_token_not_request(client, cloudtrail_records):
    client.post("/api/events/ingest", json={"source": "cloudtrail", "records": cloudtrail_records[:2]})
    audit = client.get("/api/response/audit").json()
    assert all(a["actor"] in ("admin", "system") for a in audit)
