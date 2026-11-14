import json

import pytest

from app.processing.hashing import canonical_json, sha256_hex


def test_put_get_and_verify(evidence_store):
    raw = {"b": 2, "a": {"z": 1, "y": [1, 2]}}
    ref = evidence_store.put("cloudtrail", raw)
    assert ref.reference.startswith("local://cloudtrail/")
    assert ref.sha256 == sha256_hex(canonical_json(raw))
    assert json.loads(evidence_store.get(ref.reference)) == raw
    assert evidence_store.verify(ref)


def test_key_order_does_not_change_hash(evidence_store):
    assert evidence_store.put("x", {"a": 1, "b": 2}).sha256 == evidence_store.put("x", {"b": 2, "a": 1}).sha256


def test_tampering_is_detected(evidence_store):
    ref = evidence_store.put("cloudtrail", {"eventID": "1", "eventName": "StopLogging"})
    path = evidence_store.root / ref.reference.removeprefix("local://")
    path.write_bytes(canonical_json({"eventID": "1", "eventName": "DescribeInstances"}))
    assert not evidence_store.verify(ref)


def test_reference_cannot_escape_root(evidence_store):
    with pytest.raises(ValueError):
        evidence_store.get("local://../../etc/passwd")
