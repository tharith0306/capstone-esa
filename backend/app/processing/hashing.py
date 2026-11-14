import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: same logical record -> same bytes -> same hash."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_event_id(source: str, source_event_id: str) -> str:
    """Stable CloudShield ID, so re-ingesting the same source record yields the same ID."""
    return "evt_" + sha256_hex(f"{source}:{source_event_id}".encode())[:24]
