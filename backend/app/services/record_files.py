"""Load raw records from exported files (CloudTrail S3 deliveries, flow log dumps, findings JSON)."""

import gzip
import json
from pathlib import Path
from typing import Any

from app.schemas.event import EventSource


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def load_records(path: str | Path, source: EventSource) -> list[dict[str, Any]]:
    text = _read_text(Path(path))

    if source is EventSource.VPC_FLOW:
        return [
            {"message": line.strip()}
            for line in text.splitlines()
            if line.strip() and not line.startswith("version ")
        ]

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None  # fall through to JSON Lines
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("Records", "Findings", "records"):  # CloudTrail S3 file, GetFindings dump
                if isinstance(data.get(key), list):
                    return data[key]
            return [data]
    return [json.loads(line) for line in text.splitlines() if line.strip()]
