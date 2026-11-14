from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.collectors.base import Collector
from app.schemas.event import EventSource

_GET_FINDINGS_MAX = 50


class GuardDutyCollector(Collector):
    name = "guardduty"
    source = EventSource.GUARDDUTY

    def __init__(self, client: Any):
        self.client = client

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        criteria = {
            "Criterion": {
                "updatedAt": {
                    "GreaterThanOrEqual": int(start.timestamp() * 1000),
                    "LessThan": int(end.timestamp() * 1000),
                }
            }
        }
        detector_ids: list[str] = []
        for page in self.client.get_paginator("list_detectors").paginate():
            detector_ids.extend(page.get("DetectorIds", []))

        for detector_id in detector_ids:
            finding_ids: list[str] = []
            pages = self.client.get_paginator("list_findings").paginate(
                DetectorId=detector_id, FindingCriteria=criteria
            )
            for page in pages:
                finding_ids.extend(page.get("FindingIds", []))
            for i in range(0, len(finding_ids), _GET_FINDINGS_MAX):
                chunk = finding_ids[i : i + _GET_FINDINGS_MAX]
                response = self.client.get_findings(DetectorId=detector_id, FindingIds=chunk)
                yield from response.get("Findings", [])
