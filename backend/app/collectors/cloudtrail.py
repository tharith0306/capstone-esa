"""CloudTrail management events via LookupEvents.

LookupEvents covers the last 90 days of *management* events only. S3 object-level data events
(GetObject etc.) are only delivered to the trail's S3 bucket; ingest those files with
`python -m app.cli ingest-file --source cloudtrail <file.json.gz>`.
"""

import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.collectors.base import Collector
from app.schemas.event import EventSource


class CloudTrailCollector(Collector):
    name = "cloudtrail_lookup"
    source = EventSource.CLOUDTRAIL

    def __init__(self, client: Any):
        self.client = client

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        paginator = self.client.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=start, EndTime=end):
            for item in page.get("Events", []):
                payload = item.get("CloudTrailEvent")
                if payload:
                    yield json.loads(payload)
