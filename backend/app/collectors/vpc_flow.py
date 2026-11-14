"""VPC Flow Logs published to a CloudWatch Logs group (default v2 format)."""

from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.collectors.base import Collector
from app.schemas.event import EventSource


class VpcFlowCollector(Collector):
    source = EventSource.VPC_FLOW

    def __init__(self, client: Any, log_group: str):
        self.client = client
        self.log_group = log_group
        self.name = f"vpc_flow:{log_group}"

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        paginator = self.client.get_paginator("filter_log_events")
        pages = paginator.paginate(
            logGroupName=self.log_group,
            startTime=int(start.timestamp() * 1000),
            endTime=int(end.timestamp() * 1000),
        )
        for page in pages:
            for event in page.get("events", []):
                yield {
                    "message": event["message"],
                    "log_stream": event.get("logStreamName"),
                    "ingestion_time": event.get("ingestionTime"),
                }
