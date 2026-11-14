"""Near-real-time path: EventBridge rule -> SQS queue -> CloudShield.

EventBridge delivers CloudTrail API calls ("AWS API Call via CloudTrail" / "AWS Console Sign In via
CloudTrail") and GuardDuty findings ("GuardDuty Finding") with the original record in `detail`.
Messages are deleted only after `acknowledge()`, i.e. after the records were ingested, so a crash
never loses events (SQS redelivers them and deduplication absorbs the repeat).
"""

import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.collectors.base import Collector
from app.schemas.event import EventSource

CLOUDTRAIL_DETAIL_TYPES = {"AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"}


class SqsEventBridgeCollector(Collector):
    source = EventSource.CLOUDTRAIL

    def __init__(self, client: Any, queue_url: str, max_messages: int = 2000):
        self.client = client
        self.queue_url = queue_url
        self.max_messages = max_messages
        self.name = f"sqs:{queue_url.rsplit('/', 1)[-1]}"
        self.findings: list[dict] = []
        self._receipts: list[str] = []

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        # A queue has no time range: drain what is there (bounded), ignoring start/end.
        received = 0
        while received < self.max_messages:
            resp = self.client.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
            messages = resp.get("Messages", [])
            if not messages:
                return
            for msg in messages:
                received += 1
                self._receipts.append(msg["ReceiptHandle"])
                try:
                    envelope = json.loads(msg["Body"])
                except json.JSONDecodeError:
                    continue
                detail_type = envelope.get("detail-type")
                detail = envelope.get("detail") or {}
                if detail_type in CLOUDTRAIL_DETAIL_TYPES:
                    yield detail
                elif detail_type == "GuardDuty Finding":
                    self.findings.append(detail)

    def acknowledge(self) -> int:
        for i in range(0, len(self._receipts), 10):
            batch = self._receipts[i:i + 10]
            self.client.delete_message_batch(
                QueueUrl=self.queue_url,
                Entries=[{"Id": str(j), "ReceiptHandle": h} for j, h in enumerate(batch)])
        count, self._receipts = len(self._receipts), []
        return count
