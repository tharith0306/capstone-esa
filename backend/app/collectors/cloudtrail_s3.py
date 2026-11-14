"""CloudTrail log files delivered to the trail's S3 bucket. Unlike LookupEvents, this includes S3
object-level data events (GetObject/PutObject) and covers every region the trail logs."""

import gzip
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.collectors.base import Collector
from app.schemas.event import EventSource


class CloudTrailS3Collector(Collector):
    source = EventSource.CLOUDTRAIL

    def __init__(self, client: Any, bucket: str, prefix: str = "AWSLogs/"):
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.name = f"cloudtrail_s3:{bucket}"

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if "/CloudTrail/" not in key or not key.endswith(".json.gz"):
                    continue  # skip digest files and other services' logs
                if not (start <= obj["LastModified"] < end):
                    continue
                body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
                yield from json.loads(gzip.decompress(body)).get("Records", [])
