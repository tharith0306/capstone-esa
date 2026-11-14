from typing import Any

import boto3
from botocore.config import Config

from app.core.config import Settings

# CloudTrail LookupEvents is limited to 2 requests/s per account per region; adaptive retry backs off.
_BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})


def aws_client(settings: Settings, service: str) -> Any:
    session = boto3.Session(profile_name=settings.aws_profile or None, region_name=settings.aws_region)
    return session.client(service, config=_BOTO_CONFIG)
