"""Collect raw records from AWS for one source and ingest them (shared by CLI and Celery)."""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session, sessionmaker

from app.collectors.aws import aws_client
from app.collectors.base import Collector
from app.core.config import Settings
from app.schemas.event import EventSource
from app.services.checkpoints import get_checkpoint, set_checkpoint
from app.services.ingestion import IngestionService

COLLECTABLE = ("cloudtrail", "cloudtrail_s3", "vpc_flow", "guardduty", "cloudwatch", "sqs")


def build_collector(settings: Settings, name: str, log_group: str | None = None) -> tuple[Collector, EventSource]:
    if name == "cloudtrail":
        from app.collectors.cloudtrail import CloudTrailCollector
        return CloudTrailCollector(aws_client(settings, "cloudtrail")), EventSource.CLOUDTRAIL
    if name == "cloudtrail_s3":
        from app.collectors.cloudtrail_s3 import CloudTrailS3Collector
        if not settings.trail_bucket:
            raise ValueError("CLOUDSHIELD_TRAIL_BUCKET is required for cloudtrail_s3")
        return (CloudTrailS3Collector(aws_client(settings, "s3"), settings.trail_bucket, settings.trail_prefix),
                EventSource.CLOUDTRAIL)
    if name == "guardduty":
        from app.collectors.guardduty import GuardDutyCollector
        return GuardDutyCollector(aws_client(settings, "guardduty")), EventSource.GUARDDUTY
    if name == "vpc_flow":
        from app.collectors.vpc_flow import VpcFlowCollector
        group = log_group or settings.vpc_flow_log_group
        if not group:
            raise ValueError("a CloudWatch Logs group is required for vpc_flow (--log-group or CLOUDSHIELD_VPC_FLOW_LOG_GROUP)")
        return VpcFlowCollector(aws_client(settings, "logs"), group), EventSource.VPC_FLOW
    if name == "cloudwatch":
        from app.collectors.cloudwatch import CloudWatchMetricsCollector
        return (CloudWatchMetricsCollector(aws_client(settings, "cloudwatch"), aws_client(settings, "ec2")),
                EventSource.CLOUDWATCH)
    if name == "sqs":
        from app.collectors.sqs import SqsEventBridgeCollector
        if not settings.sqs_queue_url:
            raise ValueError("CLOUDSHIELD_SQS_QUEUE_URL is required for sqs")
        return SqsEventBridgeCollector(aws_client(settings, "sqs"), settings.sqs_queue_url), EventSource.CLOUDTRAIL
    raise ValueError(f"unknown collector {name}; choose from {COLLECTABLE}")


def collect(settings: Settings, session_factory: sessionmaker[Session], ingestion: IngestionService, name: str,
            since: datetime | None = None, until: datetime | None = None, log_group: str | None = None) -> dict:
    collector, source = build_collector(settings, name, log_group)
    end = until or datetime.now(timezone.utc)
    if since is None:
        with session_factory() as session:
            since = get_checkpoint(session, collector.name) or (
                end - timedelta(minutes=settings.collector_default_lookback_minutes))
    result = ingestion.ingest(source, collector.collect(since, end))
    extra = {}
    findings = getattr(collector, "findings", None)
    if findings:
        extra["guardduty"] = ingestion.ingest(EventSource.GUARDDUTY, findings).model_dump(mode="json")
    if hasattr(collector, "acknowledge"):
        extra["acknowledged_messages"] = collector.acknowledge()  # only after a successful ingest
    # Late-delivered events can carry timestamps before `end`; re-read an overlap next time.
    cursor = max(since, end - timedelta(minutes=settings.collector_overlap_minutes))
    with session_factory() as session:
        set_checkpoint(session, collector.name, cursor)
    return {"collector": collector.name, "from": since.isoformat(), "to": end.isoformat(),
            **result.model_dump(mode="json"), **extra}
