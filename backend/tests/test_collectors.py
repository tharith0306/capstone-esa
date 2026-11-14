import json
from datetime import datetime, timezone

import boto3
from botocore.stub import Stubber

from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.vpc_flow import VpcFlowCollector

START = datetime(2026, 11, 4, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 4, 11, 0, tzinfo=timezone.utc)


def _client(service):
    # Dummy values: the Stubber intercepts every call, nothing reaches AWS.
    return boto3.client(
        service, region_name="ap-south-1", aws_access_key_id="testing", aws_secret_access_key="testing"
    )


def test_cloudtrail_collector_unpacks_cloudtrail_event(cloudtrail_by_id):
    client = _client("cloudtrail")
    record = cloudtrail_by_id["07"]
    with Stubber(client) as stub:
        stub.add_response(
            "lookup_events",
            {"Events": [{"EventId": record["eventID"], "EventName": "CreateAccessKey",
                         "CloudTrailEvent": json.dumps(record)}]},
            {"StartTime": START, "EndTime": END},
        )
        collected = list(CloudTrailCollector(client).collect(START, END))
    assert collected == [record]


def test_vpc_flow_collector_wraps_messages():
    client = _client("logs")
    line = "2 111122223333 eni-1 10.0.0.1 10.0.0.2 1 2 6 1 40 1793788140 1793788200 ACCEPT OK"
    with Stubber(client) as stub:
        stub.add_response(
            "filter_log_events",
            {"events": [{"message": line, "logStreamName": "eni-1-all", "ingestionTime": 1}]},
            {"logGroupName": "/cloudshield/vpc-flow",
             "startTime": int(START.timestamp() * 1000), "endTime": int(END.timestamp() * 1000)},
        )
        collected = list(VpcFlowCollector(client, "/cloudshield/vpc-flow").collect(START, END))
    assert collected == [{"message": line, "log_stream": "eni-1-all", "ingestion_time": 1}]
