"""Collectors, inventory and *live* response actions exercised against moto's AWS emulator.

No real AWS account is touched; moto intercepts every boto3 call in-process."""

import gzip
import json
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

from app.collectors.cloudtrail_s3 import CloudTrailS3Collector
from app.collectors.sqs import SqsEventBridgeCollector
from app.core.config import Settings
from app.response.executor import ResponseExecutor
from app.response.policies import DENY_ALL_POLICY

REGION = "ap-south-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    # Dummy values so botocore never looks for real credentials; moto intercepts all calls.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def live_executor() -> ResponseExecutor:
    return ResponseExecutor(Settings(response_mode="live"),
                            client_factory=lambda service, region: boto3.client(service, region_name=region or REGION))


@mock_aws
def test_cloudtrail_s3_collector_reads_gzipped_trail_files(cloudtrail_records):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="trail", CreateBucketConfiguration={"LocationConstraint": REGION})
    key = "AWSLogs/111122223333/CloudTrail/ap-south-1/2026/11/04/file.json.gz"
    s3.put_object(Bucket="trail", Key=key, Body=gzip.compress(json.dumps({"Records": cloudtrail_records[:3]}).encode()))
    s3.put_object(Bucket="trail", Key="AWSLogs/111122223333/CloudTrail-Digest/x.json.gz", Body=b"ignored")
    now = datetime.now(timezone.utc)
    got = list(CloudTrailS3Collector(s3, "trail").collect(now - timedelta(hours=1), now + timedelta(hours=1)))
    assert got == cloudtrail_records[:3]


@mock_aws
def test_sqs_eventbridge_collector_acknowledges_after_ingest(cloudtrail_records):
    sqs = boto3.client("sqs", region_name=REGION)
    url = sqs.create_queue(QueueName="cloudshield-events")["QueueUrl"]
    sqs.send_message(QueueUrl=url, MessageBody=json.dumps(
        {"detail-type": "AWS API Call via CloudTrail", "detail": cloudtrail_records[6]}))
    sqs.send_message(QueueUrl=url, MessageBody=json.dumps({"detail-type": "GuardDuty Finding", "detail": {"Id": "f1"}}))
    collector = SqsEventBridgeCollector(sqs, url)
    now = datetime.now(timezone.utc)
    assert list(collector.collect(now, now)) == [cloudtrail_records[6]]
    assert collector.findings == [{"Id": "f1"}]
    assert collector.acknowledge() == 2
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages",
                                                                    "ApproximateNumberOfMessagesNotVisible"])
    assert attrs["Attributes"] == {"ApproximateNumberOfMessages": "0", "ApproximateNumberOfMessagesNotVisible": "0"}


@mock_aws
def test_inventory_scan():
    from app.services.inventory import scan_aws

    ec2 = boto3.client("ec2", region_name=REGION)
    image = ec2.describe_images()["Images"][0]["ImageId"]
    inst = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, InstanceType="t3.micro")["Instances"][0]
    boto3.client("s3", region_name=REGION).create_bucket(
        Bucket="customer-data", CreateBucketConfiguration={"LocationConstraint": REGION})
    boto3.client("iam").create_user(UserName="bob")
    records = scan_aws(Settings(aws_region=REGION))
    by_type = {r["resource_type"]: r for r in records}
    assert by_type["ec2_instance"]["resource_id"] == inst["InstanceId"]
    assert by_type["ec2_instance"]["attributes"]["private_ips"] == [inst["PrivateIpAddress"]]
    assert by_type["s3_bucket"]["resource_id"] == "arn:aws:s3:::customer-data"
    assert by_type["iam_user"]["resource_id"] == "bob"


@mock_aws
def test_live_deactivate_key_with_verification_and_rollback():
    iam = boto3.client("iam")
    iam.create_user(UserName="bob")
    key = iam.create_access_key(UserName="bob")["AccessKey"]["AccessKeyId"]
    target = {"user": "bob", "access_key_id": key}
    result = live_executor().execute("DEACTIVATE_ACCESS_KEY", target)
    assert result["executed"] and result["verified"] is True
    assert iam.list_access_keys(UserName="bob")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    assert live_executor().execute("DEACTIVATE_ACCESS_KEY", target, rollback=True)["verified"] is True
    assert iam.list_access_keys(UserName="bob")["AccessKeyMetadata"][0]["Status"] == "Active"


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_live_quarantine_and_detach_policy():
    iam = boto3.client("iam")
    iam.create_user(UserName="bob")
    iam.attach_user_policy(UserName="bob", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ex = live_executor()
    ex.execute("DETACH_USER_POLICY", {"user": "bob", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    ex.execute("ATTACH_DENY_ALL", {"user": "bob"})
    attached = [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName="bob")["AttachedPolicies"]]
    assert attached == [DENY_ALL_POLICY]


@mock_aws
def test_live_revoke_security_group_and_stop_instances():
    ec2 = boto3.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="app", Description="app")["GroupId"]
    rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[rule])
    ex = live_executor()
    ex.execute("REVOKE_SECURITY_GROUP_INGRESS", {"group_id": sg, "cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22,
                                                  "region": REGION})
    assert ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"] == []

    image = ec2.describe_images()["Images"][0]["ImageId"]
    ids = [i["InstanceId"] for i in ec2.run_instances(ImageId=image, MinCount=2, MaxCount=2)["Instances"]]
    ex.execute("STOP_INSTANCES", {"instance_ids": ids, "region": REGION})
    states = {i["State"]["Name"] for r in ec2.describe_instances(InstanceIds=ids)["Reservations"] for i in r["Instances"]}
    assert states <= {"stopping", "stopped"}


@mock_aws
def test_live_block_public_access():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="customer-data", CreateBucketConfiguration={"LocationConstraint": REGION})
    live_executor().execute("BLOCK_PUBLIC_ACCESS", {"bucket": "customer-data"})
    config = s3.get_public_access_block(Bucket="customer-data")["PublicAccessBlockConfiguration"]
    assert all(config.values())


def test_two_person_rule_in_live_mode(tmp_path):
    from app.database.models import IncidentRecord, ResponseActionRecord
    from app.database.session import create_engine_from_url, create_session_factory, init_db
    from app.services.response import ResponseService, WorkflowError

    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'x.db'}")
    init_db(engine)
    factory = create_session_factory(engine)
    with factory() as s:
        s.add(IncidentRecord(incident_id="inc_1", run_id="r", title="t", primary_class="c", risk_score=90,
                             risk_level="CRITICAL", start=datetime.now(timezone.utc), end=datetime.now(timezone.utc),
                             alert_count=1, event_count=1, correlation_score=1))
        s.add(ResponseActionRecord(action_id="act_1", incident_id="inc_1", action_type="DEACTIVATE_ACCESS_KEY",
                                   target={"user": "bob", "access_key_id": "AKIA"}, description="d", rationale="r",
                                   api_call="x", automatable=True, reversible=True))
        s.commit()
    calls = []
    executor = ResponseExecutor(Settings(response_mode="live"), client_factory=lambda svc, region: _Recorder(calls))
    service = ResponseService(factory, Settings(response_mode="live"), executor)
    service.decide("act_1", "alice", approve=True)
    with pytest.raises(WorkflowError, match="two-person"):
        service.execute("act_1", "alice")
    assert service.execute("act_1", "bob")["status"] == "executed"
    assert calls and calls[0][0] == "update_access_key"


class _Recorder:
    def __init__(self, calls):
        self.calls = calls

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIA", "Status": "Inactive"}]}
        return call
