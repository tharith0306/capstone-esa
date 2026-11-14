"""Layer 9b: execute an *approved* action against AWS.

Default mode is dry_run: the exact API call is recorded but never sent. Live mode needs both
CLOUDSHIELD_RESPONSE_MODE=live and a dedicated CLOUDSHIELD_RESPONDER_PROFILE whose IAM policy allows
only these operations. The collector identity is never used for writes.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import Settings
from app.response.policies import DENY_ALL_POLICY


@dataclass(frozen=True)
class Operation:
    service: str
    operation: str
    params: Callable[[dict], dict]
    rollback_operation: str | None = None
    rollback_params: Callable[[dict], dict] | None = None


def _sg_permissions(t: dict) -> dict:
    return {"GroupId": t["group_id"], "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": t["from_port"], "ToPort": t["to_port"],
        "IpRanges": [{"CidrIp": t["cidr"]}]}]}


OPERATIONS: dict[str, Operation] = {
    "DEACTIVATE_ACCESS_KEY": Operation(
        "iam", "update_access_key",
        lambda t: {"UserName": t["user"], "AccessKeyId": t["access_key_id"], "Status": "Inactive"},
        "update_access_key",
        lambda t: {"UserName": t["user"], "AccessKeyId": t["access_key_id"], "Status": "Active"}),
    "DETACH_USER_POLICY": Operation(
        "iam", "detach_user_policy", lambda t: {"UserName": t["user"], "PolicyArn": t["policy_arn"]},
        "attach_user_policy", lambda t: {"UserName": t["user"], "PolicyArn": t["policy_arn"]}),
    "REMOVE_USER_FROM_GROUP": Operation(
        "iam", "remove_user_from_group", lambda t: {"UserName": t["user"], "GroupName": t["group"]},
        "add_user_to_group", lambda t: {"UserName": t["user"], "GroupName": t["group"]}),
    "ATTACH_DENY_ALL": Operation(
        "iam", "attach_user_policy", lambda t: {"UserName": t["user"], "PolicyArn": DENY_ALL_POLICY},
        "detach_user_policy", lambda t: {"UserName": t["user"], "PolicyArn": DENY_ALL_POLICY}),
    "REVOKE_SECURITY_GROUP_INGRESS": Operation(
        "ec2", "revoke_security_group_ingress", _sg_permissions,
        "authorize_security_group_ingress", _sg_permissions),
    "START_CLOUDTRAIL_LOGGING": Operation("cloudtrail", "start_logging", lambda t: {"Name": t["trail"]}),
    "BLOCK_PUBLIC_ACCESS": Operation(
        "s3", "put_public_access_block",
        lambda t: {"Bucket": t["bucket"], "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True}}),
    "STOP_INSTANCES": Operation(
        "ec2", "stop_instances", lambda t: {"InstanceIds": t["instance_ids"]},
        "start_instances", lambda t: {"InstanceIds": t["instance_ids"]}),
}


class ExecutionError(RuntimeError):
    pass


class ResponseExecutor:
    def __init__(self, settings: Settings, client_factory: Callable[[str, str | None], Any] | None = None):
        self.settings = settings
        self._client_factory = client_factory

    @property
    def live(self) -> bool:
        return self.settings.response_mode == "live"

    def _client(self, service: str, region: str | None) -> Any:
        if self._client_factory:
            return self._client_factory(service, region)
        if not self.settings.responder_profile:
            raise ExecutionError("live mode requires CLOUDSHIELD_RESPONDER_PROFILE (a write-scoped identity)")
        session = boto3.Session(profile_name=self.settings.responder_profile,
                                region_name=region or self.settings.aws_region)
        return session.client(service)

    def plan(self, action_type: str, target: dict, rollback: bool = False) -> dict:
        op = OPERATIONS.get(action_type)
        if op is None:
            raise ExecutionError(f"{action_type} is a manual action; CloudShield cannot execute it")
        if rollback:
            if not op.rollback_operation:
                raise ExecutionError(f"{action_type} has no automatic rollback")
            return {"service": op.service, "operation": op.rollback_operation, "params": op.rollback_params(target)}
        return {"service": op.service, "operation": op.operation, "params": op.params(target)}

    def execute(self, action_type: str, target: dict, rollback: bool = False) -> dict:
        call = self.plan(action_type, target, rollback)
        if not self.live:
            return {"mode": "dry_run", "executed": False, **call,
                    "note": "Dry run: no AWS API was called. Set CLOUDSHIELD_RESPONSE_MODE=live to execute."}
        client = self._client(call["service"], target.get("region"))
        try:
            response = getattr(client, call["operation"])(**call["params"])
        except (ClientError, BotoCoreError) as exc:
            raise ExecutionError(f"{call['service']}:{call['operation']} failed: {exc}") from exc
        response.pop("ResponseMetadata", None)
        return {"mode": "live", "executed": True, **call, "response": response,
                "verified": self._verify(client, action_type, target, rollback)}

    @staticmethod
    def _verify(client: Any, action_type: str, target: dict, rollback: bool) -> bool | None:
        if action_type == "DEACTIVATE_ACCESS_KEY":
            keys = client.list_access_keys(UserName=target["user"])["AccessKeyMetadata"]
            status = next((k["Status"] for k in keys if k["AccessKeyId"] == target["access_key_id"]), None)
            return status == ("Active" if rollback else "Inactive")
        return None
