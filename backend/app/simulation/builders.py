"""Builds raw records in the exact shape AWS delivers them, so they exercise the real normalizers."""

import random
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.schemas.event import EventSource
from app.simulation.environment import ACCOUNT_ID, DETECTOR_ID, HOME_REGION, Principal

GLOBAL_SERVICES = {"iam.amazonaws.com", "signin.amazonaws.com"}


@dataclass(frozen=True)
class Label:
    scenario_id: str | None
    attack_class: str
    stage: str


NORMAL = Label(None, "normal", "NORMAL")


@dataclass
class SimRecord:
    source: EventSource
    raw: dict[str, Any]
    label: Label
    timestamp: datetime


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class RecordFactory:
    def __init__(self, rng: random.Random):
        self.rng = rng

    def _uuid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def _identity(self, p: Principal, key: str | None) -> dict[str, Any]:
        if p.identity_type == "AssumedRole":
            ident = {
                "type": "AssumedRole",
                "principalId": f"{p.principal_id}:{p.session_name}",
                "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{p.role_name}/{p.session_name}",
                "accountId": ACCOUNT_ID,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": p.principal_id,
                        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{p.role_name}",
                        "accountId": ACCOUNT_ID,
                        "userName": p.role_name,
                    }
                },
            }
        else:
            ident = {
                "type": "IAMUser",
                "principalId": p.principal_id,
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{p.name}",
                "accountId": ACCOUNT_ID,
                "userName": p.name,
            }
        if key:
            ident["accessKeyId"] = key
        return ident

    def api(
        self,
        ts: datetime,
        p: Principal,
        name: str,
        service: str,
        *,
        ip: str,
        key: str | None,
        params: dict | None = None,
        response: dict | None = None,
        extra: dict | None = None,
        error: str | None = None,
        read_only: bool = False,
        category: str = "Management",
        user_agent: str | None = None,
        region: str | None = None,
        resources: list | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "eventVersion": "1.09",
            "userIdentity": self._identity(p, key),
            "eventTime": iso(ts),
            "eventSource": service,
            "eventName": name,
            "awsRegion": "us-east-1" if service in GLOBAL_SERVICES else (region or HOME_REGION),
            "sourceIPAddress": ip,
            "userAgent": user_agent or p.cli_user_agent,
            "requestParameters": params,
            "responseElements": None if error else response,
            "requestID": self._uuid(),
            "eventID": self._uuid(),
            "readOnly": read_only,
            "eventType": "AwsApiCall",
            "managementEvent": category == "Management",
            "recipientAccountId": ACCOUNT_ID,
            "eventCategory": category,
        }
        if extra:
            record["additionalEventData"] = extra
        if resources:
            record["resources"] = resources
        if error:
            record["errorCode"] = error
            record["errorMessage"] = f"User is not authorized to perform: {service.split('.')[0]}:{name}"
        return record

    def console_login(
        self, ts: datetime, p: Principal, *, ip: str, success: bool, mfa: bool, user_agent: str
    ) -> dict[str, Any]:
        record = {
            "eventVersion": "1.09",
            "userIdentity": self._identity(p, None),
            "eventTime": iso(ts),
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": ip,
            "userAgent": user_agent,
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/home",
                "MobileVersion": "No",
                "MFAUsed": "Yes" if mfa and success else "No",
            },
            "eventID": self._uuid(),
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "managementEvent": True,
            "recipientAccountId": ACCOUNT_ID,
            "eventCategory": "Management",
        }
        if not success:
            record["errorMessage"] = "Failed authentication"
        return record

    @staticmethod
    def flow(
        eni: str, src: str, dst: str, sport: int, dport: int, nbytes: int, start: datetime,
        *, action: str = "ACCEPT", protocol: int = 6, seconds: int = 60,
    ) -> dict[str, Any]:
        packets = max(1, nbytes // 1200)
        begin = int(start.timestamp())
        line = (
            f"2 {ACCOUNT_ID} {eni} {src} {dst} {sport} {dport} {protocol} {packets} {nbytes} "
            f"{begin} {begin + seconds} {action} OK"
        )
        return {"message": line}

    def finding(
        self,
        ts: datetime,
        finding_type: str,
        severity: float,
        title: str,
        *,
        user: Principal | None = None,
        key: str | None = None,
        instance_id: str | None = None,
        bucket: str | None = None,
        remote_ip: str | None = None,
        action_type: str = "AWS_API_CALL",
        api: str | None = None,
        outbound: bool = False,
    ) -> dict[str, Any]:
        if user is not None:
            resource = {
                "ResourceType": "AccessKey",
                "AccessKeyDetails": {"AccessKeyId": key, "PrincipalId": user.principal_id,
                                     "UserName": user.name, "UserType": user.identity_type},
            }
        elif instance_id:
            resource = {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": instance_id}}
        else:
            resource = {"ResourceType": "S3Bucket", "S3BucketDetails": [{"Name": bucket}]}

        action: dict[str, Any] = {"ActionType": action_type}
        remote = {"RemoteIpDetails": {"IpAddressV4": remote_ip}} if remote_ip else {}
        if action_type == "NETWORK_CONNECTION":
            action["NetworkConnectionAction"] = {
                "ConnectionDirection": "OUTBOUND" if outbound else "INBOUND", **remote}
        else:
            action["AwsApiCallAction"] = {"Api": api or "Unknown", **remote}

        finding_id = self._uuid().replace("-", "")
        return {
            "AccountId": ACCOUNT_ID,
            "Id": finding_id,
            "Arn": f"arn:aws:guardduty:{HOME_REGION}:{ACCOUNT_ID}:detector/{DETECTOR_ID}/finding/{finding_id}",
            "CreatedAt": iso(ts),
            "UpdatedAt": iso(ts),
            "Region": HOME_REGION,
            "Resource": resource,
            "Service": {"Action": action, "Count": 1, "DetectorId": DETECTOR_ID,
                        "EventFirstSeen": iso(ts), "EventLastSeen": iso(ts), "ServiceName": "guardduty"},
            "Severity": severity,
            "Title": title,
            "Type": finding_type,
            "SchemaVersion": "2.0",
        }
