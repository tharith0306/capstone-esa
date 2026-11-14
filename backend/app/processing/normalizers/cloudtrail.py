"""CloudTrail record -> SecurityEvent.

Accepts a full CloudTrail record as found in the S3 trail files ("Records": [...]) or in the
`CloudTrailEvent` JSON string returned by LookupEvents.
"""

import ipaddress
from dataclasses import dataclass
from typing import Any

from app.processing.hashing import make_event_id
from app.processing.normalizers.base import NormalizationError, Normalizer, parse_timestamp
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent


@dataclass(frozen=True)
class EventRule:
    event_type: str
    layer: Layer
    severity: float


def _rules(event_type: str, layer: Layer, severity: float, *names: str) -> dict[str, EventRule]:
    return {name: EventRule(event_type, layer, severity) for name in names}


_I, _N, _C, _S, _M = Layer.IDENTITY, Layer.NETWORK, Layer.COMPUTE, Layer.STORAGE, Layer.MANAGEMENT

# Known security-relevant API calls. Severity is a starting prior for the risk engine, not a verdict.
EVENT_RULES: dict[str, EventRule] = {
    # Identity: authentication and sessions
    **_rules("CONSOLE_LOGIN", _I, 0.2, "ConsoleLogin"),
    **_rules("SESSION_TOKEN_ISSUED", _I, 0.1, "GetSessionToken", "GetFederationToken"),
    **_rules("ROLE_ASSUMED", _I, 0.2, "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"),
    **_rules("IDENTITY_DISCOVERY", _I, 0.2, "GetCallerIdentity"),
    # Identity: credentials and principals
    **_rules("IAM_USER_CREATED", _I, 0.5, "CreateUser"),
    **_rules("IAM_USER_DELETED", _I, 0.5, "DeleteUser"),
    **_rules("LOGIN_PROFILE_CHANGED", _I, 0.6, "CreateLoginProfile", "UpdateLoginProfile"),
    **_rules("ACCESS_KEY_CREATED", _I, 0.6, "CreateAccessKey"),
    **_rules("ACCESS_KEY_UPDATED", _I, 0.4, "UpdateAccessKey"),
    **_rules("ACCESS_KEY_DELETED", _I, 0.3, "DeleteAccessKey"),
    **_rules("MFA_DEVICE_REMOVED", _I, 0.7, "DeactivateMFADevice", "DeleteVirtualMFADevice"),
    # Identity: permissions (privilege escalation surface)
    **_rules("POLICY_ATTACHED", _I, 0.7, "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"),
    **_rules("INLINE_POLICY_ADDED", _I, 0.7, "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"),
    **_rules("POLICY_VERSION_CHANGED", _I, 0.7, "CreatePolicyVersion", "SetDefaultPolicyVersion"),
    **_rules("GROUP_MEMBERSHIP_ADDED", _I, 0.6, "AddUserToGroup"),
    **_rules("ROLE_TRUST_POLICY_CHANGED", _I, 0.7, "UpdateAssumeRolePolicy"),
    **_rules(
        "IAM_ENUMERATION", _I, 0.3,
        "ListUsers", "ListRoles", "ListPolicies", "ListAttachedUserPolicies",
        "ListAttachedRolePolicies", "GetAccountAuthorizationDetails",
    ),
    # Compute
    **_rules("INSTANCE_LAUNCHED", _C, 0.4, "RunInstances"),
    **_rules("INSTANCE_STOPPED", _C, 0.3, "StopInstances"),
    **_rules("INSTANCE_TERMINATED", _C, 0.4, "TerminateInstances"),
    **_rules("INSTANCE_MODIFIED", _C, 0.5, "ModifyInstanceAttribute"),
    **_rules("INSTANCE_CREDENTIAL_ACCESS", _C, 0.7, "GetPasswordData"),
    **_rules("KEY_PAIR_CREATED", _C, 0.5, "CreateKeyPair", "ImportKeyPair"),
    **_rules("COMPUTE_ENUMERATION", _C, 0.1, "DescribeInstances"),
    # Network
    **_rules("SECURITY_GROUP_CREATED", _N, 0.3, "CreateSecurityGroup"),
    **_rules("SECURITY_GROUP_INGRESS_OPENED", _N, 0.6, "AuthorizeSecurityGroupIngress"),
    **_rules("SECURITY_GROUP_EGRESS_OPENED", _N, 0.5, "AuthorizeSecurityGroupEgress"),
    **_rules("SECURITY_GROUP_RULE_REVOKED", _N, 0.2, "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress"),
    **_rules("FLOW_LOGS_DELETED", _N, 0.9, "DeleteFlowLogs"),
    # Storage
    **_rules("STORAGE_ENUMERATION", _S, 0.2, "ListBuckets"),
    **_rules("OBJECT_LISTING", _S, 0.2, "ListObjects", "ListObjectsV2"),
    **_rules("OBJECT_DOWNLOADED", _S, 0.2, "GetObject"),
    **_rules("OBJECT_UPLOADED", _S, 0.1, "PutObject"),
    **_rules("OBJECT_DELETED", _S, 0.4, "DeleteObject", "DeleteObjects"),
    **_rules("BUCKET_POLICY_CHANGED", _S, 0.7, "PutBucketPolicy", "DeleteBucketPolicy"),
    **_rules("BUCKET_ACL_CHANGED", _S, 0.7, "PutBucketAcl", "PutObjectAcl"),
    **_rules("PUBLIC_ACCESS_BLOCK_CHANGED", _S, 0.8, "PutPublicAccessBlock", "DeletePublicAccessBlock"),
    # Management: tampering with the monitoring itself (defense evasion)
    **_rules("AUDIT_LOGGING_STOPPED", _M, 0.95, "StopLogging", "DeleteTrail"),
    **_rules("AUDIT_TRAIL_MODIFIED", _M, 0.7, "UpdateTrail", "PutEventSelectors"),
    **_rules("THREAT_DETECTION_DISABLED", _M, 0.95, "DeleteDetector", "DisassociateFromMasterAccount"),
}

_SERVICE_LAYERS: dict[str, Layer] = {
    "iam": _I, "sts": _I, "signin": _I, "sso": _I,
    "ec2": _C, "lambda": _C, "ecs": _C, "eks": _C,
    "s3": _S, "rds": _S, "dynamodb": _S,
    "cloudtrail": _M, "guardduty": _M, "config": _M, "organizations": _M, "kms": _M,
}

_ACCESS_DENIED_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "Client.UnauthorizedOperation", "UnauthorizedAccess",
}
_INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


class CloudTrailNormalizer(Normalizer):
    source = EventSource.CLOUDTRAIL

    def source_event_id(self, raw: dict[str, Any]) -> str:
        event_id = raw.get("eventID")
        if not event_id:
            raise NormalizationError("CloudTrail record has no eventID")
        return str(event_id)

    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        sid = self.source_event_id(raw)
        name = raw.get("eventName")
        if not name:
            raise NormalizationError(f"CloudTrail record {sid} has no eventName")

        service = str(raw.get("eventSource") or "")
        identity = raw.get("userIdentity") or {}
        params = raw.get("requestParameters") or {}
        response = raw.get("responseElements") or {}
        extra = raw.get("additionalEventData") or {}
        error_code = raw.get("errorCode")

        rule = EVENT_RULES.get(name) or _fallback_rule(service, raw.get("readOnly"))
        outcome = _outcome(name, error_code, response)
        actor_id, actor_type = _actor(identity)
        resource_id, resource_type = _resource(service, params, response, raw.get("resources"))
        source_ip, attributes = _source_ip(raw.get("sourceIPAddress"))
        attributes.update(_attributes(name, raw, params, response, extra, error_code))

        severity = rule.severity
        if outcome is Outcome.FAILURE:
            severity += 0.2
        if attributes.get("open_to_internet"):
            severity = max(severity, 0.8)

        access_key = identity.get("accessKeyId") or None
        return SecurityEvent(
            event_id=make_event_id(self.source.value, sid),
            timestamp=parse_timestamp(raw.get("eventTime")),
            account_id=raw.get("recipientAccountId") or identity.get("accountId"),
            region=raw.get("awsRegion"),
            event_source=self.source,
            source_event_id=sid,
            event_name=name,
            event_type=rule.event_type,
            layer=rule.layer,
            action=f"{service.split('.')[0]}:{name}" if service else name,
            outcome=outcome,
            error_code=error_code,
            actor_id=actor_id,
            actor_type=actor_type,
            # ASIA* keys are temporary STS credentials, i.e. one session.
            session_id=access_key if access_key and access_key.startswith("ASIA") else None,
            access_key_id=access_key,
            source_ip=source_ip,
            resource_id=resource_id,
            resource_type=resource_type,
            bytes_transferred=_bytes_out(extra),
            base_severity=round(min(severity, 1.0), 3),
            user_agent=raw.get("userAgent"),
            attributes=attributes,
            raw_event_reference=evidence.reference,
            raw_event_hash=evidence.sha256,
        )


def _fallback_rule(service: str, read_only: Any) -> EventRule:
    layer = _SERVICE_LAYERS.get(service.split(".")[0], Layer.APPLICATION)
    if read_only is True or str(read_only).lower() == "true":
        return EventRule("API_CALL_READ", layer, 0.05)
    return EventRule("API_CALL_WRITE", layer, 0.15)


def _outcome(name: str, error_code: str | None, response: dict[str, Any]) -> Outcome:
    if name == "ConsoleLogin":
        status = response.get("ConsoleLogin")
        if status == "Success":
            return Outcome.SUCCESS
        if status == "Failure":
            return Outcome.FAILURE
    return Outcome.FAILURE if error_code else Outcome.SUCCESS


def _actor(identity: dict[str, Any]) -> tuple[str | None, str | None]:
    kind = identity.get("type")
    arn = identity.get("arn") or ""
    if kind == "Root":
        return "root", kind
    if kind == "IAMUser":
        return identity.get("userName") or arn.rsplit("/", 1)[-1] or None, kind
    if kind == "AssumedRole":
        issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
        role = issuer.get("userName")
        session_name = arn.rsplit("/", 1)[-1] if arn else None
        if role and session_name:
            return f"{role}/{session_name}", kind
        return role or session_name or identity.get("principalId"), kind
    if kind == "AWSService":
        return identity.get("invokedBy"), kind
    return identity.get("userName") or identity.get("principalId") or arn or None, kind


def _instance_ids(block: dict[str, Any]) -> list[str]:
    items = (block.get("instancesSet") or {}).get("items") or []
    ids = [item["instanceId"] for item in items if item.get("instanceId")]
    if block.get("instanceId"):
        ids.insert(0, block["instanceId"])
    return ids


def _resource(
    service: str,
    params: dict[str, Any],
    response: dict[str, Any],
    resources: list[dict[str, Any]] | None,
) -> tuple[str | None, str | None]:
    bucket = params.get("bucketName")
    if bucket:
        key = params.get("key")
        if key:
            return f"arn:aws:s3:::{bucket}/{key}", "s3_object"
        return f"arn:aws:s3:::{bucket}", "s3_bucket"

    if service == "ec2.amazonaws.com":
        instance_ids = _instance_ids(params) or _instance_ids(response)
        if instance_ids:
            return instance_ids[0], "ec2_instance"
        if params.get("groupId"):
            return str(params["groupId"]), "security_group"
        if params.get("groupName"):
            return str(params["groupName"]), "security_group"

    if service == "iam.amazonaws.com":
        for field, kind in (
            ("userName", "iam_user"), ("roleName", "iam_role"),
            ("groupName", "iam_group"), ("policyArn", "iam_policy"),
        ):
            if params.get(field):
                return str(params[field]), kind

    if service == "sts.amazonaws.com" and params.get("roleArn"):
        return str(params["roleArn"]), "iam_role"

    if service == "cloudtrail.amazonaws.com" and params.get("name"):
        return str(params["name"]), "cloudtrail_trail"

    for item in resources or []:
        if item.get("ARN"):
            return str(item["ARN"]), item.get("type")
    return None, None


def _source_ip(value: Any) -> tuple[str | None, dict[str, Any]]:
    """CloudTrail sometimes reports a service name ("ec2.amazonaws.com", "AWS Internal")."""
    if not value:
        return None, {}
    try:
        ipaddress.ip_address(value)
        return str(value), {}
    except ValueError:
        return None, {"source_address": str(value)}


def _attributes(
    name: str,
    raw: dict[str, Any],
    params: dict[str, Any],
    response: dict[str, Any],
    extra: dict[str, Any],
    error_code: str | None,
) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    if raw.get("readOnly") is not None:
        attrs["read_only"] = raw["readOnly"] is True or str(raw["readOnly"]).lower() == "true"
    if "MFAUsed" in extra:
        attrs["mfa_used"] = extra["MFAUsed"] == "Yes"
    if raw.get("eventCategory"):
        attrs["event_category"] = raw["eventCategory"]
    if error_code in _ACCESS_DENIED_CODES:
        attrs["access_denied"] = True
    if raw.get("errorMessage"):
        attrs["error_message"] = raw["errorMessage"]
    if params.get("policyArn"):
        attrs["policy_arn"] = params["policyArn"]
    if name == "AddUserToGroup" and params.get("groupName"):
        attrs["group_name"] = params["groupName"]
    if name in ("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy") and params.get("policyName"):
        attrs["policy_name"] = params["policyName"]

    if name == "CreateAccessKey":
        created = (response.get("accessKey") or {}).get("accessKeyId")
        if created:
            attrs["created_access_key_id"] = created
    if name in ("UpdateAccessKey", "DeleteAccessKey") and params.get("accessKeyId"):
        attrs["target_access_key_id"] = params["accessKeyId"]
    if name.startswith("AssumeRole"):
        issued = (response.get("credentials") or {}).get("accessKeyId")
        if issued:
            attrs["issued_access_key_id"] = issued

    if name == "RunInstances":
        items = (response.get("instancesSet") or {}).get("items") or []
        attrs["instance_count"] = len(items) or int(params.get("maxCount") or 1)
        attrs["instance_type"] = params.get("instanceType")
        attrs["instance_ids"] = [i["instanceId"] for i in items if i.get("instanceId")]

    if name.startswith(("AuthorizeSecurityGroup", "RevokeSecurityGroup")):
        cidrs, ports = _ip_permissions(params)
        if cidrs:
            attrs["cidrs"] = cidrs
        if ports:
            attrs["ports"] = ports
        attrs["open_to_internet"] = name.startswith("Authorize") and bool(set(cidrs) & _INTERNET_CIDRS)
    return attrs


def _ip_permissions(params: dict[str, Any]) -> tuple[list[str], list[str]]:
    cidrs: list[str] = []
    ports: list[str] = []
    if params.get("cidrIp"):
        cidrs.append(params["cidrIp"])
    for perm in (params.get("ipPermissions") or {}).get("items") or []:
        low, high = perm.get("fromPort"), perm.get("toPort")
        if low is not None:
            ports.append(str(low) if low == high else f"{low}-{high}")
        for rng in (perm.get("ipRanges") or {}).get("items") or []:
            if rng.get("cidrIp"):
                cidrs.append(rng["cidrIp"])
        for rng in (perm.get("ipv6Ranges") or {}).get("items") or []:
            if rng.get("cidrIpv6"):
                cidrs.append(rng["cidrIpv6"])
    return cidrs, ports


def _bytes_out(extra: dict[str, Any]) -> int | None:
    value = extra.get("bytesTransferredOut")
    try:
        return int(float(value)) if value is not None else None
    except (TypeError, ValueError):
        return None
