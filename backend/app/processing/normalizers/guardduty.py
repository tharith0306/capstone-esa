"""GuardDuty finding (GetFindings response item) -> SecurityEvent.

GuardDuty is one input signal among many; CloudShield's own models must not depend on it.
"""

from typing import Any

from app.processing.hashing import make_event_id
from app.processing.normalizers.base import NormalizationError, Normalizer, parse_timestamp
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent

_NETWORK_ACTIONS = {"NETWORK_CONNECTION", "PORT_PROBE", "DNS_REQUEST"}
_COMPUTE_RESOURCES = {"Instance", "EKSCluster", "Container", "ECSCluster", "Lambda"}


class GuardDutyNormalizer(Normalizer):
    source = EventSource.GUARDDUTY

    def source_event_id(self, raw: dict[str, Any]) -> str:
        finding_id = raw.get("Id")
        if not finding_id:
            raise NormalizationError("GuardDuty finding has no Id")
        return str(finding_id)

    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        sid = self.source_event_id(raw)
        resource = raw.get("Resource") or {}
        resource_kind = resource.get("ResourceType")
        service = raw.get("Service") or {}
        action = service.get("Action") or {}
        action_type = action.get("ActionType") or "UNKNOWN"

        layer = Layer.APPLICATION
        actor_id = access_key = resource_id = resource_type = None
        if resource_kind == "AccessKey":
            details = resource.get("AccessKeyDetails") or {}
            layer = Layer.IDENTITY
            actor_id = details.get("UserName")
            access_key = details.get("AccessKeyId")
            resource_id, resource_type = actor_id, "iam_user"
        elif resource_kind == "S3Bucket":
            buckets = resource.get("S3BucketDetails") or []
            layer = Layer.STORAGE
            if buckets and buckets[0].get("Name"):
                resource_id, resource_type = f"arn:aws:s3:::{buckets[0]['Name']}", "s3_bucket"
        elif resource_kind in _COMPUTE_RESOURCES:
            layer = Layer.COMPUTE
            instance = resource.get("InstanceDetails") or {}
            if instance.get("InstanceId"):
                resource_id, resource_type = instance["InstanceId"], "ec2_instance"
        if action_type in _NETWORK_ACTIONS:
            layer = Layer.NETWORK

        remote_ip, outbound = _remote_ip(action)
        severity = float(raw.get("Severity") or 0) / 10.0
        finding_type = str(raw.get("Type") or "Unknown")
        return SecurityEvent(
            event_id=make_event_id(self.source.value, sid),
            timestamp=parse_timestamp(service.get("EventFirstSeen") or raw.get("CreatedAt")),
            account_id=raw.get("AccountId"),
            region=raw.get("Region"),
            event_source=self.source,
            source_event_id=sid,
            event_name=finding_type,
            event_type="GUARDDUTY_FINDING",
            layer=layer,
            action=f"guardduty:{action_type}",
            outcome=Outcome.UNKNOWN,
            actor_id=actor_id,
            actor_type="IAMUser" if actor_id else None,
            access_key_id=access_key,
            source_ip=None if outbound else remote_ip,
            destination_ip=remote_ip if outbound else None,
            resource_id=resource_id,
            resource_type=resource_type,
            base_severity=round(min(max(severity, 0.0), 1.0), 3),
            attributes={
                "finding_type": finding_type,
                "title": raw.get("Title"),
                "guardduty_severity": raw.get("Severity"),
                "action_type": action_type,
                "count": service.get("Count"),
                "last_seen": service.get("EventLastSeen"),
            },
            raw_event_reference=evidence.reference,
            raw_event_hash=evidence.sha256,
        )


def _remote_ip(action: dict[str, Any]) -> tuple[str | None, bool]:
    """Return (remote IP, is_outbound)."""
    for key in ("AwsApiCallAction", "NetworkConnectionAction", "KubernetesApiCallAction"):
        block = action.get(key) or {}
        ip = (block.get("RemoteIpDetails") or {}).get("IpAddressV4")
        if ip:
            return ip, block.get("ConnectionDirection") == "OUTBOUND"
    probes = (action.get("PortProbeAction") or {}).get("PortProbeDetails") or []
    if probes:
        return (probes[0].get("RemoteIpDetails") or {}).get("IpAddressV4"), False
    return None, False
