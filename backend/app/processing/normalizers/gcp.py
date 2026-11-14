"""Google Cloud Audit Log entry (LogEntry with an AuditLog protoPayload) -> SecurityEvent."""

import ipaddress
from typing import Any

from app.processing.hashing import make_event_id
from app.processing.normalizers.base import NormalizationError, Normalizer, parse_timestamp
from app.processing.normalizers.cloudtrail import EventRule
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent

# Matched against the end of methodName (e.g. "google.iam.admin.v1.CreateServiceAccountKey",
# "v1.compute.instances.insert", "storage.objects.get").
SUFFIX_RULES: list[tuple[str, EventRule]] = [
    ("CreateServiceAccountKey", EventRule("ACCESS_KEY_CREATED", Layer.IDENTITY, 0.6)),
    ("CreateServiceAccount", EventRule("IAM_USER_CREATED", Layer.IDENTITY, 0.5)),
    ("SetIamPolicy", EventRule("POLICY_ATTACHED", Layer.IDENTITY, 0.7)),
    ("UpdateRole", EventRule("POLICY_VERSION_CHANGED", Layer.IDENTITY, 0.7)),
    ("ListServiceAccounts", EventRule("IAM_ENUMERATION", Layer.IDENTITY, 0.3)),
    ("compute.instances.insert", EventRule("INSTANCE_LAUNCHED", Layer.COMPUTE, 0.4)),
    ("compute.instances.delete", EventRule("INSTANCE_TERMINATED", Layer.COMPUTE, 0.4)),
    ("compute.instances.list", EventRule("COMPUTE_ENUMERATION", Layer.COMPUTE, 0.1)),
    ("compute.firewalls.insert", EventRule("SECURITY_GROUP_INGRESS_OPENED", Layer.NETWORK, 0.6)),
    ("compute.firewalls.patch", EventRule("SECURITY_GROUP_INGRESS_OPENED", Layer.NETWORK, 0.6)),
    ("storage.objects.get", EventRule("OBJECT_DOWNLOADED", Layer.STORAGE, 0.2)),
    ("storage.objects.list", EventRule("OBJECT_LISTING", Layer.STORAGE, 0.2)),
    ("storage.buckets.list", EventRule("STORAGE_ENUMERATION", Layer.STORAGE, 0.2)),
    ("storage.setIamPermissions", EventRule("BUCKET_POLICY_CHANGED", Layer.STORAGE, 0.7)),
    ("DeleteSink", EventRule("AUDIT_LOGGING_STOPPED", Layer.MANAGEMENT, 0.95)),
    ("UpdateSink", EventRule("AUDIT_TRAIL_MODIFIED", Layer.MANAGEMENT, 0.7)),
]
_SERVICE_LAYERS = {"iam.googleapis.com": Layer.IDENTITY, "compute.googleapis.com": Layer.COMPUTE,
                   "storage.googleapis.com": Layer.STORAGE, "logging.googleapis.com": Layer.MANAGEMENT,
                   "cloudresourcemanager.googleapis.com": Layer.IDENTITY}
_PERMISSION_DENIED = 7


class GcpAuditNormalizer(Normalizer):
    source = EventSource.GCP_AUDIT

    def source_event_id(self, raw: dict[str, Any]) -> str:
        if not raw.get("insertId"):
            raise NormalizationError("GCP log entry has no insertId")
        return f"{raw['insertId']}:{raw.get('timestamp', '')}"

    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        sid = self.source_event_id(raw)
        payload = raw.get("protoPayload") or {}
        method = payload.get("methodName")
        if not method:
            raise NormalizationError(f"GCP entry {sid} is not an audit log (no protoPayload.methodName)")
        service = payload.get("serviceName", "")
        rule = next((r for suffix, r in SUFFIX_RULES if method.endswith(suffix)), None)
        if rule is None:
            read = any(tok in method.lower() for tok in (".get", ".list", "get", "list"))
            rule = EventRule("API_CALL_READ" if read else "API_CALL_WRITE",
                             _SERVICE_LAYERS.get(service, Layer.APPLICATION), 0.05 if read else 0.15)
        status = payload.get("status") or {}
        code = int(status.get("code") or 0)
        outcome = Outcome.FAILURE if code else Outcome.SUCCESS
        meta = payload.get("requestMetadata") or {}
        ip = meta.get("callerIp")
        try:
            ip = str(ipaddress.ip_address(ip)) if ip else None
        except ValueError:
            ip = None
        request = payload.get("request") or {}
        open_internet = rule.event_type == "SECURITY_GROUP_INGRESS_OPENED" and "0.0.0.0/0" in (request.get("sourceRanges") or [])
        labels = (raw.get("resource") or {}).get("labels") or {}
        severity = rule.severity + (0.2 if outcome is Outcome.FAILURE else 0.0)
        return SecurityEvent(
            event_id=make_event_id(self.source.value, sid),
            timestamp=parse_timestamp(raw.get("timestamp")),
            cloud_provider="gcp",
            account_id=labels.get("project_id"),
            region=labels.get("location") or labels.get("zone"),
            event_source=self.source,
            source_event_id=sid,
            event_name=method,
            event_type=rule.event_type,
            layer=rule.layer,
            action=f"{service.split('.')[0]}:{method.rsplit('.', 1)[-1]}",
            outcome=outcome,
            error_code=str(code) if code else None,
            actor_id=(payload.get("authenticationInfo") or {}).get("principalEmail"),
            actor_type="GoogleIdentity",
            source_ip=ip,
            resource_id=payload.get("resourceName"),
            resource_type=f"gcp:{(raw.get('resource') or {}).get('type', 'resource')}",
            base_severity=round(min(1.0, max(severity, 0.8 if open_internet else 0.0)), 3),
            user_agent=meta.get("callerSuppliedUserAgent"),
            attributes={"log_name": raw.get("logName"), "open_to_internet": open_internet,
                        "access_denied": code == _PERMISSION_DENIED, "status_message": status.get("message")},
            raw_event_reference=evidence.reference,
            raw_event_hash=evidence.sha256,
        )
