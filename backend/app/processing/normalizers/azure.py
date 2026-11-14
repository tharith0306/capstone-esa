"""Azure Activity Log record -> SecurityEvent (multi-cloud support).

Accepts the diagnostic-settings export schema (time, operationName, resultType, callerIpAddress,
identity.claims, ...) and the REST API schema (eventTimestamp, operationName.value, caller,
status.value, ...).
"""

import ipaddress
from typing import Any

from app.processing.hashing import canonical_json, make_event_id, sha256_hex
from app.processing.normalizers.base import NormalizationError, Normalizer, parse_timestamp
from app.processing.normalizers.cloudtrail import EventRule
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent

_UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"

RULES: dict[str, EventRule] = {
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE": EventRule("POLICY_ATTACHED", Layer.IDENTITY, 0.7),
    "MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/WRITE": EventRule("POLICY_VERSION_CHANGED", Layer.IDENTITY, 0.7),
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/DELETE": EventRule("API_CALL_WRITE", Layer.IDENTITY, 0.3),
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE": EventRule("INSTANCE_LAUNCHED", Layer.COMPUTE, 0.4),
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE": EventRule("INSTANCE_TERMINATED", Layer.COMPUTE, 0.4),
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION": EventRule("INSTANCE_MODIFIED", Layer.COMPUTE, 0.7),
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION": EventRule("STORAGE_KEYS_LISTED", Layer.STORAGE, 0.6),
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE": EventRule("BUCKET_POLICY_CHANGED", Layer.STORAGE, 0.5),
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE": EventRule("SECURITY_GROUP_INGRESS_OPENED", Layer.NETWORK, 0.6),
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE": EventRule("AUDIT_LOGGING_STOPPED", Layer.MANAGEMENT, 0.95),
    "MICROSOFT.SECURITY/SECURITYCONTACTS/DELETE": EventRule("THREAT_DETECTION_DISABLED", Layer.MANAGEMENT, 0.8),
    "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE": EventRule("POLICY_ATTACHED", Layer.IDENTITY, 0.7),
}
_PROVIDER_LAYERS = {
    "MICROSOFT.AUTHORIZATION": Layer.IDENTITY, "MICROSOFT.COMPUTE": Layer.COMPUTE,
    "MICROSOFT.STORAGE": Layer.STORAGE, "MICROSOFT.NETWORK": Layer.NETWORK,
    "MICROSOFT.INSIGHTS": Layer.MANAGEMENT, "MICROSOFT.SECURITY": Layer.MANAGEMENT,
}


def _field(value: Any) -> str | None:
    if isinstance(value, dict):  # REST schema wraps strings as {"value": ..., "localizedValue": ...}
        return value.get("value")
    return value


class AzureActivityNormalizer(Normalizer):
    source = EventSource.AZURE_ACTIVITY

    def source_event_id(self, raw: dict[str, Any]) -> str:
        explicit = raw.get("eventDataId") or raw.get("id")
        if explicit:
            return str(explicit)
        if not raw.get("operationName") or not (raw.get("time") or raw.get("eventTimestamp")):
            raise NormalizationError("Azure activity record needs operationName and time")
        return sha256_hex(canonical_json(raw))[:32]

    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        sid = self.source_event_id(raw)
        operation = (_field(raw.get("operationName")) or "").upper()
        if not operation:
            raise NormalizationError(f"Azure record {sid} has no operationName")
        provider = operation.split("/")[0]
        rule = RULES.get(operation) or EventRule(
            "API_CALL_READ" if operation.endswith("/READ") else "API_CALL_WRITE",
            _PROVIDER_LAYERS.get(provider, Layer.APPLICATION), 0.05 if operation.endswith("/READ") else 0.15)

        status = (_field(raw.get("resultType")) or _field(raw.get("status")) or "").lower()
        outcome = Outcome.FAILURE if status in ("failure", "failed") else Outcome.SUCCESS if status in ("success", "succeeded") else Outcome.UNKNOWN
        claims = (raw.get("identity") or {}).get("claims") or {}
        actor = raw.get("caller") or claims.get(_UPN) or claims.get(_NAME) or claims.get("appid")
        resource_id = (raw.get("resourceId") or "").lower() or None
        parts = (resource_id or "").split("/")
        subscription = parts[2] if len(parts) > 2 and parts[1] == "subscriptions" else None
        ip = raw.get("callerIpAddress")
        try:
            ip = str(ipaddress.ip_address(ip)) if ip else None
        except ValueError:
            ip = None
        props = raw.get("properties") or {}
        severity = rule.severity + (0.2 if outcome is Outcome.FAILURE else 0.0)
        open_internet = rule.event_type == "SECURITY_GROUP_INGRESS_OPENED" and str(
            props.get("sourceAddressPrefix", props.get("requestbody", ""))).find("*") >= 0
        return SecurityEvent(
            event_id=make_event_id(self.source.value, sid),
            timestamp=parse_timestamp(raw.get("time") or raw.get("eventTimestamp")),
            cloud_provider="azure",
            account_id=subscription,
            region=raw.get("location"),
            event_source=self.source,
            source_event_id=sid,
            event_name=operation,
            event_type=rule.event_type,
            layer=rule.layer,
            action=f"azure:{operation}",
            outcome=outcome,
            error_code=_field(raw.get("resultSignature")) if outcome is Outcome.FAILURE else None,
            actor_id=actor,
            actor_type="AzureADPrincipal" if actor else None,
            source_ip=ip,
            resource_id=resource_id,
            resource_type=f"azure:{parts[-2]}" if len(parts) >= 2 and parts[-2] else None,
            base_severity=round(min(1.0, max(severity, 0.8 if open_internet else 0.0)), 3),
            attributes={"category": _field(raw.get("category")), "correlation_id": raw.get("correlationId"),
                        "open_to_internet": open_internet, "access_denied": status == "failure" and
                        "authorization" in str(_field(raw.get("resultSignature")) or "").lower()},
            raw_event_reference=evidence.reference,
            raw_event_hash=evidence.sha256,
        )
