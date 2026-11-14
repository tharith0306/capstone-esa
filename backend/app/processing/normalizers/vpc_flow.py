"""VPC Flow Log line (default version-2 format) -> SecurityEvent.

Raw record shape: {"message": "<flow log line>", ...optional CloudWatch Logs metadata}.
"""

from typing import Any

from app.processing.hashing import make_event_id, sha256_hex
from app.processing.normalizers.base import (
    NormalizationError,
    Normalizer,
    SkipRecord,
    parse_timestamp,
)
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent

V2_FIELDS = (
    "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log_status",
)
PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}


def _message(raw: dict[str, Any]) -> str:
    message = raw.get("message")
    if not isinstance(message, str) or not message.strip():
        raise NormalizationError("VPC flow record has no 'message' line")
    return message.strip()


def _int(value: str) -> int | None:
    return int(value) if value.isdigit() else None


class VpcFlowNormalizer(Normalizer):
    source = EventSource.VPC_FLOW

    def source_event_id(self, raw: dict[str, Any]) -> str:
        # Flow lines carry no ID; the line itself (interface + 5-tuple + window + counters) is unique.
        return sha256_hex(_message(raw).encode())[:32]

    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        parts = _message(raw).split()
        if len(parts) != len(V2_FIELDS):
            raise NormalizationError(
                f"expected {len(V2_FIELDS)} fields in default flow log format, got {len(parts)}"
            )
        rec = dict(zip(V2_FIELDS, parts))
        if rec["log_status"] != "OK":
            raise SkipRecord(f"flow log status {rec['log_status']}")

        accepted = rec["action"] == "ACCEPT"
        start, end = _int(rec["start"]), _int(rec["end"])
        sid = self.source_event_id(raw)
        return SecurityEvent(
            event_id=make_event_id(self.source.value, sid),
            timestamp=parse_timestamp(start),
            account_id=rec["account_id"],
            event_source=self.source,
            source_event_id=sid,
            event_name=f"FLOW_{rec['action']}",
            event_type="NETWORK_FLOW_ACCEPTED" if accepted else "NETWORK_FLOW_REJECTED",
            layer=Layer.NETWORK,
            action=f"vpc:{rec['action'].lower()}",
            outcome=Outcome.SUCCESS if accepted else Outcome.FAILURE,
            source_ip=rec["srcaddr"],
            destination_ip=rec["dstaddr"],
            source_port=_int(rec["srcport"]),
            destination_port=_int(rec["dstport"]),
            protocol=PROTOCOLS.get(rec["protocol"], rec["protocol"]),
            resource_id=rec["interface_id"],
            resource_type="network_interface",
            bytes_transferred=_int(rec["bytes"]),
            base_severity=0.05 if accepted else 0.15,
            attributes={
                "packets": _int(rec["packets"]),
                "duration_seconds": (end - start) if start is not None and end is not None else None,
                "log_stream": raw.get("log_stream"),
            },
            raw_event_reference=evidence.reference,
            raw_event_hash=evidence.sha256,
        )
