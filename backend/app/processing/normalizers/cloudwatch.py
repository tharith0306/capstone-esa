"""CloudWatch metric datapoint -> SecurityEvent (compute layer).

Raw shape (produced by the CloudWatch collector or the simulator):
{"instance_id", "metric", "value", "unit", "timestamp", "region", "account_id", "private_ip"}
"""

from typing import Any

from app.processing.hashing import make_event_id
from app.processing.normalizers.base import NormalizationError, Normalizer, parse_timestamp
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent

CPU_HIGH = 80.0


class CloudWatchNormalizer(Normalizer):
    source = EventSource.CLOUDWATCH

    def source_event_id(self, raw: dict[str, Any]) -> str:
        if not raw.get("instance_id") or not raw.get("metric") or raw.get("timestamp") is None:
            raise NormalizationError("metric record needs instance_id, metric and timestamp")
        return f"{raw['instance_id']}:{raw['metric']}:{raw['timestamp']}"

    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        sid = self.source_event_id(raw)
        try:
            value = float(raw["value"])
        except (KeyError, TypeError, ValueError) as exc:
            raise NormalizationError(f"metric {sid} has no numeric value") from exc
        metric = str(raw["metric"])
        high = metric == "CPUUtilization" and value >= CPU_HIGH
        return SecurityEvent(
            event_id=make_event_id(self.source.value, sid),
            timestamp=parse_timestamp(raw["timestamp"]),
            account_id=raw.get("account_id"),
            region=raw.get("region"),
            event_source=self.source,
            source_event_id=sid,
            event_name=metric,
            event_type="METRIC_CPU_HIGH" if high else "METRIC_SAMPLE",
            layer=Layer.COMPUTE,
            action=f"cloudwatch:{metric}",
            outcome=Outcome.UNKNOWN,
            source_ip=raw.get("private_ip"),
            resource_id=raw["instance_id"],
            resource_type="ec2_instance",
            base_severity=0.3 if high else 0.0,
            attributes={"metric": metric, "value": value, "unit": raw.get("unit"), "private_ip": raw.get("private_ip")},
            raw_event_reference=evidence.reference,
            raw_event_hash=evidence.sha256,
        )
