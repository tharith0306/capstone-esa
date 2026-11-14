from app.processing.normalizers.base import NormalizationError, Normalizer, SkipRecord
from app.processing.normalizers.cloudtrail import CloudTrailNormalizer
from app.processing.normalizers.guardduty import GuardDutyNormalizer
from app.processing.normalizers.vpc_flow import VpcFlowNormalizer
from app.schemas.event import EventSource

_NORMALIZERS: dict[EventSource, Normalizer] = {
    EventSource.CLOUDTRAIL: CloudTrailNormalizer(),
    EventSource.VPC_FLOW: VpcFlowNormalizer(),
    EventSource.GUARDDUTY: GuardDutyNormalizer(),
}


def get_normalizer(source: EventSource) -> Normalizer:
    return _NORMALIZERS[source]


__all__ = ["NormalizationError", "Normalizer", "SkipRecord", "get_normalizer"]
