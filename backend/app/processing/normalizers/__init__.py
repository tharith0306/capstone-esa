from app.processing.normalizers.azure import AzureActivityNormalizer
from app.processing.normalizers.base import NormalizationError, Normalizer, SkipRecord
from app.processing.normalizers.cloudtrail import CloudTrailNormalizer
from app.processing.normalizers.cloudwatch import CloudWatchNormalizer
from app.processing.normalizers.gcp import GcpAuditNormalizer
from app.processing.normalizers.guardduty import GuardDutyNormalizer
from app.processing.normalizers.vpc_flow import VpcFlowNormalizer
from app.schemas.event import EventSource

_NORMALIZERS: dict[EventSource, Normalizer] = {
    EventSource.CLOUDTRAIL: CloudTrailNormalizer(),
    EventSource.VPC_FLOW: VpcFlowNormalizer(),
    EventSource.GUARDDUTY: GuardDutyNormalizer(),
    EventSource.CLOUDWATCH: CloudWatchNormalizer(),
    EventSource.AZURE_ACTIVITY: AzureActivityNormalizer(),
    EventSource.GCP_AUDIT: GcpAuditNormalizer(),
}


def get_normalizer(source: EventSource) -> Normalizer:
    return _NORMALIZERS[source]


__all__ = ["NormalizationError", "Normalizer", "SkipRecord", "get_normalizer"]
