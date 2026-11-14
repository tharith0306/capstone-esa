"""The common event schema every telemetry source is normalized into (Layer 3)."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EventSource(str, Enum):
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW = "vpc_flow"
    GUARDDUTY = "guardduty"


class Layer(str, Enum):
    IDENTITY = "identity"
    NETWORK = "network"
    COMPUTE = "compute"
    STORAGE = "storage"
    # Changes to the security tooling itself: CloudTrail, GuardDuty, Config, KMS, Organizations.
    MANAGEMENT = "management"
    APPLICATION = "application"


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EvidenceRef(BaseModel):
    """Where the untouched raw record is preserved, and the SHA-256 of its canonical JSON."""

    reference: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    cloud_provider: str = "aws"
    account_id: str | None = None
    region: str | None = None

    event_source: EventSource
    source_event_id: str
    event_name: str = Field(description="Name as reported by the source, e.g. CreateAccessKey")
    event_type: str = Field(description="CloudShield canonical type, e.g. ACCESS_KEY_CREATED")
    layer: Layer
    action: str
    outcome: Outcome
    error_code: str | None = None

    # Correlation keys: identity
    actor_id: str | None = None
    actor_type: str | None = None
    session_id: str | None = None
    access_key_id: str | None = None

    # Correlation keys: network
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None

    # Correlation keys: resource
    resource_id: str | None = None
    resource_type: str | None = None

    bytes_transferred: int | None = Field(default=None, ge=0)
    base_severity: float = Field(
        ge=0.0,
        le=1.0,
        description="Static prior from the event type/source. Not an ML score.",
    )
    user_agent: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    raw_event_reference: str
    raw_event_hash: str

    @field_validator("timestamp")
    @classmethod
    def _as_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
