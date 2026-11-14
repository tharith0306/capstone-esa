from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from CLOUDSHIELD_* environment variables or backend/.env."""

    model_config = SettingsConfigDict(env_prefix="CLOUDSHIELD_", env_file=".env", extra="ignore")

    environment: str = "development"
    log_level: str = "INFO"

    database_url: str = "sqlite:///./data/cloudshield.db"

    evidence_backend: Literal["local", "s3"] = "local"
    evidence_dir: str = "./data/evidence"
    evidence_bucket: str | None = None
    evidence_prefix: str = "raw-events"

    aws_region: str = "ap-south-1"
    aws_profile: str | None = None

    # First run of a collector with no checkpoint looks back this far.
    collector_default_lookback_minutes: int = 60
    # CloudTrail and VPC Flow Logs deliver late (typically 5-15 min). The next run restarts this far
    # before the previous end time; deduplication absorbs the overlap.
    collector_overlap_minutes: int = 15

    max_ingest_batch: int = 5000

    # ---- ML / analysis ----
    model_dir: str = "./data/models"
    reports_dir: str = "./data/reports"
    window_minutes: int = 15
    attack_probability_threshold: float = 0.5
    anomaly_alert_threshold: float = 0.995
    correlation_threshold: float = 0.4
    history_lookback_days: int = 14
    baseline_warmup_hours: int = 24

    # ---- response ----
    # dry_run records the exact API call without sending it; live requires a write-scoped profile.
    response_mode: Literal["dry_run", "live"] = "dry_run"
    responder_profile: str | None = None

    # In live mode the executing user must differ from the approver (two-person rule).
    require_two_person_live: bool = True

    # ---- authentication ----
    auth_enabled: bool = True
    jwt_secret: str | None = None  # random per process if unset (tokens die on restart)
    token_ttl_minutes: int = 480
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None  # random and logged once if unset and no users exist

    # ---- background jobs (Celery + Redis); empty = run synchronously in the API process ----
    celery_broker_url: str | None = None
    schedule_collect_minutes: int = 0  # >0 enables periodic AWS collection + analysis via celery beat
    vpc_flow_log_group: str | None = None
    sqs_queue_url: str | None = None
    trail_bucket: str | None = None
    trail_prefix: str = "AWSLogs/"

    # ---- optional Neo4j export ----
    neo4j_uri: str | None = None
    neo4j_user: str = "neo4j"
    neo4j_password: str | None = None

    # ---- demo ----
    enable_simulation: bool = True
    cors_origins: list[str] = ["http://localhost:5173"]


    @field_validator("*", mode="before")
    @classmethod
    def _empty_is_unset(cls, value, info):
        # `FOO=` in docker-compose / .env must mean "not set", never an empty password or secret.
        if value == "" and info.field_name in _OPTIONAL_STRINGS:
            return None
        return value


_OPTIONAL_STRINGS = {
    "evidence_bucket", "aws_profile", "responder_profile", "jwt_secret", "bootstrap_admin_password",
    "celery_broker_url", "vpc_flow_log_group", "sqs_queue_url", "trail_bucket", "neo4j_uri", "neo4j_password",
}


@lru_cache
def get_settings() -> Settings:
    return Settings()
