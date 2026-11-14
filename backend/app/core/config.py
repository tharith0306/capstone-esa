from functools import lru_cache
from typing import Literal

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
    cors_origins: list[str] = ["http://localhost:5173"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
