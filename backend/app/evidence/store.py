"""Preserves every raw record exactly as received, content-addressed by SHA-256.

The normalized event points back here so an investigator can always recover and verify the original.
For a real deployment use the S3 backend on a bucket with versioning and Object Lock enabled.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.processing.hashing import canonical_json, sha256_hex
from app.schemas.event import EvidenceRef


class EvidenceStore(ABC):
    def put(self, source: str, raw: Any) -> EvidenceRef:
        data = canonical_json(raw)
        digest = sha256_hex(data)
        reference = self._write(source, digest, data)
        return EvidenceRef(reference=reference, sha256=digest)

    def verify(self, evidence: EvidenceRef) -> bool:
        try:
            return sha256_hex(self.get(evidence.reference)) == evidence.sha256
        except (FileNotFoundError, KeyError, ValueError):
            return False

    @staticmethod
    def _key(source: str, digest: str) -> str:
        return f"{source}/{digest[:2]}/{digest}.json"

    @abstractmethod
    def _write(self, source: str, digest: str, data: bytes) -> str:
        """Persist write-once and return the reference string."""

    @abstractmethod
    def get(self, reference: str) -> bytes: ...


class LocalEvidenceStore(EvidenceStore):
    SCHEME = "local://"

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _write(self, source: str, digest: str, data: bytes) -> str:
        key = self._key(source, digest)
        path = self.root / key
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(path)
        return self.SCHEME + key

    def get(self, reference: str) -> bytes:
        if not reference.startswith(self.SCHEME):
            raise ValueError(f"not a local evidence reference: {reference}")
        path = (self.root / reference.removeprefix(self.SCHEME)).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("evidence reference escapes the evidence directory")
        return path.read_bytes()


class S3EvidenceStore(EvidenceStore):
    def __init__(self, client: Any, bucket: str, prefix: str = "raw-events"):
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def _write(self, source: str, digest: str, data: bytes) -> str:
        key = f"{self.prefix}/{self._key(source, digest)}"
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType="application/json",
            ChecksumAlgorithm="SHA256",
            Metadata={"sha256": digest, "event-source": source},
        )
        return f"s3://{self.bucket}/{key}"

    def get(self, reference: str) -> bytes:
        bucket, _, key = reference.removeprefix("s3://").partition("/")
        if not reference.startswith("s3://") or not key:
            raise ValueError(f"not an s3 evidence reference: {reference}")
        return self.client.get_object(Bucket=bucket, Key=key)["Body"].read()


def build_evidence_store(settings: Settings) -> EvidenceStore:
    if settings.evidence_backend == "s3":
        if not settings.evidence_bucket:
            raise ValueError("CLOUDSHIELD_EVIDENCE_BUCKET is required when evidence_backend=s3")
        from app.collectors.aws import aws_client

        return S3EvidenceStore(aws_client(settings, "s3"), settings.evidence_bucket, settings.evidence_prefix)
    return LocalEvidenceStore(settings.evidence_dir)
