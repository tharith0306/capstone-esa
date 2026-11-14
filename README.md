# CloudShield

**Cross-Layer Security Event Correlation and Explainable Risk Scoring for Cloud Attack Detection
and Forensic Investigation.** BTech CSE capstone.

CloudShield monitors an AWS account across the identity, network, compute, storage and management
layers. It detects suspicious behaviour with ML and links separate alerts into one multi-stage
incident. It also explains the incident's risk score, rebuilds the attack path as a graph and
timeline, and recommends responses that need human approval.

## Status

| Phase | Layer | State |
|---|---|---|
| 1 | AWS lab environment | Setup guide + IAM policies in [`infrastructure/aws`](infrastructure/aws/README.md) |
| 2 | Event collection | ✅ CloudTrail (LookupEvents + trail files), VPC Flow Logs, GuardDuty |
| 3 | Normalization | ✅ Common Pydantic schema, raw evidence preserved with SHA-256 |
| 4 | Database | ✅ SQLAlchemy models (SQLite locally, PostgreSQL via Docker) |
| 5–8 | Features, ML detection, correlation, SHAP | Not started |
| 9–10 | Risk engine, attack graph and forensics | Not started |
| 11–12 | Response engine, React dashboard | Not started |
| 13 | Experiments | Not started |

## Repository layout

```
backend/
  app/
    collectors/      Layer 2: boto3 pullers (cloudtrail, vpc_flow, guardduty)
    processing/      Layer 3: hashing + per-source normalizers -> SecurityEvent
    evidence/        write-once raw-event store (local dir or S3), hash verification
    database/        SQLAlchemy models: raw_events, security_events, collector_checkpoints
    services/        ingestion pipeline, collector checkpoints, file loaders
    api/             FastAPI routers (/api/health, /api/events/*)
    schemas/         SecurityEvent (common schema) + API models
    cli.py           init-db | ingest-file | collect
  sample_data/       synthetic credential-compromise chain across all three sources
  tests/
infrastructure/aws/  lab setup guide, collector IAM policy, trail bucket policy, data-event selectors
ml_training/         (later) datasets, notebooks, saved models
frontend/            (later) React dashboard
```

## Quick start (local, no AWS needed)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Load the sample attack chain and browse it:

```bash
python -m app.cli ingest-file --source cloudtrail sample_data/cloudtrail_credential_compromise.json
python -m app.cli ingest-file --source vpc_flow sample_data/vpc_flow_sample.log
python -m app.cli ingest-file --source guardduty sample_data/guardduty_findings.json
uvicorn app.main:create_app --factory --reload
```

Then open http://localhost:8000/docs. Try `GET /api/events?source_ip=203.0.113.50`. It returns
the attacker's activity across identity, network, storage and management events, which is the
raw material for the correlation engine.

With Docker (PostgreSQL): `docker compose up --build`.

## How ingestion works

```
collector / file / POST /api/events/ingest
        │  raw record
        ▼
dedupe on (source, source_event_id)  ──duplicate──▶ counted, dropped
        ▼
evidence store: canonical JSON → SHA-256 → write-once  (kept even if normalization fails)
        ▼
normalizer → SecurityEvent (layer, event_type, actor, access key, IPs, resource, base_severity, …)
        ▼
raw_events (intake ledger: normalized | skipped | failed)  +  security_events
```

- `base_severity` is a static prior per event type, **not** an ML score. The risk engine combines
  it with the model outputs later.
- `GET /api/events/{id}/raw` returns the original record and re-verifies its hash, so tampering
  with stored evidence is detectable.
- Collectors keep a checkpoint per source and re-read a 15-minute overlap, because CloudTrail and
  Flow Logs deliver late. Deduplication absorbs the overlap.

## Configuration

Settings come from `CLOUDSHIELD_*` environment variables or `backend/.env`. See
[`.env.example`](.env.example).
