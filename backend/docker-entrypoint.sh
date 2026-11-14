#!/bin/sh
set -e
python -m app.cli init-db
python -m app.cli train --if-needed
if [ "${CLOUDSHIELD_SEED_DEMO:-false}" = "true" ]; then
  python -m app.cli simulate --if-empty --analyze
fi
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
