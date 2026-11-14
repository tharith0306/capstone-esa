#!/bin/sh
set -e
python -m app.cli init-db
if [ ! -f "${CLOUDSHIELD_MODEL_DIR:-./data/models}/bundle.joblib" ]; then
  echo "No trained models found: training on simulated data (about 30 s)..."
  python -m app.cli train
fi
if [ "${CLOUDSHIELD_SEED_DEMO:-false}" = "true" ]; then
  python -m app.cli simulate --if-empty --analyze
fi
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
