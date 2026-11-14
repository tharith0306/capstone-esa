# ML training and research

Training and evaluation code lives in the backend package so the API, the CLI and the experiments
share exactly one implementation:

| What | Where |
|---|---|
| Labelled data simulator | `backend/app/simulation/` |
| Feature engineering (45 features, 15-min entity windows) | `backend/app/ml/features.py` |
| Isolation Forest / XGBoost / Random Forest training | `backend/app/ml/training.py` |
| Supervised HMM (9 stages × 17 observations) | `backend/app/ml/hmm.py` |
| SHAP explanations | `backend/app/ml/explain.py` |
| Experiments E1–E6 | `backend/app/experiments/` |

```bash
python -m app.cli train                 # writes the bundle to $CLOUDSHIELD_MODEL_DIR (default backend/data/models)
python -m app.cli experiments           # writes reports/experiments.{md,json}
python -m app.cli experiments --quick   # smaller datasets for a smoke test
```

## Data protocol

- **Train:** seed 7, 30 days, 6 attacks/day (about 162 scenarios), 20% stealthy. The last 20% of the period is the time-based validation split; the Isolation Forest ECDF reference uses only held-out normal windows.
- **Tuning:** seed 8, used only to grid-search the correlation threshold, τ and maximum gap.
- **Test:** seed 99, 14 days, 25% stealthy. A different organisation, never seen in training or tuning.
- **Stealth:** seed 123, 10 days, 100% stealthy (robustness, E6).

The first simulated day is history only and is never scored, so that baselines exist.

`datasets/` is for public datasets (TON_IoT, UNSW-NB15, CIC-IDS) if network-only experiments are
added later. `saved_models/` is ignored by git, and so are the datasets.

`reports/` holds the latest experiment report and the ground truth of the demo data.
