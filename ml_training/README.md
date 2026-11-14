# ML training and research

Training and evaluation code lives in the backend package so the API, the CLI and the experiments
share exactly one implementation:

| What | Where |
|---|---|
| Labelled data simulator | `backend/app/simulation/` |
| Feature engineering (47 features, 15-min entity windows) | `backend/app/ml/features.py` |
| Isolation Forest / XGBoost / Random Forest training | `backend/app/ml/training.py` |
| Supervised HMM (9 stages × 17 observations) | `backend/app/ml/hmm.py` |
| SHAP explanations | `backend/app/ml/explain.py` |
| LIME + DiCE counterfactuals | `backend/app/ml/local_explain.py` |
| BiLSTM / Transformer stage taggers (optional `deep` extra) | `backend/app/ml/sequence.py` |
| RL response simulator (contextual bandit) | `backend/app/response/rl.py` |
| Experiments E1–E6 (+ E3b, E4b, E5b) | `backend/app/experiments/` |
| Public network datasets (UNSW-NB15, TON_IoT, CIC-IDS2017) | `backend/app/experiments/public_datasets.py` |

```bash
python -m app.cli train                 # writes the bundle to $CLOUDSHIELD_MODEL_DIR (default backend/data/models)
python -m app.cli experiments           # writes reports/experiments.{md,json}
python -m app.cli experiments --quick   # smaller datasets for a smoke test
```

## Data protocol

- **Train:** seed 7, 30 days, 6 attacks/day (about 162 scenarios), 20% stealthy. The last 20% of the period is the time-based validation split; the Isolation Forest ECDF reference uses only held-out normal windows.
- **Tuning:** seed 8, used only to grid-search the correlation threshold, τ and maximum gap, and to choose the evidence-weighted correlation term of the risk score.
- **Test:** seed 99, 14 days, 25% stealthy. A different organisation, never seen in training or tuning.
- **Stealth:** seed 123, 10 days, 100% stealthy (robustness, E6).

The first simulated day is history only and is never scored, so that baselines exist.

## Public datasets (network flows only)

Put the CSVs in `datasets/` (git-ignored), then run, for example:

```bash
python -m app.cli public-experiment --dataset unsw --path ../ml_training/datasets
```

The script expects these files:

| Dataset | Files |
|---|---|
| UNSW-NB15 | `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` |
| TON_IoT | `train_test_network.csv` |
| CIC-IDS2017 | `MachineLearningCVE/*.csv` |

Host identifiers (IPs, ports, timestamps) are dropped before training so the models can't
memorise entities. The report goes to `reports/public_<name>.md`. These datasets contain network
flows only, so they validate network detection, not IAM/CloudTrail detection.

`reports/` holds the latest experiment report and the ground truth of the demo data.
