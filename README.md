# CloudShield

**Cross-Layer Security Event Correlation and Explainable Risk Scoring for Cloud Attack Detection
and Forensic Investigation.** BTech CSE capstone.

CloudShield monitors an AWS account across the identity, network, compute, storage and management
layers. It detects suspicious behaviour with a hybrid of ML models and rules, and joins related
alerts into multi-stage incidents. For each incident it explains the risk score, rebuilds the attack
path as a ranked graph and a timeline decoded by a Hidden Markov Model, and recommends mitigations
that an analyst must approve before they run.

## Quick start (Docker)

```bash
docker compose up --build
```

Open **http://localhost:8080** for the dashboard and **http://localhost:8000/docs** for the API.

On the first start the backend container does the following before serving:

1. Creates the PostgreSQL tables.
2. Trains the models on simulated, labelled data (about 30 s).
3. Seeds a simulated week of activity with attacks and runs the analysis.

Set `CLOUDSHIELD_SEED_DEMO=false` to start empty. On macOS without Docker Desktop, run `colima start` first.

Run the research experiments; the report is written to `ml_training/reports/`:

```bash
docker compose exec backend python -m app.cli experiments
```

## Architecture

| # | Layer | Implementation | Code |
|---|---|---|---|
| 1 | Cloud infrastructure | AWS lab guide and least-privilege IAM policies | `infrastructure/aws/` |
| 2 | Event collection | Boto3 collectors: CloudTrail, VPC Flow Logs (CloudWatch Logs), GuardDuty. Checkpoints with a late-delivery overlap | `app/collectors/` |
| 3 | Normalization | Pydantic common schema with about 70 mapped CloudTrail APIs. Raw records preserved write-once with a SHA-256 hash | `app/processing/`, `app/evidence/` |
| 4 | Features | 45 behavioural features per entity per 15-min window, compared with the entity's own history. IPs and names are deliberately **not** features | `app/ml/features.py` |
| 5 | ML detection | **Isolation Forest** (unsupervised, ECDF-calibrated), **XGBoost** (8 classes), **Random Forest** baseline, plus deterministic rules | `app/ml/`, `app/analysis/alerts.py` |
| 6 | Correlation | C = 0.30T + 0.25I + 0.20R + 0.15N + 0.10S with a commonness filter and a shared-entity guard. Connected components become incidents | `app/analysis/correlation.py` |
| 7 | Explainability and risk | **SHAP** (TreeExplainer) on XGBoost. R = 100(0.20A + 0.25P + 0.20C + 0.15S + 0.10T + 0.10D) | `app/ml/explain.py`, `app/analysis/risk.py` |
| 8 | Forensics | **HMM** (9 kill-chain stages, Viterbi), **NetworkX** attack graph with R(v) node ranking, timeline, MITRE ATT&CK mapping, hashed evidence manifest | `app/ml/hmm.py`, `app/analysis/forensics.py` |
| 9 | Response | Policy → actions → analyst approval → execution (**dry run by default**) → rollback, with an audit log | `app/response/`, `app/services/response.py` |
| 10 | Dashboard and API | FastAPI + PostgreSQL; React + TypeScript + Tailwind + Recharts + React Flow | `app/api/`, `frontend/` |
| 13 | Experiments | E1–E6: model comparison, correlation ablation, SHAP faithfulness, forensic reconstruction, risk/response, stealth robustness | `app/experiments/` |

### Where the training data comes from

No public dataset contains labelled AWS IAM/CloudTrail attacks. `app/simulation/` therefore
generates a realistic organisation with these principals:

- developers, admins and analysts;
- EC2 service roles;
- a CI/CD role.

It also produces internet scanner noise and nine attack scenarios. The scenarios cover brute force,
credential compromise, reconnaissance, privilege escalation with backdoor users, data
exfiltration, defense evasion, cryptomining, a full kill chain and an insider. Each comes in a
normal and a *stealthy* variant.

Records are emitted in the exact AWS formats and pass through the production normalizers. Benign
activity deliberately overlaps with attacks, such as admins granting permissions, analysts making
bulk exports and CI runners using new IPs. Models are trained on one simulated organisation and
evaluated on different, unseen ones. **All reported numbers are on synthetic data.**

## Results (held-out organisation)

From [`ml_training/reports/experiments.md`](ml_training/reports/experiments.md):

| Experiment | Result |
|---|---|
| E1 XGBoost, attack vs normal | F1 0.945, PR-AUC 0.993, 0.3% false positives; 8-class macro-F1 0.92 |
| E1 Isolation Forest alone | ROC-AUC 0.88 but recall 0.07. Anomaly ≠ attack, so it complements the classifiers rather than replacing them |
| E2 Correlation | 68% fewer alerts to triage, pair F1 0.74, 1.7 incidents per attack, 4.6% of false alerts merged into real incidents |
| E3 SHAP faithfulness | Removing the top-3 SHAP features drops class probability by 0.90, against 0.06 for random features |
| E4 HMM stage decoding | 95.7% exact stage accuracy, against 87.8% for a static observation→stage mapping |
| E4 Attack graph | 79% of ground-truth entities recovered; the attacker or victim is in the top-3 ranked nodes 91% of the time |
| E5 Risk score | ROC-AUC 0.98 for attack vs benign incidents; 98% of attacks rated HIGH+; 0.15 false HIGH+ incidents per day; median detection 5.9 min after an attack starts |
| E6 Stealth | All stealthy scenarios detected; fewer reach HIGH; their timelines are less complete |

## Local development (without Docker)

```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"           # on macOS XGBoost also needs: brew install libomp
pytest                            # 65 tests
python -m app.cli train
python -m app.cli simulate --analyze
uvicorn app.main:create_app --factory --reload
```

```bash
cd frontend && npm install && npm run dev    # http://localhost:5173, proxies /api to :8000
```

CLI commands:

- `init-db`
- `ingest-file --source {cloudtrail|vpc_flow|guardduty} FILE…`
- `collect {cloudtrail|vpc_flow|guardduty}`, which pulls from AWS
- `train`
- `simulate [--if-empty] [--analyze]`
- `analyze [--since] [--until]`
- `experiments [--quick]`

## Using it on a real AWS account

Follow [`infrastructure/aws/README.md`](infrastructure/aws/README.md) to set up the trail, flow logs,
GuardDuty and a read-only collector identity. Then run `collect`, followed by `analyze`.

Response actions stay in **dry run** until you set both of these:

- `CLOUDSHIELD_RESPONSE_MODE=live`
- `CLOUDSHIELD_RESPONDER_PROFILE`, a separate identity allowed only the response API calls

The collector identity is never used for writes.

## Known limitations and future work

- **Synthetic data.** The models must be re-validated on real CloudTrail before any production claim.
- **Correlation fragmentation.** Cryptomining hosts can't be linked to the `RunInstances` call without an ENI → instance inventory, which is the next enrichment to add. The commonness filter trades some recall for less contamination (see E2).
- **Not production-ready.** There's no authentication on the API or dashboard; approvals record a self-declared analyst name. Schema changes use `create_all`; Alembic migrations come next.
- **Not implemented yet.** Optional components from the design: LIME, DiCE counterfactuals, an LSTM/Transformer sequence model, Neo4j, and multi-cloud support.
