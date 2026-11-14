# CloudShield

**Cross-Layer Security Event Correlation and Explainable Risk Scoring for Cloud Attack Detection
and Forensic Investigation.** BTech CSE capstone.

CloudShield monitors cloud accounts across the identity, network, compute, storage and management
layers. AWS is the primary target, and Azure and GCP audit logs are normalized into the same schema.

It detects suspicious behaviour with a hybrid of ML models and rules, and joins related alerts into
multi-stage incidents. For each incident it:

- explains the risk score with SHAP, LIME and DiCE counterfactuals;
- rebuilds the attack path as a ranked graph and an HMM-decoded timeline, with a PDF report and a
  Neo4j export;
- recommends mitigations that analysts approve before execution. Live execution follows a
  two-person rule.

## Quick start (Docker)

```bash
colima start                      # macOS without Docker Desktop
docker compose up --build
docker compose logs backend | grep "generated password"   # first admin login (user: admin)
```

Open **http://localhost:8080** for the dashboard and **http://localhost:8000/docs** for the API.

The stack runs these services:

- PostgreSQL
- Redis
- the API
- a Celery worker
- the nginx dashboard

On first start the backend runs the Alembic migrations, trains the models (about 30 s), seeds a
simulated week with attacks, and analyses it. Set `CLOUDSHIELD_BOOTSTRAP_ADMIN_PASSWORD` to choose the
admin password, and `CLOUDSHIELD_SEED_DEMO=false` to start empty.

Optional services:

- `docker compose --profile scheduler up` runs periodic AWS collection and analysis (Celery beat).
- `docker compose --profile graph up` starts Neo4j for attack-graph exploration.
- `docker compose build --build-arg EXTRAS=graph,deep backend` adds PyTorch for the sequence-model experiments.

## Architecture

| # | Layer | Implementation |
|---|---|---|
| 1 | Cloud infrastructure | Terraform lab (validated with OpenTofu), IAM policies, real-attack runbook with Stratus Red Team (`infrastructure/aws/`) |
| 2 | Collection | CloudTrail (LookupEvents, S3 trail files), **EventBridge→SQS** (near real time, deletes messages only after ingest), VPC Flow Logs, GuardDuty, **CloudWatch CPU metrics**, **asset inventory** (EC2/ENI/S3/IAM) |
| 3 | Normalization | Common Pydantic schema for **AWS, Azure Activity Log and GCP Audit Logs**. Raw records preserved write-once with SHA-256 (local or S3 Object Lock) |
| 4 | Features | 47 behavioural features per entity window, relative to each entity's own history. Identifiers are kept out of model inputs. Flows and metrics are linked to instances via the inventory |
| 5 | Detection | Isolation Forest (ECDF-calibrated), XGBoost (8 classes), Random Forest baseline, rules |
| 6 | Correlation | C = 0.30T + 0.25I + 0.20R + 0.15N + 0.10S with a commonness filter and a shared-entity guard, tuned on a separate organisation |
| 7 | Explainability and risk | **SHAP**, **LIME**, **DiCE** counterfactuals; R = 100(0.20A + 0.25P + 0.20C + 0.15S + 0.10T + 0.10D) |
| 8 | Forensics | Supervised **HMM** (BiLSTM and Transformer compared in E4b), NetworkX graph with R(v) ranking, MITRE ATT&CK, hashed evidence manifest, **PDF report**, **Neo4j/Cypher export** |
| 9 | Response | Policy → approval → dry-run or live execution (separate responder identity) → rollback, with an audit log; **RL simulator** for offline comparison |
| 10 | API and dashboard | FastAPI with **JWT auth and roles**; Alembic; Celery + Redis; React + TypeScript + Tailwind + Recharts 3 + React Flow |
| 13 | Experiments | E1–E6 plus E3b (LIME/DiCE), E4b (deep sequence models), E5b (RL), and a public network-dataset experiment |

**Roles:**

- **viewer:** read only.
- **analyst:** run analysis, approve and reject actions, execute in dry run.
- **admin:** manage users, run simulations and AWS collection, execute live.

In live mode the executing admin must be a different person from the approver.

## Training data and results

No public dataset contains labelled AWS IAM/CloudTrail attacks. `app/simulation/` generates a
realistic organisation:

- **Principals:** developers, admins, analysts, EC2 roles and a CI role.
- **Background noise:** internet scanners and CloudWatch metrics, including legitimate batch-job
  CPU spikes.
- **Attacks:** nine attack scenarios, each in normal and stealthy variants.

Every record is emitted in its native AWS format and passes through the production normalizers.
Models train on one organisation (seed 7) and are tuned on another (seed 8). They are evaluated on
unseen organisations: seed 99, and seed 123 where every attack is stealthy. **All numbers are on
synthetic data.** [`infrastructure/aws/ATTACK_SIMULATION.md`](infrastructure/aws/ATTACK_SIMULATION.md)
is the protocol for validating them on a real account.

From [`ml_training/reports/experiments.md`](ml_training/reports/experiments.md):

| Experiment | Result (held-out organisation) |
|---|---|
| E1 detection | XGBoost: attack F1 0.93, PR-AUC 0.985, 0.6% false positives, 8-class macro-F1 0.91. Random Forest is comparable (F1 0.95). Isolation Forest alone has recall 0.07; anomaly ≠ attack |
| E2 correlation | 75% fewer items to triage, pair F1 0.95, 1.3 incidents per attack, 0.9% of false alerts merged into real incidents |
| E3 explainability | Removing the top-3 SHAP features drops class probability by 0.91, against 0.05 for random features (19×). LIME agrees with SHAP on 40% of the top-5; DiCE found a counterfactual for 100% of windows |
| E4 forensics | 95% of each attack's events land in its incident, 82% graph entity recall, and the attacker or victim is in the top-3 nodes in 100% of cases. HMM stage accuracy is 95.7% vs 87.4% for static rules |
| E4b sequence models | BiLSTM 95.4% stage accuracy (51k params) vs HMM 91.1% (243 params) vs Transformer 85.7% on the same per-entity sessions. The HMM is kept in production for interpretability |
| E5 risk/response | Risk ROC-AUC 0.92; 83% of attacks rated HIGH+; 0.92 false HIGH+ incidents per day; median detection 7 min after an attack starts |
| E5b RL (offline, assumed reward model) | Q-learning: reward 0.97, 85% of attacks contained, 15% of benign incidents disrupted. Policy engine: 0.64, 55% and 9% |
| E6 stealth | 95% of stealthy scenarios detected, and 95% of those reach HIGH+ |

The public-dataset experiment (UNSW-NB15 / TON_IoT / CIC-IDS2017, network flows only) is ready but
the datasets aren't bundled. Download them into `ml_training/datasets/`, then run
`python -m app.cli public-experiment --dataset unsw`.

## Local development

```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,deep,graph]"   # macOS: brew install libomp (XGBoost)
pytest                               # 91 tests, incl. moto-emulated AWS for collectors and live actions
export CLOUDSHIELD_BOOTSTRAP_ADMIN_PASSWORD=dev-admin-password
python -m app.cli train && python -m app.cli simulate --analyze
uvicorn app.main:create_app --factory --reload
cd ../frontend && npm install && npm run dev       # http://localhost:5173
```

CLI commands:

- **Data:** `init-db`, `ingest-file --source {cloudtrail|vpc_flow|guardduty|cloudwatch|azure_activity|gcp_audit} FILE…`
- **AWS:** `collect {cloudtrail|cloudtrail_s3|sqs|vpc_flow|guardduty|cloudwatch}`, `inventory`
- **Pipeline:** `train [--if-needed]`, `simulate [--if-empty] [--analyze]`, `analyze`
- **Research:** `experiments [--quick]`, `public-experiment --dataset …`

CI is defined in [`ci/github-actions.yml`](ci/github-actions.yml): tests, an experiment smoke run, the
frontend build and the Docker build. Move it to `.github/workflows/ci.yml` to activate it; pushing workflow
files needs a token with the `workflow` scope.

## Known limitations

- **Synthetic data only.** Every reported number comes from simulated organisations. The real-AWS
  protocol exists and the Terraform validates, but it hasn't been run. Live response actions are
  tested against moto, not a real account.
- **More false positives after better correlation.** Benign HIGH+ incidents went up once
  correlation stopped fragmenting multi-window benign activity, such as analysts' bulk exports and
  admins' permission changes: 0.92/day now, after evidence-weighting the correlation term (see E2/E5).
- **Multi-cloud covers ingestion only.** Azure and GCP records are normalized, but there are no
  collectors for them, and the models are trained on AWS behaviour only.
- **The RL reward model is assumed.** Treat E5b as a design study, not evidence.
