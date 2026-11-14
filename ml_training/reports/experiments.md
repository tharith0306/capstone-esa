# CloudShield experiment report

Generated 2026-11-14T17:50:45.863822+00:00 · model `20261114-1749-6765e2bf` · 119.1 s

> **All data is synthetic**, produced by the CloudShield simulator (realistic CloudTrail / VPC Flow / GuardDuty records run through the production normalizers). Models are trained on one simulated organisation and evaluated on different, unseen organisations. Results show the method works on this data; they are not a measurement against real attackers.

## Datasets

| Set | Seed | Days | Events | Windows | Attack scenarios |
|---|---|---|---|---|---|
| train | 7 | 30 | 64543 | 18720 | 162 |
| test | 99 | 14 | 29137 | 8235 | 33 |
| stealth | 123 | 10 | 18485 | 5548 | 21 |

Thresholds: attack probability ≥ 0.5, anomaly ECDF ≥ 0.995, correlation ≥ 0.4.

## E1 · Detection models (window level, test set)

8235 windows, 335 contain attack activity.

| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC | Macro-F1 (8 classes) | ms / 1k windows |
|---|---|---|---|---|---|---|---|
| Isolation Forest (unsupervised) | 0.250 | 0.069 | 0.108 | 0.881 | 0.184 | — | 9.128 |
| Random Forest (baseline) | 0.932 | 0.976 | 0.953 | 0.999 | 0.980 | 0.910 | 6.569 |
| XGBoost | 0.878 | 0.985 | 0.928 | 0.999 | 0.985 | 0.905 | 3.396 |
| Hybrid (XGBoost OR Isolation Forest) | 0.746 | 0.988 | 0.850 | 0.995 | 0.890 | — | 12.524 |

False-positive rate on normal windows: XGBoost 0.0058, Isolation Forest 0.0087, hybrid 0.0143.

| Class | Windows | XGBoost F1 | Random Forest F1 |
|---|---|---|---|
| normal | 7900 | 0.997 | 0.998 |
| brute_force | 5 | 0.909 | 0.800 |
| credential_compromise | 28 | 0.781 | 0.774 |
| reconnaissance | 28 | 0.769 | 0.833 |
| privilege_escalation | 20 | 0.976 | 0.974 |
| data_exfiltration | 67 | 0.887 | 0.947 |
| defense_evasion | 37 | 0.959 | 0.973 |
| resource_abuse | 150 | 0.962 | 0.977 |

## E2 · Cross-layer alert correlation (ablation)

Defaults (threshold 0.4, τ 120 min, max gap 6 h) were chosen by grid search on a separate tuning organisation (seed 8).

476 alerts (363 from attacks, 113 false).

| Method | Incidents | Alert reduction | Pair precision | Pair recall | Pair F1 | Purity | Incidents / scenario | False-alert contamination |
|---|---|---|---|---|---|---|---|---|
| No correlation (one incident per alert) | 476 | 0.000 | 1.000 | 0.000 | 0.000 | 1.000 | 11.000 | 0.000 |
| Temporal only (≈5 min window) | 119 | 0.750 | 0.824 | 0.799 | 0.812 | 0.888 | 2.580 | 0.266 |
| Entity matching only | 46 | 0.903 | 0.633 | 1.000 | 0.775 | 0.769 | 1.000 | 0.310 |
| Weighted similarity (no commonness filter, no stage) | 92 | 0.807 | 0.912 | 1.000 | 0.954 | 0.943 | 1.000 | 0.044 |
| CloudShield hybrid (full) | 118 | 0.752 | 0.954 | 0.948 | 0.951 | 0.959 | 1.300 | 0.009 |

## E3 · Explainability (SHAP on XGBoost)

- Explained 200 correctly classified attack windows, 2.06 ms per explanation.
- Deletion test (replace top-3 positive-SHAP features with the normal median): class probability drops by **0.9113** vs 0.0479 for 3 random features (ratio 19.01×).
- Overlap between each local top-5 and the global top-10: 0.583.
- Global top features: write_ratio, activity_deviation, max_cpu_utilization, discovery_count, failed_login_count, unique_resources, hours_since_prev_activity, sensitive_access_count, unique_source_ips, bytes_out_external.

### E3b · LIME and DiCE

- LIME: 241.9 ms per explanation, mean local R² 0.236; top-5 agreement with SHAP 0.4.
- DiCE counterfactuals (reductions of present activity only): found for 1.0 of windows, changing 3.13 features on average, 710.4 ms each.

## E4 · Forensic reconstruction

- Scenarios with an incident: 33 / 33
- Mean timeline completeness (share of the scenario's events inside its incident): 0.9485
- Mean entity recall of the attack graph (attacker IP, identities, keys, resources): 0.8205
- Top-3 ranked graph nodes include the attacker IP or a compromised identity: 1.0

| Stage decoder | Exact stage accuracy (attack events) | Attack-vs-normal accuracy (all incident events) |
|---|---|---|
| HMM (Viterbi) | 0.957 | 0.870 |
| Static rule (observation → stage) | 0.874 | 0.811 |

### E4b · Sequence models for stage decoding (per-entity sessions, test organisation)

| Model | Parameters | Train s | Attack stage acc. | Attack events flagged | Normal kept normal |
|---|---|---|---|---|---|
| HMM (supervised, Viterbi) | 243 | — | 0.911 | 0.939 | 0.859 |
| Static rule (observation → stage) | 0 | 0 | 0.860 | 0.887 | 0.670 |
| BiLSTM (2 layers) | 51787 | 18.200 | 0.954 | 0.969 | 0.988 |
| Transformer encoder (2 layers, 4 heads) | 76747 | 26.300 | 0.857 | 0.873 | 0.993 |

## E5 · Risk scoring and response

- Incidents: 118 (40 contain attack activity, 78 benign)
- Risk score as attack-incident classifier: ROC-AUC **0.9204** (mean risk 71.7 attack vs 43.6 benign)
- Attack incidents rated HIGH/CRITICAL: 0.825; benign HIGH/CRITICAL incidents per day: 0.92
- Median detection delay (scenario start → first alert window closes; excludes pipeline run cadence): 7.0 min
- Recommended actions: {'DEACTIVATE_ACCESS_KEY': 37, 'REVIEW_DATA_ACCESS': 22, 'REMOVE_USER_FROM_GROUP': 5, 'REVOKE_SECURITY_GROUP_INGRESS': 8, 'BLOCK_PUBLIC_ACCESS': 2, 'START_CLOUDTRAIL_LOGGING': 5, 'RESTORE_MONITORING': 12, 'ATTACH_DENY_ALL': 6, 'DETACH_USER_POLICY': 3, 'DELETE_INLINE_POLICY': 1, 'STOP_INSTANCES': 8, 'NOTIFY_ANALYST': 39}; automatable actions planned in dry-run: 74 (failed: 0)

### E5b · Reinforcement-learning response simulator (offline)

Reward model: damage prevented − operating cost; benign containment pays a disruption cost (see app/response/rl.py). Trained on 318 incidents, evaluated on 118.

| Strategy | Mean reward | Attacks contained | Benign disrupted |
|---|---|---|---|
| Always monitor | 0.000 | 0.000 | 0.000 |
| Always full containment | -3.800 | 1.000 | 1.000 |
| CloudShield policy engine (all proposals approved) | 0.637 | 0.550 | 0.090 |
| Q-learning (contextual bandit) | 0.969 | 0.850 | 0.154 |

### Detection by scenario type (test set)

| Scenario | n | Detected | HIGH/CRITICAL | Completeness | Median delay (min) |
|---|---|---|---|---|---|
| brute_force | 4 | 1.000 | 0.250 | 1.000 | 7.200 |
| brute_force_then_access | 2 | 1.000 | 1.000 | 1.000 | 9.200 |
| credential_compromise | 2 | 1.000 | 1.000 | 1.000 | 4.900 |
| data_exfiltration | 2 | 1.000 | 1.000 | 0.920 | 4.300 |
| defense_evasion | 4 | 1.000 | 1.000 | 1.000 | 5.000 |
| full_chain | 9 | 1.000 | 1.000 | 0.830 | 9.400 |
| insider_exfiltration | 3 | 1.000 | 1.000 | 1.000 | 1.700 |
| privilege_escalation | 4 | 1.000 | 1.000 | 1.000 | 2.900 |
| resource_abuse | 3 | 1.000 | 1.000 | 1.000 | 8.500 |

## E6 · Robustness to stealthy attacks

Dataset: all attacks stealthy (known IP & user agent, MFA, actions spread over hours).

| Model | Window recall (test) | Window recall (stealth) |
|---|---|---|
| Isolation Forest (unsupervised) | 0.069 | 0.018 |
| Random Forest (baseline) | 0.976 | 0.968 |
| XGBoost | 0.985 | 0.982 |
| Hybrid (XGBoost OR Isolation Forest) | 0.988 | 0.986 |

Scenario detection rate under stealth: 0.952; reaching HIGH/CRITICAL: 0.9524.

| Scenario | n | Detected | HIGH/CRITICAL | Completeness |
|---|---|---|---|---|
| brute_force | 2 | 1.000 | 1.000 | 1.000 |
| brute_force_then_access | 3 | 1.000 | 1.000 | 1.000 |
| credential_compromise | 1 | 1.000 | 1.000 | 0.860 |
| data_exfiltration | 2 | 1.000 | 1.000 | 0.820 |
| defense_evasion | 1 | 1.000 | 1.000 | 1.000 |
| full_chain | 4 | 1.000 | 1.000 | 0.630 |
| insider_exfiltration | 3 | 0.670 | 0.670 | 1.000 |
| privilege_escalation | 4 | 1.000 | 1.000 | 0.910 |
| resource_abuse | 1 | 1.000 | 1.000 | 0.950 |
