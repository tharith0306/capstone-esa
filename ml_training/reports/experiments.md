# CloudShield experiment report

Generated 2026-11-14T17:12:46.801821+00:00 · model `20261114-1712-c770f935` · 20.1 s

> **All data is synthetic**, produced by the CloudShield simulator (realistic CloudTrail / VPC Flow / GuardDuty records run through the production normalizers). Models are trained on one simulated organisation and evaluated on different, unseen organisations. Results show the method works on this data; they are not a measurement against real attackers.

## Datasets

| Set | Seed | Days | Events | Windows | Attack scenarios |
|---|---|---|---|---|---|
| train | 7 | 30 | 50193 | 16318 | 162 |
| test | 99 | 14 | 21843 | 7121 | 33 |
| stealth | 123 | 10 | 14429 | 4878 | 21 |

Thresholds: attack probability ≥ 0.5, anomaly ECDF ≥ 0.995, correlation ≥ 0.4.

## E1 · Detection models (window level, test set)

7121 windows, 239 contain attack activity.

| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC | Macro-F1 (8 classes) | ms / 1k windows |
|---|---|---|---|---|---|---|---|
| Isolation Forest (unsupervised) | 0.267 | 0.067 | 0.107 | 0.883 | 0.159 | — | 10.256 |
| Random Forest (baseline) | 0.954 | 0.958 | 0.956 | 1.000 | 0.989 | 0.939 | 9.931 |
| XGBoost | 0.917 | 0.975 | 0.945 | 1.000 | 0.993 | 0.920 | 7.068 |
| Hybrid (XGBoost OR Isolation Forest) | 0.783 | 0.979 | 0.870 | 0.994 | 0.823 | — | 17.324 |

False-positive rate on normal windows: XGBoost 0.0031, Isolation Forest 0.0064, hybrid 0.0094.

| Class | Windows | XGBoost F1 | Random Forest F1 |
|---|---|---|---|
| normal | 6882 | 0.998 | 0.999 |
| brute_force | 12 | 1.000 | 1.000 |
| credential_compromise | 28 | 0.767 | 0.780 |
| reconnaissance | 21 | 0.800 | 0.864 |
| privilege_escalation | 19 | 0.905 | 0.974 |
| data_exfiltration | 68 | 0.906 | 0.930 |
| defense_evasion | 39 | 0.987 | 0.961 |
| resource_abuse | 52 | 1.000 | 1.000 |

## E2 · Cross-layer alert correlation (ablation)

Defaults (threshold 0.4, τ 120 min, max gap 6 h) were chosen by grid search on a separate tuning organisation (seed 8).

340 alerts (275 from attacks, 65 false).

| Method | Incidents | Alert reduction | Pair precision | Pair recall | Pair F1 | Purity | Incidents / scenario | False-alert contamination |
|---|---|---|---|---|---|---|---|---|
| No correlation (one incident per alert) | 340 | 0.000 | 1.000 | 0.000 | 0.000 | 1.000 | 8.330 | 0.000 |
| Temporal only (≈5 min window) | 113 | 0.668 | 0.699 | 0.354 | 0.470 | 0.866 | 2.640 | 0.246 |
| Entity matching only | 35 | 0.897 | 0.454 | 0.966 | 0.618 | 0.722 | 1.090 | 0.415 |
| Weighted similarity (no commonness filter, no stage) | 88 | 0.741 | 0.913 | 0.871 | 0.891 | 0.968 | 1.300 | 0.123 |
| CloudShield hybrid (full) | 108 | 0.682 | 0.856 | 0.645 | 0.736 | 0.939 | 1.670 | 0.046 |

## E3 · Explainability (SHAP on XGBoost)

- Explained 200 correctly classified attack windows, 2.2 ms per explanation.
- Deletion test (replace top-3 positive-SHAP features with the normal median): class probability drops by **0.9015** vs 0.0571 for 3 random features (ratio 15.79×).
- Overlap between each local top-5 and the global top-10: 0.597.
- Global top features: write_ratio, failed_login_count, discovery_count, activity_deviation, hours_since_prev_activity, uncommon_port_flows, unique_resources, sensitive_access_count, access_key_created_count, bytes_out_external.

## E4 · Forensic reconstruction

- Scenarios with an incident: 33 / 33
- Mean timeline completeness (share of the scenario's events inside its incident): 0.8733
- Mean entity recall of the attack graph (attacker IP, identities, keys, resources): 0.7911
- Top-3 ranked graph nodes include the attacker IP or a compromised identity: 0.9091

| Stage decoder | Exact stage accuracy (attack events) | Attack-vs-normal accuracy (all incident events) |
|---|---|---|
| HMM (Viterbi) | 0.957 | 0.972 |
| Static rule (observation → stage) | 0.878 | 0.885 |

## E5 · Risk scoring and response

- Incidents: 108 (51 contain attack activity, 57 benign)
- Risk score as attack-incident classifier: ROC-AUC **0.9843** (mean risk 75.3 attack vs 38.8 benign)
- Attack incidents rated HIGH/CRITICAL: 0.9804; benign HIGH/CRITICAL incidents per day: 0.15
- Median detection delay (scenario start → first alert window closes; excludes pipeline run cadence): 5.9 min
- Recommended actions: {'DEACTIVATE_ACCESS_KEY': 40, 'DELETE_INLINE_POLICY': 2, 'REVOKE_SECURITY_GROUP_INGRESS': 10, 'BLOCK_PUBLIC_ACCESS': 4, 'RESTORE_MONITORING': 16, 'REVIEW_DATA_ACCESS': 19, 'REMOVE_USER_FROM_GROUP': 3, 'ATTACH_DENY_ALL': 9, 'DETACH_USER_POLICY': 9, 'START_CLOUDTRAIL_LOGGING': 4, 'STOP_INSTANCES': 5, 'NOTIFY_ANALYST': 24}; automatable actions planned in dry-run: 84 (failed: 0)

### Detection by scenario type (test set)

| Scenario | n | Detected | HIGH/CRITICAL | Completeness | Median delay (min) |
|---|---|---|---|---|---|
| brute_force | 2 | 1.000 | 1.000 | 1.000 | 10.400 |
| brute_force_then_access | 3 | 1.000 | 1.000 | 1.000 | 6.700 |
| data_exfiltration | 4 | 1.000 | 1.000 | 0.940 | 8.600 |
| defense_evasion | 5 | 1.000 | 1.000 | 1.000 | 2.100 |
| full_chain | 10 | 1.000 | 1.000 | 0.870 | 6.600 |
| insider_exfiltration | 2 | 1.000 | 1.000 | 1.000 | 11.200 |
| privilege_escalation | 3 | 1.000 | 1.000 | 1.000 | 5.000 |
| resource_abuse | 4 | 1.000 | 1.000 | 0.330 | 4.700 |

## E6 · Robustness to stealthy attacks

Dataset: all attacks stealthy (known IP & user agent, MFA, actions spread over hours).

| Model | Window recall (test) | Window recall (stealth) |
|---|---|---|
| Isolation Forest (unsupervised) | 0.067 | 0.004 |
| Random Forest (baseline) | 0.958 | 0.965 |
| XGBoost | 0.975 | 0.974 |
| Hybrid (XGBoost OR Isolation Forest) | 0.979 | 0.974 |

Scenario detection rate under stealth: 1.0; reaching HIGH/CRITICAL: 1.0.

| Scenario | n | Detected | HIGH/CRITICAL | Completeness |
|---|---|---|---|---|
| brute_force | 1 | 1.000 | 1.000 | 1.000 |
| brute_force_then_access | 2 | 1.000 | 1.000 | 1.000 |
| data_exfiltration | 2 | 1.000 | 1.000 | 0.760 |
| defense_evasion | 2 | 1.000 | 1.000 | 0.750 |
| full_chain | 5 | 1.000 | 1.000 | 0.600 |
| insider_exfiltration | 1 | 1.000 | 1.000 | 1.000 |
| privilege_escalation | 6 | 1.000 | 1.000 | 0.970 |
| resource_abuse | 2 | 1.000 | 1.000 | 0.500 |
