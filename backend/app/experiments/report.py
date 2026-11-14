"""Render the experiment report as Markdown (for the paper / repo)."""


def _table(rows: list[dict], columns: list[tuple[str, str]]) -> str:
    head = "| " + " | ".join(title for _, title in columns) + " |"
    sep = "|" + "|".join("---" for _ in columns) + "|"
    body = []
    for r in rows:
        cells = []
        for key, _ in columns:
            v = r.get(key)
            cells.append("—" if v is None else f"{v:.3f}" if isinstance(v, float) else str(v))
        body.append("| " + " | ".join(cells) + " |")
    return "\n".join([head, sep, *body])


def render_markdown(r: dict) -> str:
    e1, e2, e3, e4, e5, e6 = (r[k] for k in ("e1_model_comparison", "e2_correlation", "e3_explainability",
                                             "e4_forensics", "e5_risk_and_response", "e6_robustness"))
    d = r["datasets"]
    per_class = [{"class": k, **v} for k, v in e1["per_class_f1"].items()]
    sd = e4["stage_decoding"]
    lines = [
        "# CloudShield experiment report",
        "",
        f"Generated {r['generated_at']} · model `{r['model_version']}` · {r['seconds']} s"
        + (" · **quick mode**" if r["quick"] else ""),
        "",
        "> **All data is synthetic**, produced by the CloudShield simulator (realistic CloudTrail / VPC Flow / "
        "GuardDuty records run through the production normalizers). Models are trained on one simulated "
        "organisation and evaluated on different, unseen organisations. Results show the method works on "
        "this data; they are not a measurement against real attackers.",
        "",
        "## Datasets",
        "",
        _table([
            {"set": "train", "seed": d["train"]["config"]["seed"], "days": d["train"]["config"]["days"],
             "events": d["train"]["events"], "windows": d["train"]["windows"], "scenarios": d["train"]["scenarios"]},
            {"set": "test", **{k: d["test"][k] for k in ("seed", "days", "events", "windows", "scenarios")}},
            {"set": "stealth", **{k: d["stealth"][k] for k in ("seed", "days", "events", "windows", "scenarios")}},
        ], [("set", "Set"), ("seed", "Seed"), ("days", "Days"), ("events", "Events"), ("windows", "Windows"),
            ("scenarios", "Attack scenarios")]),
        "",
        f"Thresholds: attack probability ≥ {r['thresholds']['attack_probability']}, anomaly ECDF ≥ "
        f"{r['thresholds']['anomaly_ecdf']}, correlation ≥ {r['thresholds']['correlation']}.",
        "",
        "## E1 · Detection models (window level, test set)",
        "",
        f"{e1['windows']} windows, {e1['attack_windows']} contain attack activity.",
        "",
        _table(e1["models"], [("model", "Model"), ("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"),
                              ("roc_auc", "ROC-AUC"), ("pr_auc", "PR-AUC"), ("macro_f1", "Macro-F1 (8 classes)"),
                              ("latency_ms_per_1k", "ms / 1k windows")]),
        "",
        f"False-positive rate on normal windows: XGBoost {e1['false_positive_rate']['xgboost']}, "
        f"Isolation Forest {e1['false_positive_rate']['isolation_forest']}, hybrid {e1['false_positive_rate']['hybrid']}.",
        "",
        _table(per_class, [("class", "Class"), ("support", "Windows"), ("xgboost", "XGBoost F1"),
                           ("random_forest", "Random Forest F1")]),
        "",
        "## E2 · Cross-layer alert correlation (ablation)",
        "",
        "Defaults (threshold 0.4, τ 120 min, max gap 6 h) were chosen by grid search on a separate tuning organisation (seed 8).",
        "",
        f"{e2['alerts']} alerts ({e2['attack_alerts']} from attacks, {e2['false_alerts']} false).",
        "",
        _table(e2["methods"], [("method", "Method"), ("incidents", "Incidents"), ("alert_reduction", "Alert reduction"),
                               ("pairwise_precision", "Pair precision"), ("pairwise_recall", "Pair recall"),
                               ("pairwise_f1", "Pair F1"), ("purity", "Purity"),
                               ("fragments_per_scenario", "Incidents / scenario"),
                               ("false_alert_contamination", "False-alert contamination")]),
        "",
        "## E3 · Explainability (SHAP on XGBoost)",
        "",
        f"- Explained {e3.get('explained')} correctly classified attack windows, "
        f"{e3.get('ms_per_explanation')} ms per explanation.",
        f"- Deletion test (replace top-{e3.get('deletion_k')} positive-SHAP features with the normal median): "
        f"class probability drops by **{e3.get('mean_probability_drop_top_shap')}** vs "
        f"{e3.get('mean_probability_drop_random')} for {e3.get('deletion_k')} random features "
        f"(ratio {e3.get('faithfulness_ratio')}×).",
        f"- Overlap between each local top-5 and the global top-10: {e3.get('local_global_top5_overlap')}.",
        f"- Global top features: {', '.join(e3.get('global_top_features', []))}.",
        "",
        "### E3b · LIME and DiCE",
        "",
        f"- LIME: {e3['local'].get('lime_ms')} ms per explanation, mean local R² {e3['local'].get('lime_mean_local_r2')}; "
        f"top-5 agreement with SHAP {e3['local'].get('shap_lime_top5_agreement')}.",
        f"- DiCE counterfactuals (reductions of present activity only): found for {e3['local'].get('dice_success_rate')} "
        f"of windows, changing {e3['local'].get('dice_mean_features_changed')} features on average, "
        f"{e3['local'].get('dice_ms')} ms each.",
        "",
        "## E4 · Forensic reconstruction",
        "",
        f"- Scenarios with an incident: {e4['scenarios_with_incident']} / {e4['scenarios']}",
        f"- Mean timeline completeness (share of the scenario's events inside its incident): {e4['mean_completeness']}",
        f"- Mean entity recall of the attack graph (attacker IP, identities, keys, resources): {e4['mean_entity_recall']}",
        f"- Top-3 ranked graph nodes include the attacker IP or a compromised identity: {e4['top3_node_hit_rate']}",
        "",
        _table([
            {"decoder": "HMM (Viterbi)", "stage": sd["hmm_attack_stage_accuracy"], "binary": sd["hmm_attack_vs_normal_accuracy"]},
            {"decoder": "Static rule (observation → stage)", "stage": sd["rule_attack_stage_accuracy"],
             "binary": sd["rule_attack_vs_normal_accuracy"]},
        ], [("decoder", "Stage decoder"), ("stage", "Exact stage accuracy (attack events)"),
            ("binary", "Attack-vs-normal accuracy (all incident events)")]),
        "",
        "### E4b · Sequence models for stage decoding (per-entity sessions, test organisation)",
        "",
        _table(e4["sequence_models"]["models"], [("model", "Model"), ("parameters", "Parameters"),
                                                 ("train_seconds", "Train s"), ("attack_stage_accuracy", "Attack stage acc."),
                                                 ("attack_detected_as_attack", "Attack events flagged"),
                                                 ("normal_kept_normal", "Normal kept normal")]),
        "",
        "## E5 · Risk scoring and response",
        "",
        f"- Incidents: {e5['incidents']} ({e5['attack_incidents']} contain attack activity, {e5['benign_incidents']} benign)",
        f"- Risk score as attack-incident classifier: ROC-AUC **{e5['risk_auc_attack_vs_benign']}** "
        f"(mean risk {e5['mean_risk_attack']} attack vs {e5['mean_risk_benign']} benign)",
        f"- Attack incidents rated HIGH/CRITICAL: {e5['attack_incidents_high_or_critical']}; "
        f"benign HIGH/CRITICAL incidents per day: {e5['benign_high_or_critical_per_day']}",
        f"- Median detection delay (scenario start → first alert window closes; excludes pipeline run cadence): {e5['median_detection_delay_minutes']} min",
        f"- Recommended actions: {e5['recommended_actions']}; automatable actions planned in dry-run: "
        f"{e5['automatable_actions_planned']} (failed: {e5['automatable_actions_failed_to_plan']})",
        "",
        "### E5b · Reinforcement-learning response simulator (offline)",
        "",
        f"Reward model: {e5['reinforcement_learning']['reward_model']}. Trained on "
        f"{e5['reinforcement_learning']['train_incidents']} incidents, evaluated on {e5['reinforcement_learning']['test_incidents']}.",
        "",
        _table(e5["reinforcement_learning"]["strategies"], [("strategy", "Strategy"), ("mean_reward", "Mean reward"),
                                                            ("attack_containment_rate", "Attacks contained"),
                                                            ("benign_disruption_rate", "Benign disrupted")]),
        "",
        "### Detection by scenario type (test set)",
        "",
        _table(r["per_kind"], [("kind", "Scenario"), ("scenarios", "n"), ("detected", "Detected"),
                               ("high_or_critical", "HIGH/CRITICAL"), ("mean_completeness", "Completeness"),
                               ("median_delay_min", "Median delay (min)")]),
        "",
        "## E6 · Robustness to stealthy attacks",
        "",
        f"Dataset: {e6['dataset']}.",
        "",
        _table([{"model": m, "stealth": v, "test": e6["baseline_window_recall"].get(m)}
                for m, v in e6["window_recall"].items()],
               [("model", "Model"), ("test", "Window recall (test)"), ("stealth", "Window recall (stealth)")]),
        "",
        f"Scenario detection rate under stealth: {e6['scenario_detection_rate']}; reaching HIGH/CRITICAL: "
        f"{e6['scenarios_reaching_high']}.",
        "",
        _table(e6["per_kind"], [("kind", "Scenario"), ("scenarios", "n"), ("detected", "Detected"),
                                ("high_or_critical", "HIGH/CRITICAL"), ("mean_completeness", "Completeness")]),
        "",
    ]
    return "\n".join(lines)
