"""Phase 13: research experiments (E1-E6).

Models are trained on one simulated organisation (seed 7) and evaluated on *different* simulated
organisations (seeds 99 and 123) whose principals, timings and attack instances were never seen in
training. All numbers come from synthetic data and must be reported as such.
"""

import json
import logging
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score, roc_auc_score

from app.analysis.correlation import CorrelationConfig, correlate
from app.analysis.engine import AnalysisConfig, AnalysisEngine
from app.core.config import Settings
from app.experiments.report import render_markdown
from app.ml.explain import Explainer
from app.ml.features import to_rows
from app.ml.taxonomy import ATTACK_CLASSES, STAGES
from app.ml.training import LabelledData, TrainingConfig, binary_metrics, build_labelled_data, train
from app.response.executor import ExecutionError, ResponseExecutor

log = logging.getLogger(__name__)

RULE_STAGE = {
    "LOGIN_FAILURE": "CREDENTIAL_ACCESS", "LOGIN_SUCCESS": "INITIAL_ACCESS", "DISCOVERY": "DISCOVERY",
    "ACCESS_DENIED": "DISCOVERY", "CREDENTIAL_CHANGE": "PERSISTENCE", "PRIVILEGE_CHANGE": "PRIVILEGE_ESCALATION",
    "FIREWALL_EXPOSURE": "DEFENSE_EVASION", "DEFENSE_EVASION": "DEFENSE_EVASION", "DATA_ACCESS": "EXFILTRATION",
    "DATA_EXPOSURE": "EXFILTRATION", "FLOW_LARGE_OUT": "EXFILTRATION", "COMPUTE_PROVISION": "IMPACT",
}


def _r(x: float, n: int = 4) -> float:
    return round(float(x), n)


# ------------------------------------------------------------------ E1
def e1_models(bundle, data: LabelledData, anomaly_threshold: float) -> dict:
    X, y = data.X, data.y
    attack = (y != 0).astype(int)
    out = {"windows": int(len(X)), "attack_windows": int(attack.sum()), "models": [], "per_class_f1": {}}

    t = time.perf_counter(); anomaly = bundle.anomaly_score(X); t_if = time.perf_counter() - t
    t = time.perf_counter(); px = bundle.class_proba(X); t_x = time.perf_counter() - t
    t = time.perf_counter(); pr = bundle.rf_proba(X); t_r = time.perf_counter() - t
    per_1k = lambda s: _r(1000 * 1000 * s / len(X), 3)  # noqa: E731  ms per 1000 windows

    out["models"].append({"model": "Isolation Forest (unsupervised)", **binary_metrics(attack, anomaly, anomaly_threshold),
                          "macro_f1": None, "latency_ms_per_1k": per_1k(t_if)})
    out["models"].append({"model": "Random Forest (baseline)", **binary_metrics(attack, 1 - pr[:, 0], 0.5),
                          "macro_f1": _r(f1_score(y, pr.argmax(1), average="macro")), "latency_ms_per_1k": per_1k(t_r)})
    out["models"].append({"model": "XGBoost", **binary_metrics(attack, 1 - px[:, 0], 0.5),
                          "macro_f1": _r(f1_score(y, px.argmax(1), average="macro")), "latency_ms_per_1k": per_1k(t_x)})
    hybrid_pred = ((1 - px[:, 0]) >= 0.5) | (anomaly >= anomaly_threshold)
    hybrid_score = np.maximum(1 - px[:, 0], anomaly)
    hb = binary_metrics(attack, hybrid_pred.astype(float), 0.5)
    hb.update({k: v for k, v in binary_metrics(attack, hybrid_score, 0.5).items() if k in ("roc_auc", "pr_auc")})
    out["models"].append({"model": "Hybrid (XGBoost OR Isolation Forest)", **hb, "macro_f1": None,
                          "latency_ms_per_1k": per_1k(t_x + t_if)})

    labels = list(range(len(ATTACK_CLASSES)))
    fx = f1_score(y, px.argmax(1), labels=labels, average=None, zero_division=0)
    fr = f1_score(y, pr.argmax(1), labels=labels, average=None, zero_division=0)
    support = Counter(y.tolist())
    for i, cls in enumerate(ATTACK_CLASSES):
        out["per_class_f1"][cls] = {"xgboost": _r(fx[i]), "random_forest": _r(fr[i]), "support": support.get(i, 0)}
    out["false_positive_rate"] = {
        "xgboost": _r(((1 - px[:, 0]) >= 0.5)[attack == 0].mean()),
        "isolation_forest": _r((anomaly >= anomaly_threshold)[attack == 0].mean()),
        "hybrid": _r(hybrid_pred[attack == 0].mean()),
    }
    return out


# ------------------------------------------------------------------ E2
def _alert_truth(alerts, labels) -> list[str | None]:
    truth = []
    for a in alerts:
        scen = Counter(labels[e].scenario_id for e in a.event_ids if e in labels and labels[e].scenario_id)
        truth.append(scen.most_common(1)[0][0] if scen else None)
    return truth


def _clustering_quality(groups: list[list[int]], truth: list[str | None]) -> dict:
    pred_pairs = {(a, b) for g in groups for a, b in combinations(sorted(g), 2)}
    by_scen = defaultdict(list)
    for i, s in enumerate(truth):
        if s:
            by_scen[s].append(i)
    true_pairs = {(a, b) for idx in by_scen.values() for a, b in combinations(sorted(idx), 2)}
    tp = len(pred_pairs & true_pairs)
    precision = tp / len(pred_pairs) if pred_pairs else 1.0
    recall = tp / len(true_pairs) if true_pairs else 1.0
    attack_groups = [g for g in groups if any(truth[i] for i in g)]
    purity_num = sum(max(Counter(truth[i] for i in g).values()) for g in attack_groups)
    purity_den = sum(len(g) for g in attack_groups)
    group_of = {i: gi for gi, g in enumerate(groups) for i in g}
    fragments = [len({group_of[i] for i in idx}) for idx in by_scen.values()]
    false_alerts = [i for i, s in enumerate(truth) if s is None]
    contaminated = sum(1 for i in false_alerts if any(truth[j] for j in groups[group_of[i]]))
    return {
        "incidents": len(groups),
        "alert_reduction": _r(1 - len(groups) / max(1, len(truth))),
        "pairwise_precision": _r(precision), "pairwise_recall": _r(recall),
        "pairwise_f1": _r(2 * precision * recall / (precision + recall) if precision + recall else 0.0),
        "purity": _r(purity_num / purity_den if purity_den else 1.0),
        "fragments_per_scenario": _r(np.mean(fragments) if fragments else 0.0, 2),
        "false_alert_contamination": _r(contaminated / len(false_alerts) if false_alerts else 0.0),
    }


def e2_correlation(alerts, labels) -> dict:
    truth = _alert_truth(alerts, labels)
    methods = {
        "No correlation (one incident per alert)": None,
        "Temporal only (≈5 min window)": CorrelationConfig(threshold=0.25, use_entities=False, use_stage=False,
                                                          require_shared_entity=False),
        "Entity matching only": CorrelationConfig(threshold=0.0, use_temporal=False, use_stage=False,
                                                  common_entity_limit=10**6),
        "Weighted similarity (no commonness filter, no stage)": CorrelationConfig(common_entity_limit=10**6,
                                                                                use_stage=False),
        "CloudShield hybrid (full)": CorrelationConfig(),
    }
    results = []
    for name, cfg in methods.items():
        t = time.perf_counter()
        groups = [[i] for i in range(len(alerts))] if cfg is None else [g.alert_indices for g in correlate(alerts, cfg)]
        results.append({"method": name, **_clustering_quality(groups, truth),
                        "latency_ms": _r(1000 * (time.perf_counter() - t), 1)})
    return {"alerts": len(alerts), "attack_alerts": sum(1 for t in truth if t),
            "false_alerts": sum(1 for t in truth if t is None), "methods": results}


# ------------------------------------------------------------------ E3
def e3_explainability(bundle, data: LabelledData, seed: int, k: int = 3) -> dict:
    px = bundle.class_proba(data.X)
    pred = px.argmax(1)
    idx = np.flatnonzero((pred == data.y) & (data.y != 0))
    rng = np.random.default_rng(seed)
    if len(idx) > 200:
        idx = rng.choice(idx, 200, replace=False)
    if len(idx) == 0:
        return {"explained": 0}
    explainer = Explainer(bundle)
    X = data.X.iloc[idx]
    t = time.perf_counter()
    expl = explainer.explain(X, data.windows.iloc[idx], [int(pred[i]) for i in idx], top_k=len(bundle.feature_names))
    seconds = time.perf_counter() - t
    baseline = data.X[data.y == 0].median()
    global_top = {g["feature"] for g in bundle.metadata.get("global_importance", [])[:10]}

    drops_shap, drops_rand, overlaps = [], [], []
    feats = bundle.feature_names
    for row, (i, e) in enumerate(zip(idx, expl)):
        cls = int(pred[i])
        p0 = px[i, cls]
        top = [f["feature"] for f in e["features"] if f["shap"] > 0][:k]
        x = X.iloc[[row]].copy()
        x[top] = baseline[top].values
        drops_shap.append(p0 - bundle.class_proba(x)[0, cls])
        rand_drops = []
        for _ in range(5):
            rnd = list(rng.choice(feats, k, replace=False))
            xr = X.iloc[[row]].copy()
            xr[rnd] = baseline[rnd].values
            rand_drops.append(p0 - bundle.class_proba(xr)[0, cls])
        drops_rand.append(np.mean(rand_drops))
        top5 = {f["feature"] for f in e["features"][:5]}
        overlaps.append(len(top5 & global_top) / 5)
    return {
        "explained": int(len(idx)),
        "ms_per_explanation": _r(1000 * seconds / len(idx), 2),
        "deletion_k": k,
        "mean_probability_drop_top_shap": _r(np.mean(drops_shap)),
        "mean_probability_drop_random": _r(np.mean(drops_rand)),
        "faithfulness_ratio": _r(np.mean(drops_shap) / max(1e-9, np.mean(drops_rand)), 2),
        "local_global_top5_overlap": _r(np.mean(overlaps)),
        "global_top_features": [g["feature"] for g in bundle.metadata.get("global_importance", [])[:10]],
    }


# ------------------------------------------------------------------ E4 / E5
def _scenario_events(labels) -> dict[str, set[str]]:
    out = defaultdict(set)
    for eid, lab in labels.items():
        if lab.scenario_id:
            out[lab.scenario_id].add(eid)
    return out


def e4_e5_forensics_response(result, data: LabelledData, settings: Settings) -> tuple[dict, dict, list[dict]]:
    labels = data.labels
    scen_events = _scenario_events(labels)
    cutoff = data.score_from
    per_scenario = []
    hmm_attack_correct = hmm_attack_total = hmm_binary_correct = hmm_total = 0
    rule_attack_correct = rule_binary_correct = 0
    rows_by_id = {r.event_id: r for r in to_rows(data.events)}

    for info in data.dataset.scenarios:
        events = {e for e in scen_events.get(info.scenario_id, set()) if rows_by_id[e].ts >= cutoff.timestamp()}
        if not events:
            continue
        hits = [(len(events & set(inc.event_ids)), inc) for inc in result.incidents]
        overlap, best = max(hits, key=lambda h: h[0], default=(0, None))
        alerts_hit = [a for a in result.alerts if events & set(a.event_ids)]
        entry = {"scenario_id": info.scenario_id, "kind": info.kind, "stealthy": info.stealthy,
                 "detected": bool(alerts_hit), "events": len(events)}
        if best is not None and overlap:
            node_labels = {n["label"] for n in best.graph["nodes"]}
            truth = info.identities | info.keys | info.ips | info.resources
            top3 = {n["label"] for n in best.graph["nodes"][:3]}
            entry.update(
                risk=best.risk["score"], level=best.risk["level"], incident_alerts=len(best.alerts),
                completeness=_r(overlap / len(events)),
                entity_recall=_r(len(truth & node_labels) / len(truth)) if truth else None,
                top3_hit=bool(top3 & (info.identities | {info.attacker_ip})),
                delay_minutes=_r((min(a.available_at for a in alerts_hit) - info.start).total_seconds() / 60, 1),
                actions=len(best.recommendations),
            )
            stage_of = {s["event_id"]: s["stage"] for s in best.sequence}
            for eid, decoded in stage_of.items():
                true_stage = labels[eid].stage if eid in labels else "NORMAL"
                rule_stage = RULE_STAGE.get(rows_by_id[eid].observation, "NORMAL")
                hmm_total += 1
                hmm_binary_correct += (decoded == "NORMAL") == (true_stage == "NORMAL")
                rule_binary_correct += (rule_stage == "NORMAL") == (true_stage == "NORMAL")
                if true_stage != "NORMAL":
                    hmm_attack_total += 1
                    hmm_attack_correct += decoded == true_stage
                    rule_attack_correct += rule_stage == true_stage
        per_scenario.append(entry)

    detected = [s for s in per_scenario if s.get("completeness")]
    e4 = {
        "scenarios": len(per_scenario),
        "scenarios_with_incident": len(detected),
        "mean_completeness": _r(np.mean([s["completeness"] for s in detected])) if detected else None,
        "mean_entity_recall": _r(np.mean([s["entity_recall"] for s in detected if s["entity_recall"] is not None])) if detected else None,
        "top3_node_hit_rate": _r(np.mean([s["top3_hit"] for s in detected])) if detected else None,
        "stage_decoding": {
            "events": hmm_total,
            "hmm_attack_stage_accuracy": _r(hmm_attack_correct / hmm_attack_total) if hmm_attack_total else None,
            "rule_attack_stage_accuracy": _r(rule_attack_correct / hmm_attack_total) if hmm_attack_total else None,
            "hmm_attack_vs_normal_accuracy": _r(hmm_binary_correct / hmm_total) if hmm_total else None,
            "rule_attack_vs_normal_accuracy": _r(rule_binary_correct / hmm_total) if hmm_total else None,
        },
    }

    attack_ids = set().union(*scen_events.values()) if scen_events else set()
    is_attack = [bool(attack_ids & set(inc.event_ids)) for inc in result.incidents]
    risks = [inc.risk["score"] for inc in result.incidents]
    days = max(1.0, (data.dataset.end - cutoff).total_seconds() / 86400)
    high = [inc.risk["level"] in ("HIGH", "CRITICAL") for inc in result.incidents]
    executor = ResponseExecutor(Settings(response_mode="dry_run"))
    planned = failed = 0
    action_types = Counter()
    for inc in result.incidents:
        for act in inc.recommendations:
            action_types[act["action_type"]] += 1
            if act["automatable"]:
                try:
                    executor.plan(act["action_type"], act["target"])
                    planned += 1
                except (ExecutionError, KeyError):
                    failed += 1
    e5 = {
        "incidents": len(result.incidents),
        "attack_incidents": int(sum(is_attack)),
        "benign_incidents": int(len(is_attack) - sum(is_attack)),
        "risk_auc_attack_vs_benign": _r(roc_auc_score(is_attack, risks)) if 0 < sum(is_attack) < len(is_attack) else None,
        "mean_risk_attack": _r(np.mean([r for r, a in zip(risks, is_attack) if a]), 1) if any(is_attack) else None,
        "mean_risk_benign": _r(np.mean([r for r, a in zip(risks, is_attack) if not a]), 1) if not all(is_attack) else None,
        "attack_incidents_high_or_critical": _r(np.mean([h for h, a in zip(high, is_attack) if a])) if any(is_attack) else None,
        "benign_high_or_critical_per_day": _r(sum(h for h, a in zip(high, is_attack) if not a) / days, 2),
        "scenarios_reaching_high": _r(np.mean([s.get("level") in ("HIGH", "CRITICAL") for s in per_scenario])) if per_scenario else None,
        "median_detection_delay_minutes": _r(np.median([s["delay_minutes"] for s in detected]), 1) if detected else None,
        "recommended_actions": dict(action_types),
        "automatable_actions_planned": planned,
        "automatable_actions_failed_to_plan": failed,
    }
    return e4, e5, per_scenario


def _kind_table(per_scenario: list[dict]) -> list[dict]:
    by_kind = defaultdict(list)
    for s in per_scenario:
        by_kind[s["kind"]].append(s)
    table = []
    for kind, items in sorted(by_kind.items()):
        det = [s for s in items if s.get("completeness")]
        table.append({
            "kind": kind, "scenarios": len(items),
            "detected": _r(np.mean([s["detected"] for s in items]), 2),
            "high_or_critical": _r(np.mean([s.get("level") in ("HIGH", "CRITICAL") for s in items]), 2),
            "mean_completeness": _r(np.mean([s["completeness"] for s in det]), 2) if det else None,
            "median_delay_min": _r(np.median([s["delay_minutes"] for s in det]), 1) if det else None,
        })
    return table


# ------------------------------------------------------------------ E6
def e6_robustness(bundle, engine: AnalysisEngine, normal_test: dict, stealth: LabelledData, threshold: float) -> dict:
    window_metrics = e1_models(bundle, stealth, threshold)
    result = engine.analyze(stealth.events, score_from=stealth.score_from)
    _, e5, per_scenario = e4_e5_forensics_response(result, stealth, Settings())
    return {
        "dataset": "all attacks stealthy (known IP & user agent, MFA, actions spread over hours)",
        "window_recall": {m["model"]: m["recall"] for m in window_metrics["models"]},
        "baseline_window_recall": normal_test,
        "scenario_detection_rate": _r(np.mean([s["detected"] for s in per_scenario]), 3) if per_scenario else None,
        "scenarios_reaching_high": e5["scenarios_reaching_high"],
        "per_kind": _kind_table(per_scenario),
    }


# ------------------------------------------------------------------ runner
def run_experiments(settings: Settings, quick: bool = False) -> dict:
    random.seed(0)
    t0 = time.time()
    train_cfg = TrainingConfig(days=20 if quick else 30)
    bundle = train(train_cfg)
    thr = settings.anomaly_alert_threshold
    test = build_labelled_data(99, 7 if quick else 14, 3.0, 0.25, 15, start=datetime(2026, 12, 1, tzinfo=timezone.utc))
    stealth = build_labelled_data(123, 5 if quick else 10, 3.0, 1.0, 15, start=datetime(2027, 1, 1, tzinfo=timezone.utc))
    log.info("datasets ready (%.1fs)", time.time() - t0)

    engine = AnalysisEngine(bundle, AnalysisConfig(anomaly_threshold=thr, explain=False))
    e1 = e1_models(bundle, test, thr)
    windows, alerts = engine.detect(test.rows, test.score_from)
    e2 = e2_correlation(alerts, test.labels)
    e3 = e3_explainability(bundle, test, seed=0)
    result = engine.analyze(test.events, score_from=test.score_from)
    e4, e5, per_scenario = e4_e5_forensics_response(result, test, settings)
    e6 = e6_robustness(bundle, engine, {m["model"]: m["recall"] for m in e1["models"]}, stealth, thr)

    def describe(d: LabelledData, purpose: str) -> dict:
        return {"purpose": purpose, "seed": d.dataset.seed, "days": (d.dataset.end - d.dataset.start).days,
                "events": len(d.events), "windows": int(len(d.windows)), "attack_windows": int((d.y != 0).sum()),
                "scenarios": len(d.dataset.scenarios),
                "scenario_kinds": dict(Counter(s.kind for s in d.dataset.scenarios))}

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "quick": quick,
        "seconds": None,
        "model_version": bundle.version,
        "thresholds": {"attack_probability": 0.5, "anomaly_ecdf": thr, "correlation": CorrelationConfig().threshold},
        "datasets": {
            "train": bundle.metadata["training"],
            "test": describe(test, "held-out organisation, 25% stealthy attacks"),
            "stealth": describe(stealth, "robustness: 100% stealthy attacks"),
        },
        "e1_model_comparison": e1,
        "e2_correlation": e2,
        "e3_explainability": e3,
        "e4_forensics": e4,
        "e5_risk_and_response": e5,
        "e6_robustness": e6,
        "per_kind": _kind_table(per_scenario),
        "per_scenario": per_scenario,
    }
    report["seconds"] = round(time.time() - t0, 1)
    out = Path(settings.reports_dir)
    out.mkdir(parents=True, exist_ok=True)
    report["paths"] = {"json": str(out / "experiments.json"), "markdown": str(out / "experiments.md")}
    (out / "experiments.json").write_text(json.dumps(report, indent=2, default=str))
    (out / "experiments.md").write_text(render_markdown(report))
    return report
