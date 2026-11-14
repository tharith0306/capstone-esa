"""Network-intrusion experiment on public datasets (design: TON_IoT, UNSW-NB15, CIC-IDS2017).

These datasets contain *network flow* records, not cloud API activity, so they validate only the
network-detection part of the method (IF / RF / XGBoost on flow features). They say nothing about
IAM or CloudTrail attacks, and results are reported separately from the cloud experiments.

Expected files (place them under ml_training/datasets/, they are git-ignored):
  unsw    UNSW_NB15_training-set.csv + UNSW_NB15_testing-set.csv   (label, attack_cat)
  ton_iot train_test_network.csv                                    (label, type)
  cicids  one or more MachineLearningCVE/*.csv                      (" Label")
"""

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# Columns that identify hosts/sessions or leak the label; dropped to avoid entity memorisation.
LEAKY = {"id", "srcip", "dstip", "src_ip", "dst_ip", "sport", "dsport", "src_port", "dst_port", "ts", "stime",
         "ltime", "flow id", "source ip", "destination ip", "source port", "timestamp", "attack_cat", "type",
         "label", "dns_query", "ssl_subject", "ssl_issuer", "http_uri", "http_user_agent"}


def _read(paths: list[Path], max_rows: int | None) -> pd.DataFrame:
    frames = [pd.read_csv(p, low_memory=False, nrows=max_rows) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    return df


def load(name: str, directory: str | Path, max_rows: int | None = None) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    d = Path(directory)
    if name == "unsw":
        df = _read(sorted(d.glob("UNSW_NB15_*ing-set.csv")), max_rows)
        y_bin, y_cat = df["label"].astype(int).to_numpy(), df["attack_cat"].fillna("Normal").astype(str).to_numpy()
    elif name == "ton_iot":
        df = _read(sorted(d.glob("train_test_network*.csv")), max_rows)
        y_bin, y_cat = df["label"].astype(int).to_numpy(), df["type"].astype(str).to_numpy()
    elif name == "cicids":
        df = _read(sorted(d.glob("*.csv")), max_rows)
        y_cat = df["Label"].astype(str).str.strip().to_numpy()
        y_bin = (y_cat != "BENIGN").astype(int)
    else:
        raise ValueError("dataset must be unsw, ton_iot or cicids")
    if df.empty:
        raise FileNotFoundError(f"no {name} CSV files found in {d}")
    X = df[[c for c in df.columns if c.lower() not in LEAKY]]
    categorical = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]  # pandas 3: 'str' dtype
    X = pd.get_dummies(X, columns=categorical, dummy_na=False)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).astype(float)
    return X, y_bin, y_cat


def run_public_experiment(name: str, directory: str | Path, out_dir: str | Path, max_rows: int | None = None,
                          seed: int = 0) -> dict:
    X, y, y_cat = load(name, directory, max_rows)
    X_tr, X_te, y_tr, y_te, c_tr, c_te = train_test_split(X, y, y_cat, test_size=0.3, stratify=y, random_state=seed)
    results = []

    def record(model: str, score: np.ndarray, pred: np.ndarray, seconds: float) -> None:
        results.append({"model": model,
                        "precision": round(float(precision_score(y_te, pred, zero_division=0)), 4),
                        "recall": round(float(recall_score(y_te, pred, zero_division=0)), 4),
                        "f1": round(float(f1_score(y_te, pred, zero_division=0)), 4),
                        "roc_auc": round(float(roc_auc_score(y_te, score)), 4),
                        "pr_auc": round(float(average_precision_score(y_te, score)), 4),
                        "train_seconds": round(seconds, 1)})

    t = time.time()
    iforest = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(X_tr[y_tr == 0])
    raw_tr = -iforest.score_samples(X_tr[y_tr == 0])
    threshold = np.quantile(raw_tr, 0.99)
    raw = -iforest.score_samples(X_te)
    record("Isolation Forest (normal-only)", raw, raw >= threshold, time.time() - t)

    t = time.time()
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, class_weight="balanced_subsample",
                                random_state=seed, n_jobs=-1).fit(X_tr, y_tr)
    p = rf.predict_proba(X_te)[:, 1]
    record("Random Forest", p, p >= 0.5, time.time() - t)

    t = time.time()
    xgb = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
                        tree_method="hist", random_state=seed, n_jobs=-1,
                        scale_pos_weight=float((y_tr == 0).sum() / max(1, (y_tr == 1).sum()))).fit(X_tr, y_tr)
    p = xgb.predict_proba(X_te)[:, 1]
    record("XGBoost", p, p >= 0.5, time.time() - t)

    pred = p >= 0.5
    per_category = []
    for cat in sorted(set(c_te)):
        mask = c_te == cat
        per_category.append({"category": cat, "n": int(mask.sum()),
                             "detected_or_correct": round(float((pred[mask] == y_te[mask]).mean()), 4)})
    report = {"dataset": name, "rows": int(len(X)), "features": int(X.shape[1]),
              "attack_share": round(float(y.mean()), 4), "split": "stratified 70/30", "models": results,
              "xgboost_by_category": per_category,
              "note": "Network-flow data only: validates network detection, not cloud API / IAM detection."}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"public_{name}.json").write_text(json.dumps(report, indent=2))
    lines = [f"# Public dataset experiment: {name}", "", report["note"], "",
             f"{report['rows']} rows, {report['features']} features, {report['attack_share']:.1%} attacks, {report['split']}.", "",
             "| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC | Train s |", "|---|---|---|---|---|---|---|"]
    lines += [f"| {r['model']} | {r['precision']} | {r['recall']} | {r['f1']} | {r['roc_auc']} | {r['pr_auc']} | {r['train_seconds']} |"
              for r in results]
    lines += ["", "| Category | n | XGBoost correct |", "|---|---|---|"]
    lines += [f"| {c['category']} | {c['n']} | {c['detected_or_correct']} |" for c in per_category]
    (out / f"public_{name}.md").write_text("\n".join(lines) + "\n")
    return report
