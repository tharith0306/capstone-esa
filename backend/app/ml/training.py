"""Train the detection models on a simulated, labelled AWS dataset."""

import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from app.analysis.inventory import Inventory
from app.ml.explain import Explainer
from app.ml.features import FEATURES, build_windows, model_matrix, to_rows
from app.ml.hmm import StageHMM, labelled_sequences
from app.ml.models import ModelBundle
from app.ml.taxonomy import ATTACK_CLASSES
from app.processing.hashing import sha256_hex
from app.simulation.generator import generate_dataset, normalize_dataset

log = logging.getLogger(__name__)


@dataclass
class TrainingConfig:
    seed: int = 7
    days: int = 30
    attacks_per_day: float = 6.0
    stealthy_fraction: float = 0.2
    window_minutes: int = 15
    validation_fraction: float = 0.2


@dataclass
class LabelledData:
    windows: pd.DataFrame
    X: pd.DataFrame
    y: np.ndarray
    rows: list
    labels: dict
    dataset: object
    events: list
    score_from: datetime
    inventory: object = None


def build_labelled_data(seed: int, days: int, attacks_per_day: float, stealthy_fraction: float,
                        window_minutes: int, start: datetime | None = None) -> LabelledData:
    dataset = generate_dataset(seed=seed, days=days, attacks_per_day=attacks_per_day,
                               stealthy_fraction=stealthy_fraction, start=start)
    events, labels = normalize_dataset(dataset)
    inventory = Inventory.from_records(dataset.inventory)
    rows = to_rows(events, inventory)
    # Skip the first day so no window is scored before identities have any history.
    score_from = dataset.start + timedelta(days=1)
    windows = build_windows(rows, window_minutes, score_from=score_from, labels=labels)
    X = model_matrix(windows)
    y = windows["label"].map({c: i for i, c in enumerate(ATTACK_CLASSES)}).to_numpy()
    return LabelledData(windows, X, y, rows, labels, dataset, events, score_from, inventory)


def make_xgb(seed: int) -> XGBClassifier:
    return XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
        objective="multi:softprob", eval_metric="mlogloss", tree_method="hist", random_state=seed, n_jobs=-1)


def make_rf(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=300, max_depth=20, min_samples_split=5,
                                  class_weight="balanced_subsample", random_state=seed, n_jobs=-1)


def make_iforest(seed: int) -> IsolationForest:
    return IsolationForest(n_estimators=200, max_samples="auto", contamination="auto", random_state=seed, n_jobs=-1)


def binary_metrics(y_true_attack: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    pred = score >= threshold
    out = {
        "precision": round(float(precision_score(y_true_attack, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true_attack, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true_attack, pred, zero_division=0)), 4),
    }
    if len(set(y_true_attack)) > 1:
        out["roc_auc"] = round(float(roc_auc_score(y_true_attack, score)), 4)
        out["pr_auc"] = round(float(average_precision_score(y_true_attack, score)), 4)
    return out


def train(config: TrainingConfig | None = None) -> ModelBundle:
    config = config or TrainingConfig()
    t0 = time.time()
    data = build_labelled_data(config.seed, config.days, config.attacks_per_day, config.stealthy_fraction,
                               config.window_minutes)
    missing = set(range(len(ATTACK_CLASSES))) - set(data.y.tolist())
    if missing:
        raise RuntimeError(f"training data lacks classes {[ATTACK_CLASSES[i] for i in missing]}; add attacks")

    # Time-based split: the last 20% of the period validates (no window from the future in training).
    cut = data.windows["window_start"].quantile(1 - config.validation_fraction)
    train_idx = (data.windows["window_start"] < cut).to_numpy()
    val_idx = ~train_idx
    X_tr, y_tr, X_val, y_val = data.X[train_idx], data.y[train_idx], data.X[val_idx], data.y[val_idx]
    log.info("training windows=%d validation windows=%d", len(X_tr), len(X_val))

    iforest = make_iforest(config.seed).fit(X_tr[y_tr == 0])
    reference = np.sort(-iforest.score_samples(X_val[y_val == 0]))

    weights = compute_sample_weight("balanced", y_tr)
    xgb = make_xgb(config.seed).fit(X_tr, y_tr, sample_weight=weights)
    rf = make_rf(config.seed).fit(X_tr, y_tr)

    # Validation metrics before refitting on everything.
    attack_val = (y_val != 0).astype(int)
    xgb_proba = xgb.predict_proba(X_val)
    rf_proba = rf.predict_proba(X_val)
    if_score = np.searchsorted(reference, -iforest.score_samples(X_val), side="right") / len(reference)
    labels_present = sorted(set(y_val.tolist()) | set(xgb_proba.argmax(1).tolist()))
    validation = {
        "windows": int(len(X_val)),
        "attack_windows": int(attack_val.sum()),
        "xgboost": {
            "macro_f1": round(float(f1_score(y_val, xgb_proba.argmax(1), average="macro")), 4),
            "binary": binary_metrics(attack_val, 1 - xgb_proba[:, 0], 0.5),
            "per_class": classification_report(
                y_val, xgb_proba.argmax(1), labels=labels_present,
                target_names=[ATTACK_CLASSES[i] for i in labels_present], output_dict=True, zero_division=0),
        },
        "random_forest": {
            "macro_f1": round(float(f1_score(y_val, rf_proba.argmax(1), average="macro")), 4),
            "binary": binary_metrics(attack_val, 1 - rf_proba[:, 0], 0.5),
        },
        "isolation_forest": {"binary": binary_metrics(attack_val, if_score, 0.99)},
    }

    # Final supervised models use all labelled windows.
    xgb = make_xgb(config.seed).fit(data.X, data.y, sample_weight=compute_sample_weight("balanced", data.y))
    rf = make_rf(config.seed).fit(data.X, data.y)
    stage_hmm = StageHMM.fit_supervised(labelled_sequences(data.rows, data.labels))

    trained_at = datetime.now(timezone.utc)
    fingerprint = sha256_hex(f"{asdict(config)}{len(data.windows)}{int(data.y.sum())}".encode())[:8]
    bundle = ModelBundle(
        version=f"{trained_at:%Y%m%d-%H%M}-{fingerprint}",
        trained_at=trained_at.isoformat(),
        feature_names=list(FEATURES),
        classes=list(ATTACK_CLASSES),
        iforest=iforest, xgb=xgb, rf=rf, hmm=stage_hmm,
        anomaly_reference=reference,
    )

    bg_attack = data.X[data.y != 0].sample(min(400, int((data.y != 0).sum())), random_state=config.seed)
    bg_normal = data.X[data.y == 0].sample(800, random_state=config.seed)
    bundle.background = pd.concat([bg_attack, bg_normal])
    bundle.background_labels = data.y[bundle.background.index.to_numpy()]
    sample = pd.concat([
        data.X[data.y != 0].sample(min(300, int((data.y != 0).sum())), random_state=config.seed),
        data.X[data.y == 0].sample(300, random_state=config.seed),
    ])
    class_counts = pd.Series(data.y).map(dict(enumerate(ATTACK_CLASSES))).value_counts().to_dict()
    bundle.metadata = {
        "training": {
            "config": asdict(config),
            "data": "CloudShield simulator (synthetic, labelled); see ml_training/README.md",
            "events": len(data.rows),
            "windows": int(len(data.windows)),
            "scenarios": len(data.dataset.scenarios),
            "class_counts": {k: int(v) for k, v in class_counts.items()},
            "seconds": round(time.time() - t0, 1),
        },
        "validation": validation,
        "global_importance": Explainer(bundle).global_importance(sample)[:20],
        "xgboost_gain_importance": dict(sorted(
            ((k, round(float(v), 3)) for k, v in xgb.get_booster().get_score(importance_type="gain").items()),
            key=lambda kv: -kv[1])[:20]),
    }
    log.info("trained %s in %.1fs", bundle.version, time.time() - t0)
    return bundle
