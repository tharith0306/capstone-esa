"""The trained model bundle: Isolation Forest, XGBoost, Random Forest baseline and the stage HMM."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier

from app.ml.hmm import StageHMM

BUNDLE_FILE = "bundle.joblib"
METADATA_FILE = "metadata.json"


@dataclass
class ModelBundle:
    version: str
    trained_at: str
    feature_names: list[str]
    classes: list[str]
    iforest: IsolationForest
    xgb: XGBClassifier
    rf: RandomForestClassifier
    hmm: StageHMM
    anomaly_reference: np.ndarray  # sorted raw IF scores of held-out normal windows
    metadata: dict[str, Any] = field(default_factory=dict)
    # stratified sample of training windows (model space) + labels, for LIME and DiCE
    background: pd.DataFrame | None = None
    background_labels: np.ndarray | None = None

    # ---------- inference ----------
    def raw_anomaly(self, X: pd.DataFrame) -> np.ndarray:
        return -self.iforest.score_samples(X[self.feature_names])

    def anomaly_score(self, X: pd.DataFrame) -> np.ndarray:
        """Empirical CDF of the raw Isolation Forest score over held-out *normal* windows.

        0.99 means "more anomalous than 99% of normal activity". It is not a probability of attack.
        """
        raw = self.raw_anomaly(X)
        return np.searchsorted(self.anomaly_reference, raw, side="right") / len(self.anomaly_reference)

    def class_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.xgb.predict_proba(X[self.feature_names])

    def rf_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.rf.predict_proba(X[self.feature_names])

    # ---------- persistence ----------
    def save(self, directory: str | Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, directory / BUNDLE_FILE)
        (directory / METADATA_FILE).write_text(json.dumps(self.public_metadata(), indent=2, default=str))
        return directory

    @staticmethod
    def load(directory: str | Path) -> "ModelBundle":
        # Only ever load bundles this application trained itself (joblib uses pickle).
        return joblib.load(Path(directory) / BUNDLE_FILE)

    @staticmethod
    def exists(directory: str | Path) -> bool:
        return (Path(directory) / BUNDLE_FILE).exists()

    def public_metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "trained_at": self.trained_at,
            "classes": self.classes,
            "features": self.feature_names,
            "models": {
                "isolation_forest": self.iforest.get_params(),
                "xgboost": {k: v for k, v in self.xgb.get_params().items() if v is not None},
                "random_forest": self.rf.get_params(),
                "hmm": self.hmm.to_dict(),
            },
            **self.metadata,
        }
