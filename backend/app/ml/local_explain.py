"""LIME local explanations and DiCE counterfactuals for an XGBoost window prediction.

LIME fits a sparse linear surrogate around one window. DiCE searches for nearby feature vectors the
model would classify as *normal*: "what would have had to be different?". A counterfactual is an
analytical aid about the model's decision boundary, not evidence that the activity was harmless,
and it never triggers any response action.
"""

import logging
import math
import os
import warnings

import numpy as np
import pandas as pd

from app.ml.explain import FEATURE_DESCRIPTIONS
from app.ml.features import RATIO_FEATURES
from app.ml.models import ModelBundle

log = logging.getLogger(__name__)
os.environ.setdefault("TQDM_DISABLE", "1")  # DiCE prints progress bars otherwise

# Features an analyst can reason about changing. Pure context (time since last activity) stays fixed.
IMMUTABLE = {"hours_since_prev_activity"}
# Log-scaled but not counts: shown with decimals rather than rounded to whole numbers.
CONTINUOUS_FEATURES = {"api_calls_per_minute", "activity_deviation", "hours_since_prev_activity"}


def to_raw(feature: str, value: float) -> float:
    """Model space -> human scale (counts and bytes were log1p-transformed)."""
    return value if feature in RATIO_FEATURES else math.expm1(value)


class LocalExplainer:
    def __init__(self, bundle: ModelBundle, seed: int = 0):
        if bundle.background is None:
            raise ValueError("model bundle has no background sample; retrain with this version")
        self.bundle = bundle
        self.seed = seed
        self._lime = None

    def _predict(self, arr: np.ndarray) -> np.ndarray:
        return self.bundle.class_proba(pd.DataFrame(arr, columns=self.bundle.feature_names))

    # ---------------------------------------------------------------- LIME
    def lime(self, x: pd.Series, class_index: int, num_features: int = 8, num_samples: int = 1500) -> dict:
        from lime.lime_tabular import LimeTabularExplainer

        if self._lime is None:
            self._lime = LimeTabularExplainer(
                self.bundle.background[self.bundle.feature_names].to_numpy(),
                feature_names=self.bundle.feature_names, class_names=self.bundle.classes,
                mode="classification", discretize_continuous=True, random_state=self.seed)
        exp = self._lime.explain_instance(x[self.bundle.feature_names].to_numpy(), self._predict,
                                          labels=[class_index], num_features=num_features, num_samples=num_samples)
        weights = exp.as_list(label=class_index)
        names = dict(exp.as_map()[class_index])
        features = []
        for (condition, weight), idx in zip(weights, names):
            feat = self.bundle.feature_names[idx]
            features.append({"feature": feat, "description": FEATURE_DESCRIPTIONS.get(feat, ""),
                             "condition": condition, "weight": round(float(weight), 4)})
        return {"explained_class": self.bundle.classes[class_index], "intercept": round(float(exp.intercept[class_index]), 4),
                "local_r2": round(float(exp.score), 4), "features": features,
                "note": "LIME conditions are in model space (counts and bytes are log1p-scaled)."}

    # ---------------------------------------------------------------- DiCE
    def counterfactuals(self, x: pd.Series, total: int = 3) -> dict:
        import dice_ml

        feats = self.bundle.feature_names
        bg = self.bundle.background[feats].copy()
        bg["label"] = (self.bundle.background_labels != 0).astype(int)  # DiCE works on attack vs normal
        data = dice_ml.Data(dataframe=bg, continuous_features=feats, outcome_name="label")
        model = dice_ml.Model(model=_BinaryAttackModel(self.bundle), backend="sklearn", model_type="classifier")
        dice = dice_ml.Dice(data, model, method="random")
        query = pd.DataFrame([x[feats].astype(float).to_numpy()], columns=feats)
        # Only *reduce* the activity actually present: "how much less of this would have looked normal?"
        active = [f for f in feats if f not in IMMUTABLE and float(x[f]) > 0]
        cf_frame, constrained = None, bool(active)
        attempts = [(active, {f: [0.0, float(x[f])] for f in active})] if active else []
        attempts.append(([f for f in feats if f not in IMMUTABLE], None))
        for vary, ranges in attempts:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                try:
                    result = dice.generate_counterfactuals(
                        query, total_CFs=total, desired_class=0, features_to_vary=vary,
                        permitted_range=ranges or {}, random_seed=self.seed, verbose=False)
                    cf_frame = result.cf_examples_list[0].final_cfs_df
                except Exception as exc:  # DiCE raises when no counterfactual is found
                    log.debug("DiCE attempt failed: %s", exc)
                    cf_frame = None
            if cf_frame is not None and len(cf_frame):
                constrained = ranges is not None
                break
        original_p = float(1 - self.bundle.class_proba(query)[0, 0])
        out = []
        if cf_frame is not None:
            for _, row in cf_frame.iterrows():
                cand = pd.DataFrame([row[feats].astype(float).to_numpy()], columns=feats)
                changes = [{"feature": f, "description": FEATURE_DESCRIPTIONS.get(f, ""),
                            "from": _display(f, float(x[f])), "to": _display(f, float(row[f]))}
                           for f in feats if abs(float(row[f]) - float(x[f])) > 1e-6]
                out.append({"attack_probability": round(float(1 - self.bundle.class_proba(cand)[0, 0]), 4),
                            "changes": changes})
        return {"method": "DiCE (random search)", "original_attack_probability": round(original_p, 4),
                "desired": "normal", "counterfactuals": out,
                "constraint": "only reductions of activity present in the window" if constrained else "any feature",
                "note": "What would have to differ for the model to call this window normal. Analytical only: "
                        "not proof the activity was benign, and never used to trigger or suppress response."}


def _display(feature: str, value: float) -> float:
    raw = to_raw(feature, value)
    return round(raw, 3) if feature in RATIO_FEATURES or feature in CONTINUOUS_FEATURES else float(round(raw))


class _BinaryAttackModel:
    """sklearn-style wrapper: P(normal), P(attack) from the multiclass XGBoost."""

    def __init__(self, bundle: ModelBundle):
        self.bundle = bundle
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X) -> np.ndarray:
        frame = X if isinstance(X, pd.DataFrame) else pd.DataFrame(X, columns=self.bundle.feature_names)
        p_normal = self.bundle.class_proba(frame[self.bundle.feature_names].astype(float))[:, 0]
        return np.column_stack([p_normal, 1 - p_normal])

    def predict(self, X) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)
