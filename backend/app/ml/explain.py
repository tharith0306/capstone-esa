"""SHAP explanations of XGBoost predictions (Layer 7). Values are in the model's log-odds (margin)
space for the explained class: positive pushes towards that class, negative away from it."""

import numpy as np
import pandas as pd
import shap

from app.ml.models import ModelBundle

FEATURE_DESCRIPTIONS = {
    "failed_login_count": "Failed console logins",
    "successful_login_count": "Successful console logins",
    "login_without_mfa": "Console logins without MFA",
    "access_key_created_count": "New access keys created",
    "privilege_change_count": "IAM permission changes (policies, groups, trust)",
    "user_creation_count": "IAM users or login profiles created",
    "role_assumption_count": "Roles assumed",
    "discovery_count": "Enumeration / discovery API calls",
    "access_denied_count": "Access-denied API errors",
    "event_count": "Number of events in the window",
    "api_calls_per_minute": "API call rate",
    "unique_event_types": "Distinct kinds of activity",
    "unique_resources": "Distinct resources touched",
    "write_ratio": "Share of write (state-changing) calls",
    "new_ip_ratio": "Activity from IPs never seen for this identity",
    "unique_source_ips": "Distinct source IPs",
    "off_hours_ratio": "Activity at hours unusual for this identity",
    "new_event_type_ratio": "Actions this identity has never performed before",
    "new_resource_ratio": "Resources this identity has never touched before",
    "new_user_agent": "New client / user agent for this identity",
    "new_region_count": "Calls in AWS regions never used before",
    "activity_deviation": "Activity volume vs. this identity's baseline",
    "hours_since_prev_activity": "Hours since this identity was last active",
    "instance_launch_count": "RunInstances calls",
    "instances_launched": "EC2 instances launched",
    "instance_change_count": "Instances stopped / terminated / modified",
    "key_pair_created_count": "EC2 key pairs created",
    "sg_change_count": "Security group changes",
    "sg_open_to_internet_count": "Security group rules opened to 0.0.0.0/0",
    "object_download_count": "S3 objects downloaded",
    "bytes_downloaded": "Volume downloaded from S3",
    "unique_objects": "Distinct S3 objects accessed",
    "sensitive_access_count": "Calls touching sensitive resources",
    "object_delete_count": "S3 objects deleted",
    "bucket_policy_change_count": "Bucket policy / ACL changes",
    "logging_tamper_count": "Changes that disable or weaken logging / detection",
    "flow_count": "Network flows",
    "rejected_flow_ratio": "Share of rejected network flows",
    "unique_dst_ports": "Distinct destination ports",
    "unique_external_peers": "Distinct external hosts contacted",
    "bytes_out_external": "Bytes sent to external hosts",
    "bytes_in_external": "Bytes received from external hosts",
    "new_external_peer_ratio": "External hosts never contacted before",
    "uncommon_port_flows": "Outbound flows on uncommon ports",
    "inbound_ssh_accepted": "Accepted inbound SSH from the internet",
}


class Explainer:
    def __init__(self, bundle: ModelBundle):
        self.bundle = bundle
        self._explainer = shap.TreeExplainer(bundle.xgb)

    def _values(self, X: pd.DataFrame) -> np.ndarray:
        values = self._explainer.shap_values(X[self.bundle.feature_names])
        if isinstance(values, list):  # older SHAP: one (n, f) array per class
            values = np.stack(values, axis=-1)
        return np.asarray(values)  # (n, f, k)

    def explain(self, X: pd.DataFrame, raw: pd.DataFrame, class_indices: list[int], top_k: int = 8) -> list[dict]:
        if len(X) == 0:
            return []
        values = self._values(X)
        base = np.atleast_1d(self._explainer.expected_value)
        explanations = []
        for row, cls in enumerate(class_indices):
            contrib = values[row, :, cls]
            order = np.argsort(-np.abs(contrib))[:top_k]
            explanations.append({
                "explained_class": self.bundle.classes[cls],
                "base_value": float(base[cls] if len(base) > cls else base[0]),
                "features": [
                    {
                        "feature": self.bundle.feature_names[i],
                        "description": FEATURE_DESCRIPTIONS.get(self.bundle.feature_names[i], ""),
                        "value": float(raw.iloc[row][self.bundle.feature_names[i]]),
                        "shap": round(float(contrib[i]), 4),
                    }
                    for i in order
                ],
            })
        return explanations

    def global_importance(self, X: pd.DataFrame) -> list[dict]:
        values = self._values(X)
        mean_abs = np.abs(values).mean(axis=(0, 2))
        order = np.argsort(-mean_abs)
        return [{"feature": self.bundle.feature_names[i], "description": FEATURE_DESCRIPTIONS.get(
            self.bundle.feature_names[i], ""), "mean_abs_shap": round(float(mean_abs[i]), 5)} for i in order]
