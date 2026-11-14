"""Resource sensitivity (the D term of the risk score). Name/type based rules for the lab; in a real
deployment this would come from resource tags or a data classification inventory."""

import re

_RULES: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r"customer|pii|payroll|secret|credential|backup", re.I), 1.0),
    (re.compile(r"finance|billing|invoice|hr-", re.I), 0.9),
    (re.compile(r"cloudtrail|trail/", re.I), 0.9),
    (re.compile(r"AdministratorAccess|admins", re.I), 0.9),
    (re.compile(r"export|analytics|report", re.I), 0.6),
]
_TYPE_DEFAULTS = {
    "iam_user": 0.6,
    "iam_role": 0.6,
    "iam_policy": 0.7,
    "security_group": 0.6,
    "cloudtrail_trail": 0.9,
    "ec2_instance": 0.5,
    "network_interface": 0.4,
}


def resource_sensitivity(resource_id: str | None, resource_type: str | None = None) -> float:
    if not resource_id:
        return 0.0
    for pattern, score in _RULES:
        if pattern.search(resource_id):
            return score
    return _TYPE_DEFAULTS.get(resource_type or "", 0.3)
