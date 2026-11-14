"""Shared vocabulary: attack classes, kill-chain stages, HMM observation symbols, MITRE mapping."""

ATTACK_CLASSES = [
    "normal",
    "brute_force",
    "credential_compromise",
    "reconnaissance",
    "privilege_escalation",
    "data_exfiltration",
    "defense_evasion",
    "resource_abuse",
]

STAGES = [
    "NORMAL",
    "CREDENTIAL_ACCESS",
    "INITIAL_ACCESS",
    "DISCOVERY",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "DEFENSE_EVASION",
    "EXFILTRATION",
    "IMPACT",
]

# Window label priority when one window contains several attack stages.
STAGE_PRIORITY = [
    "EXFILTRATION", "IMPACT", "DEFENSE_EVASION", "PRIVILEGE_ESCALATION", "PERSISTENCE",
    "INITIAL_ACCESS", "CREDENTIAL_ACCESS", "DISCOVERY",
]

STAGE_CLASS = {
    "NORMAL": "normal",
    "CREDENTIAL_ACCESS": "brute_force",
    "INITIAL_ACCESS": "credential_compromise",
    "DISCOVERY": "reconnaissance",
    "PERSISTENCE": "privilege_escalation",
    "PRIVILEGE_ESCALATION": "privilege_escalation",
    "DEFENSE_EVASION": "defense_evasion",
    "EXFILTRATION": "data_exfiltration",
    "IMPACT": "resource_abuse",
}

# Kill-chain position of each class, used for attack-stage compatibility in correlation.
CLASS_ORDER = {
    "reconnaissance": 1,
    "brute_force": 1,
    "credential_compromise": 2,
    "privilege_escalation": 3,
    "defense_evasion": 4,
    "data_exfiltration": 5,
    "resource_abuse": 5,
}

# How bad it is to have reached a stage (sequence severity in the risk score).
STAGE_SEVERITY = {
    "NORMAL": 0.0,
    "DISCOVERY": 0.4,
    "CREDENTIAL_ACCESS": 0.5,
    "INITIAL_ACCESS": 0.55,
    "PERSISTENCE": 0.7,
    "PRIVILEGE_ESCALATION": 0.8,
    "DEFENSE_EVASION": 0.85,
    "IMPACT": 0.9,
    "EXFILTRATION": 1.0,
}

OBSERVATIONS = [
    "ROUTINE_READ",
    "ROUTINE_WRITE",
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "DISCOVERY",
    "ACCESS_DENIED",
    "CREDENTIAL_CHANGE",
    "PRIVILEGE_CHANGE",
    "FIREWALL_EXPOSURE",
    "DATA_ACCESS",
    "DATA_EXPOSURE",
    "DEFENSE_EVASION",
    "COMPUTE_PROVISION",
    "FLOW_NORMAL",
    "FLOW_REJECTED",
    "FLOW_LARGE_OUT",
    "THREAT_FINDING",
]

EVENT_TYPE_OBSERVATION = {
    "IDENTITY_DISCOVERY": "DISCOVERY",
    "IAM_ENUMERATION": "DISCOVERY",
    "STORAGE_ENUMERATION": "DISCOVERY",
    "COMPUTE_ENUMERATION": "DISCOVERY",
    "OBJECT_LISTING": "DISCOVERY",
    "ACCESS_KEY_CREATED": "CREDENTIAL_CHANGE",
    "LOGIN_PROFILE_CHANGED": "CREDENTIAL_CHANGE",
    "IAM_USER_CREATED": "CREDENTIAL_CHANGE",
    "MFA_DEVICE_REMOVED": "CREDENTIAL_CHANGE",
    "POLICY_ATTACHED": "PRIVILEGE_CHANGE",
    "INLINE_POLICY_ADDED": "PRIVILEGE_CHANGE",
    "POLICY_VERSION_CHANGED": "PRIVILEGE_CHANGE",
    "GROUP_MEMBERSHIP_ADDED": "PRIVILEGE_CHANGE",
    "ROLE_TRUST_POLICY_CHANGED": "PRIVILEGE_CHANGE",
    "SECURITY_GROUP_INGRESS_OPENED": "FIREWALL_EXPOSURE",
    "SECURITY_GROUP_EGRESS_OPENED": "FIREWALL_EXPOSURE",
    "OBJECT_DOWNLOADED": "DATA_ACCESS",
    "BUCKET_POLICY_CHANGED": "DATA_EXPOSURE",
    "BUCKET_ACL_CHANGED": "DATA_EXPOSURE",
    "PUBLIC_ACCESS_BLOCK_CHANGED": "DATA_EXPOSURE",
    "AUDIT_LOGGING_STOPPED": "DEFENSE_EVASION",
    "AUDIT_TRAIL_MODIFIED": "DEFENSE_EVASION",
    "THREAT_DETECTION_DISABLED": "DEFENSE_EVASION",
    "FLOW_LOGS_DELETED": "DEFENSE_EVASION",
    "INSTANCE_LAUNCHED": "COMPUTE_PROVISION",
    "KEY_PAIR_CREATED": "COMPUTE_PROVISION",
    "SECURITY_GROUP_CREATED": "COMPUTE_PROVISION",
    "API_CALL_READ": "ROUTINE_READ",
}

# MITRE ATT&CK (Enterprise, cloud) techniques per CloudShield event type.
MITRE_TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "CONSOLE_LOGIN": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "IDENTITY_DISCOVERY": ("T1087.004", "Account Discovery: Cloud Account", "Discovery"),
    "IAM_ENUMERATION": ("T1087.004", "Account Discovery: Cloud Account", "Discovery"),
    "STORAGE_ENUMERATION": ("T1619", "Cloud Storage Object Discovery", "Discovery"),
    "OBJECT_LISTING": ("T1619", "Cloud Storage Object Discovery", "Discovery"),
    "COMPUTE_ENUMERATION": ("T1580", "Cloud Infrastructure Discovery", "Discovery"),
    "ACCESS_KEY_CREATED": ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence"),
    "IAM_USER_CREATED": ("T1136.003", "Create Account: Cloud Account", "Persistence"),
    "LOGIN_PROFILE_CHANGED": ("T1098", "Account Manipulation", "Persistence"),
    "POLICY_ATTACHED": ("T1098.003", "Account Manipulation: Additional Cloud Roles", "Privilege Escalation"),
    "INLINE_POLICY_ADDED": ("T1098.003", "Account Manipulation: Additional Cloud Roles", "Privilege Escalation"),
    "POLICY_VERSION_CHANGED": ("T1098.003", "Account Manipulation: Additional Cloud Roles", "Privilege Escalation"),
    "GROUP_MEMBERSHIP_ADDED": ("T1098.003", "Account Manipulation: Additional Cloud Roles", "Privilege Escalation"),
    "SECURITY_GROUP_INGRESS_OPENED": ("T1562.007", "Impair Defenses: Disable or Modify Cloud Firewall", "Defense Evasion"),
    "AUDIT_LOGGING_STOPPED": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "AUDIT_TRAIL_MODIFIED": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "FLOW_LOGS_DELETED": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "THREAT_DETECTION_DISABLED": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "OBJECT_DOWNLOADED": ("T1530", "Data from Cloud Storage", "Collection"),
    "BUCKET_POLICY_CHANGED": ("T1537", "Transfer Data to Cloud Account", "Exfiltration"),
    "INSTANCE_LAUNCHED": ("T1496", "Resource Hijacking", "Impact"),
    "KEY_PAIR_CREATED": ("T1578.002", "Modify Cloud Compute Infrastructure: Create Cloud Instance", "Defense Evasion"),
}
LOGIN_FAILURE_TECHNIQUE = ("T1110", "Brute Force", "Credential Access")
