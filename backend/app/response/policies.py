"""Layer 9a: map an incident to concrete, reviewable mitigation actions.

Nothing here touches AWS. Every action needs analyst approval before the executor will run it,
and an action is only proposed at HIGH risk or above (MEDIUM gets a notification only).
"""

import json

from app.processing.hashing import sha256_hex

LEVEL_ORDER = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
DENY_ALL_POLICY = "arn:aws:iam::aws:policy/AWSDenyAll"

ACTION_CATALOG = {
    "DEACTIVATE_ACCESS_KEY": ("iam:UpdateAccessKey (Status=Inactive)", True, True),
    "DETACH_USER_POLICY": ("iam:DetachUserPolicy", True, True),
    "REMOVE_USER_FROM_GROUP": ("iam:RemoveUserFromGroup", True, True),
    "ATTACH_DENY_ALL": ("iam:AttachUserPolicy (AWSDenyAll)", True, True),
    "REVOKE_SECURITY_GROUP_INGRESS": ("ec2:RevokeSecurityGroupIngress", True, True),
    "START_CLOUDTRAIL_LOGGING": ("cloudtrail:StartLogging", True, False),
    "BLOCK_PUBLIC_ACCESS": ("s3:PutPublicAccessBlock", True, False),
    "STOP_INSTANCES": ("ec2:StopInstances", True, True),
    "DELETE_INLINE_POLICY": ("iam:DeleteUserPolicy", False, False),
    "REVIEW_DATA_ACCESS": ("Manual review", False, False),
    "RESTORE_MONITORING": ("Manual: recreate trail / GuardDuty detector / flow logs", False, False),
    "NOTIFY_ANALYST": ("Notification", False, False),
}


def _level_at_least(level: str, minimum: str) -> bool:
    return LEVEL_ORDER.index(level) >= LEVEL_ORDER.index(minimum)


def _action(incident_id: str, action_type: str, target: dict, description: str, rationale: str,
            evidence: list[str]) -> dict:
    api_call, automatable, reversible = ACTION_CATALOG[action_type]
    action_id = "act_" + sha256_hex(f"{incident_id}|{action_type}|{json.dumps(target, sort_keys=True)}".encode())[:16]
    return {
        "action_id": action_id,
        "action_type": action_type,
        "target": target,
        "description": description,
        "rationale": rationale,
        "api_call": api_call,
        "automatable": automatable,
        "reversible": reversible,
        "approval_required": True,
        "evidence_event_ids": evidence[:20],
    }


def recommend_actions(incident, rows, events_by_id) -> list[dict]:
    level = incident.risk["level"]
    iid = incident.incident_id
    if not _level_at_least(level, "MEDIUM"):
        return []
    if level == "MEDIUM":
        return [_action(iid, "NOTIFY_ANALYST", {"incident_id": iid},
                        f"Notify an analyst to review incident ({incident.title})",
                        f"Risk {incident.risk['score']} is MEDIUM: investigate before any containment.", [])]

    suspicious = {t["event_id"] for t in incident.timeline if t["stage"] != "NORMAL" or t["in_alert"]}
    actions: dict[str, dict] = {}

    def add(a: dict) -> None:
        actions.setdefault(a["action_id"], a)

    for r in rows:
        if r.event_id not in suspicious:
            continue
        ev = events_by_id[r.event_id]
        attrs = ev.attributes or {}
        if r.key and r.key.startswith("AKIA") and r.actor and ev.actor_type == "IAMUser":
            add(_action(iid, "DEACTIVATE_ACCESS_KEY", {"user": r.actor, "access_key_id": r.key},
                        f"Deactivate access key {r.key} of {r.actor}",
                        "Long-term key used in suspicious activity in this incident.", [r.event_id]))
        if r.created_key and r.created_key.startswith("AKIA"):
            owner = ev.resource_id or r.actor
            add(_action(iid, "DEACTIVATE_ACCESS_KEY", {"user": owner, "access_key_id": r.created_key},
                        f"Deactivate newly created access key {r.created_key} of {owner}",
                        "Access key created during the incident (possible persistence).", [r.event_id]))
        if r.event_type == "POLICY_ATTACHED" and attrs.get("policy_arn") and ev.resource_type == "iam_user":
            add(_action(iid, "DETACH_USER_POLICY", {"user": ev.resource_id, "policy_arn": attrs["policy_arn"]},
                        f"Detach {attrs['policy_arn'].rsplit('/', 1)[-1]} from {ev.resource_id}",
                        "Permission granted during the incident (possible privilege escalation).", [r.event_id]))
        if r.event_type == "INLINE_POLICY_ADDED" and ev.resource_type == "iam_user":
            add(_action(iid, "DELETE_INLINE_POLICY", {"user": ev.resource_id, "policy_name": attrs.get("policy_name")},
                        f"Review and delete inline policy {attrs.get('policy_name')} on {ev.resource_id}",
                        "Inline policy added during the incident; deleting it is not reversible.", [r.event_id]))
        if r.event_type == "GROUP_MEMBERSHIP_ADDED":
            raw_group = attrs.get("group_name")
            if raw_group and ev.resource_id:
                add(_action(iid, "REMOVE_USER_FROM_GROUP", {"user": ev.resource_id, "group": raw_group},
                            f"Remove {ev.resource_id} from group {raw_group}",
                            "Group membership added during the incident.", [r.event_id]))
        if r.event_type == "SECURITY_GROUP_INGRESS_OPENED" and attrs.get("open_to_internet"):
            for port in attrs.get("ports") or []:
                low, _, high = port.partition("-")
                add(_action(iid, "REVOKE_SECURITY_GROUP_INGRESS",
                            {"group_id": ev.resource_id, "cidr": "0.0.0.0/0", "from_port": int(low),
                             "to_port": int(high or low), "region": ev.region},
                            f"Revoke 0.0.0.0/0 on port {port} from {ev.resource_id}",
                            "Security group opened to the internet during the incident.", [r.event_id]))
        if r.event_type == "AUDIT_LOGGING_STOPPED" and ev.event_name == "StopLogging":
            add(_action(iid, "START_CLOUDTRAIL_LOGGING", {"trail": ev.resource_id, "region": ev.region},
                        f"Restart CloudTrail logging on {ev.resource_id}",
                        "Audit logging was stopped during the incident.", [r.event_id]))
        if r.event_type in ("AUDIT_LOGGING_STOPPED", "THREAT_DETECTION_DISABLED", "FLOW_LOGS_DELETED") \
                and ev.event_name in ("DeleteTrail", "DeleteDetector", "DeleteFlowLogs"):
            add(_action(iid, "RESTORE_MONITORING", {"deleted": ev.event_name, "resource": ev.resource_id},
                        f"Recreate monitoring removed by {ev.event_name}",
                        "Monitoring was deleted; it cannot be restored automatically.", [r.event_id]))
        if r.event_type == "BUCKET_POLICY_CHANGED" and ev.resource_id:
            bucket = ev.resource_id.removeprefix("arn:aws:s3:::").split("/")[0]
            add(_action(iid, "BLOCK_PUBLIC_ACCESS", {"bucket": bucket},
                        f"Enable S3 Block Public Access on {bucket}",
                        "Bucket policy changed during the incident (possible public exposure).", [r.event_id]))
        if r.event_type == "INSTANCE_LAUNCHED" and attrs.get("instance_ids"):
            add(_action(iid, "STOP_INSTANCES", {"instance_ids": attrs["instance_ids"], "region": ev.region},
                        f"Stop {len(attrs['instance_ids'])} instance(s) launched in {ev.region}",
                        "Instances launched during the incident (possible resource hijacking).", [r.event_id]))

    sensitive_downloads = [r.event_id for r in rows if r.event_id in suspicious and r.event_type == "OBJECT_DOWNLOADED"]
    if sensitive_downloads:
        add(_action(iid, "REVIEW_DATA_ACCESS", {"resources": incident.resources[:10]},
                    f"Review {len(sensitive_downloads)} object download(s) for data-breach notification duties",
                    "Data may have left the account; decide on notification.", sensitive_downloads))

    compromised = {r.actor for r in rows if r.event_id in suspicious and r.event_type == "CONSOLE_LOGIN"
                   and r.outcome == "success" and events_by_id[r.event_id].actor_type == "IAMUser"}
    if level == "CRITICAL":
        for user in sorted(compromised):
            add(_action(iid, "ATTACH_DENY_ALL", {"user": user},
                        f"Quarantine {user} by attaching AWSDenyAll",
                        "CRITICAL incident with a suspicious console sign-in for this user.", []))
    return list(actions.values())
