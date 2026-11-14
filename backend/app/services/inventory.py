"""Asset inventory persistence and AWS refresh (DescribeInstances, ListBuckets, ListUsers)."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.inventory import Inventory
from app.collectors.aws import aws_client
from app.core.config import Settings
from app.database.models import CloudResource, utcnow


def load_inventory(session: Session) -> Inventory:
    rows = session.scalars(select(CloudResource).where(CloudResource.resource_type == "ec2_instance"))
    return Inventory.from_records([{"resource_id": r.resource_id, "resource_type": r.resource_type,
                                    "attributes": r.attributes} for r in rows])


def save_inventory(session_factory: sessionmaker[Session], records: list[dict[str, Any]], source: str) -> int:
    now = utcnow()
    with session_factory() as session:
        for rec in records:
            row = session.get(CloudResource, rec["resource_id"])
            if row is None:
                row = CloudResource(resource_id=rec["resource_id"], first_seen=now)
                session.add(row)
            row.resource_type = rec["resource_type"]
            row.cloud_provider = rec.get("cloud_provider", "aws")
            row.account_id = rec.get("account_id")
            row.region = rec.get("region")
            row.name = rec.get("name")
            row.attributes = rec.get("attributes") or {}
            row.source = source
            row.last_seen = now
        session.commit()
    return len(records)


def scan_aws(settings: Settings) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    ec2 = aws_client(settings, "ec2")
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                enis = inst.get("NetworkInterfaces", [])
                records.append({
                    "resource_id": inst["InstanceId"], "resource_type": "ec2_instance",
                    "account_id": reservation.get("OwnerId"), "region": settings.aws_region,
                    "name": next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), None),
                    "attributes": {
                        "enis": [n["NetworkInterfaceId"] for n in enis],
                        "private_ips": [a["PrivateIpAddress"] for n in enis for a in n.get("PrivateIpAddresses", [])],
                        "public_ip": inst.get("PublicIpAddress"),
                        "security_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
                        "instance_type": inst.get("InstanceType"),
                        "state": (inst.get("State") or {}).get("Name"),
                        "launch_time": str(inst.get("LaunchTime")),
                    },
                })
    s3 = aws_client(settings, "s3")
    for bucket in s3.list_buckets().get("Buckets", []):
        records.append({"resource_id": f"arn:aws:s3:::{bucket['Name']}", "resource_type": "s3_bucket",
                        "name": bucket["Name"], "attributes": {"created": str(bucket.get("CreationDate"))}})
    iam = aws_client(settings, "iam")
    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            records.append({"resource_id": user["UserName"], "resource_type": "iam_user", "name": user["UserName"],
                            "attributes": {"arn": user["Arn"], "created": str(user.get("CreateDate"))}})
    return records


def refresh_inventory_from_aws(settings: Settings, session_factory: sessionmaker[Session]) -> dict:
    records = scan_aws(settings)
    save_inventory(session_factory, records, "aws")
    counts: dict[str, int] = {}
    for r in records:
        counts[r["resource_type"]] = counts.get(r["resource_type"], 0) + 1
    return {"resources": len(records), "by_type": counts}
