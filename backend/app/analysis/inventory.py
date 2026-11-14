"""In-memory view of the asset inventory used for enrichment (no database code)."""

from dataclasses import dataclass, field


@dataclass
class Inventory:
    by_eni: dict[str, str] = field(default_factory=dict)  # network interface -> instance id
    by_ip: dict[str, str] = field(default_factory=dict)  # private IP -> instance id

    @classmethod
    def from_records(cls, records: list[dict]) -> "Inventory":
        inv = cls()
        for r in records:
            if r.get("resource_type") != "ec2_instance":
                continue
            attrs = r.get("attributes") or {}
            for eni in attrs.get("enis", []):
                inv.by_eni[eni] = r["resource_id"]
            for ip in attrs.get("private_ips", []):
                inv.by_ip[ip] = r["resource_id"]
        return inv

    def instance_for(self, eni: str | None, ip: str | None) -> str | None:
        return self.by_eni.get(eni or "") or self.by_ip.get(ip or "")
