"""The simulated AWS organisation: principals, instances, buckets.

All IPs come from documentation / benchmarking ranges (RFC 5737, RFC 2544) and RFC 1918 space.
"""

import random
import string
from dataclasses import dataclass, field

ACCOUNT_ID = "111122223333"
HOME_REGION = "ap-south-1"
OFFICE_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
DB_IP = "10.0.2.40"
AWS_ENDPOINT_IP = "192.0.2.250"  # stands in for S3 / package mirrors
TRAIL_ARN = f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT_ID}:trail/cloudshield-trail"
DETECTOR_ID = "12abc34d567e8fa901bc2d34e56789f0"

# Bucket -> what the data is. Sensitivity is *not* read from here by the analysis code.
BUCKETS = ["app-assets", "build-artifacts", "analytics-exports", "customer-data", "finance-reports"]
SENSITIVE_BUCKETS = ["customer-data", "finance-reports"]


def random_key(rng: random.Random, prefix: str) -> str:
    return prefix + "".join(rng.choices(string.ascii_uppercase + string.digits, k=16))


def client_ip(rng: random.Random) -> str:
    return f"198.51.100.{rng.randint(100, 199)}"


def internet_ip(rng: random.Random) -> str:
    """Random 'internet' host (RFC 2544 benchmarking range) used for scanner noise."""
    return f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def attacker_ip(rng: random.Random) -> str:
    return f"203.0.113.{rng.randint(1, 254)}"


@dataclass
class Instance:
    instance_id: str
    private_ip: str
    eni: str
    security_group: str


@dataclass
class Principal:
    name: str
    kind: str  # developer | admin | analyst | service | ci
    identity_type: str  # IAMUser | AssumedRole
    principal_id: str
    access_key: str
    known_ips: list[str]
    work_start: int  # UTC hour
    work_end: int
    mfa: bool = True
    cli_user_agent: str = "aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0 exe/x86_64 prompt/off"
    role_name: str | None = None
    session_name: str | None = None
    instance: Instance | None = None
    extra_keys: list[str] = field(default_factory=list)

    @property
    def actor_id(self) -> str:
        if self.identity_type == "AssumedRole":
            return f"{self.role_name}/{self.session_name}"
        return self.name


@dataclass
class Environment:
    account_id: str
    region: str
    principals: list[Principal]
    instances: list[Instance]
    app_security_group: str

    def of_kind(self, *kinds: str) -> list[Principal]:
        return [p for p in self.principals if p.kind in kinds]


_UA_BY_OS = {
    "mac": "aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0 exe/x86_64 prompt/off",
    "win": "aws-cli/2.15.30 Python/3.11.8 Windows/10 exe/AMD64 prompt/off",
    "linux": "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1017-aws exe/x86_64 prompt/off",
}


def build_environment(rng: random.Random) -> Environment:
    instances = [
        Instance(
            instance_id=f"i-0{rng.getrandbits(64):016x}"[:19],
            private_ip=f"10.0.1.{10 + i}",
            eni=f"eni-0{rng.getrandbits(64):016x}"[:21],
            security_group="sg-0a1b2c3d4e5f60001",
        )
        for i in range(3)
    ]

    def home_ips(n: int) -> list[str]:
        return [f"192.0.2.{rng.randint(1, 120)}" for _ in range(n)]

    principals: list[Principal] = []

    def user(name: str, kind: str, start: int, end: int, mfa: bool, os_name: str) -> Principal:
        return Principal(
            name=name,
            kind=kind,
            identity_type="IAMUser",
            principal_id="AIDA" + random_key(rng, "")[:16],
            access_key=random_key(rng, "AKIA"),
            known_ips=[rng.choice(OFFICE_IPS), *home_ips(rng.randint(1, 2))],
            work_start=start,
            work_end=end,
            mfa=mfa,
            cli_user_agent=_UA_BY_OS[os_name],
        )

    for i in range(1, 9):
        start = rng.randint(3, 5)
        principals.append(
            user(f"dev-{i:02d}", "developer", start, start + rng.randint(8, 10),
                 rng.random() < 0.85, rng.choice(["mac", "mac", "linux", "win"]))
        )
    for i in range(1, 3):
        principals.append(user(f"admin-{i:02d}", "admin", 3, 13, True, "mac"))
    for i in range(1, 5):
        principals.append(user(f"analyst-{i:02d}", "analyst", 4, 13, rng.random() < 0.7,
                               rng.choice(["win", "mac"])))

    for inst in instances:
        principals.append(
            Principal(
                name="app-server-role",
                kind="service",
                identity_type="AssumedRole",
                principal_id="AROAEXAMPLEAPPROLE01",
                access_key=random_key(rng, "ASIA"),
                known_ips=[inst.private_ip],
                work_start=0,
                work_end=24,
                cli_user_agent="Boto3/1.34.80 md/Botocore#1.34.80 ua/2.0 os/linux#6.5.0 lang/python#3.12.3",
                role_name="app-server-role",
                session_name=inst.instance_id,
                instance=inst,
            )
        )

    principals.append(
        Principal(
            name="ci-deploy-role",
            kind="ci",
            identity_type="AssumedRole",
            principal_id="AROAEXAMPLECIROLE001",
            access_key=random_key(rng, "ASIA"),
            known_ips=[],  # GitHub-hosted runners: a new IP on almost every run
            work_start=3,
            work_end=15,
            cli_user_agent="aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1017-azure exe/x86_64 prompt/off",
            role_name="ci-deploy-role",
            session_name="github-actions",
        )
    )
    return Environment(ACCOUNT_ID, HOME_REGION, principals, instances, "sg-0a1b2c3d4e5f60001")
