"""Labelled attack scenarios, built from kill-chain blocks.

Every record carries a Label(scenario_id, attack_class, stage). Stealthy variants reuse the victim's
known IP and user agent, use MFA, and spread actions out over hours, which is the hard case for
detection and correlation.
"""

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.schemas.event import EventSource
from app.simulation.builders import Label, RecordFactory, SimRecord
from app.simulation.environment import (
    ACCOUNT_ID,
    SENSITIVE_BUCKETS,
    TRAIL_ARN,
    Environment,
    Principal,
    random_key,
)

S3, EC2, IAM, STS = "s3.amazonaws.com", "ec2.amazonaws.com", "iam.amazonaws.com", "sts.amazonaws.com"
MB = 1024 * 1024
ATTACK_UAS = [
    "aws-cli/2.13.0 Python/3.11.4 Linux/6.5.0-kali3-amd64 exe/x86_64",
    "Boto3/1.28.0 Python/3.11.4 Linux/6.1.0 Botocore/1.31.0",
    "python-requests/2.31.0",
]
CONSOLE_UA_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

STAGE_CLASS = {
    "CREDENTIAL_ACCESS": "brute_force",
    "INITIAL_ACCESS": "credential_compromise",
    "DISCOVERY": "reconnaissance",
    "PERSISTENCE": "privilege_escalation",
    "PRIVILEGE_ESCALATION": "privilege_escalation",
    "DEFENSE_EVASION": "defense_evasion",
    "EXFILTRATION": "data_exfiltration",
    "IMPACT": "resource_abuse",
}

SCENARIOS: dict[str, tuple[list[str], float]] = {
    "brute_force": (["brute_force"], 1.0),
    "brute_force_then_access": (["brute_force_success", "initial_access", "discovery"], 1.0),
    "credential_compromise": (["initial_access", "discovery"], 1.0),
    "privilege_escalation": (["initial_access", "discovery", "persistence", "privesc"], 1.5),
    "data_exfiltration": (["initial_access", "discovery_short", "exfiltration"], 1.5),
    "defense_evasion": (["initial_access", "defense_evasion"], 1.0),
    "resource_abuse": (["key_access", "resource_abuse"], 1.0),
    "full_chain": (["initial_access", "discovery", "persistence", "privesc", "network_exposure",
                    "exfiltration", "defense_evasion"], 2.0),
    "insider_exfiltration": (["insider_exfiltration"], 0.7),
}


@dataclass
class ScenarioInfo:
    scenario_id: str
    kind: str
    victim: str
    attacker_ip: str
    start: datetime
    end: datetime
    stealthy: bool
    stages: list[str] = field(default_factory=list)
    identities: set[str] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)


class AttackBuilder:
    def __init__(self, rng: random.Random, env: Environment, factory: RecordFactory):
        self.rng = rng
        self.env = env
        self.f = factory
        self.inventory: list[dict] = []  # instances created by attackers, as an inventory scan would see them

    def build(self, scenario_id: str, kind: str, victim: Principal, start: datetime,
              attacker_ip: str, stealthy: bool) -> tuple[list[SimRecord], ScenarioInfo]:
        self.out: list[SimRecord] = []
        self.sid = scenario_id
        self.stealthy = stealthy
        self.victim = victim
        self.actor = victim  # may switch to a backdoor user
        self.ip = victim.known_ips[0] if stealthy and kind != "brute_force" else attacker_ip
        self.ua = victim.cli_user_agent if stealthy else self.rng.choice(ATTACK_UAS)
        self.key = victim.access_key
        self.info = ScenarioInfo(scenario_id, kind, victim.actor_id, self.ip, start, start, stealthy)
        self.info.identities.add(victim.actor_id)
        self.info.ips.add(self.ip)

        t = start
        for block in SCENARIOS[kind][0]:
            t = getattr(self, f"_b_{block}")(t)
            t += self._pause()
        self.info.end = max(r.timestamp for r in self.out)
        self.info.stages = sorted({r.label.stage for r in self.out})
        return self.out, self.info

    # ---------- helpers ----------
    def _pause(self) -> timedelta:
        minutes = self.rng.uniform(30, 180) if self.stealthy else self.rng.uniform(1, 8)
        return timedelta(minutes=minutes)

    def _step(self) -> timedelta:
        seconds = self.rng.uniform(300, 1800) if self.stealthy else self.rng.uniform(3, 40)
        return timedelta(seconds=seconds)

    def _emit(self, ts: datetime, stage: str, record: dict, source: EventSource = EventSource.CLOUDTRAIL):
        label = Label(self.sid, STAGE_CLASS[stage], stage)
        self.out.append(SimRecord(source, record, label, ts))

    def _api(self, ts, stage, name, service, **kw):
        kw.setdefault("ip", self.ip)
        kw.setdefault("key", self.key)
        kw.setdefault("user_agent", self.ua)
        self._emit(ts, stage, self.f.api(ts, self.actor, name, service, **kw))

    def _finding(self, ts, stage, probability, *args, **kw):
        if not self.stealthy and self.rng.random() < probability:
            ts = ts + timedelta(minutes=self.rng.uniform(1, 10))
            self._emit(ts, stage, self.f.finding(ts, *args, **kw), EventSource.GUARDDUTY)

    # ---------- kill-chain blocks ----------
    def _b_brute_force(self, t, succeed=False):
        attempts = self.rng.randint(3, 6) if self.stealthy else self.rng.randint(12, 40)
        for _ in range(attempts):
            self._emit(t, "CREDENTIAL_ACCESS", self.f.console_login(
                t, self.victim, ip=self.ip, success=False, mfa=False, user_agent=CONSOLE_UA_LINUX))
            t += timedelta(seconds=self.rng.uniform(600, 1500) if self.stealthy else self.rng.uniform(2, 15))
        if succeed:
            self._emit(t, "INITIAL_ACCESS", self.f.console_login(
                t, self.victim, ip=self.ip, success=True, mfa=False, user_agent=CONSOLE_UA_LINUX))
            self.key = random_key(self.rng, "ASIA")
        return t

    def _b_brute_force_success(self, t):
        self.stealthy_backup, self.stealthy = self.stealthy, False
        t = self._b_brute_force(t, succeed=True)
        self.stealthy = self.stealthy_backup
        return t

    def _b_initial_access(self, t):
        if self.rng.random() < 0.5 or self.stealthy:
            # console session with stolen password (stealthy: MFA-fatigue success from a residential proxy)
            self._emit(t, "INITIAL_ACCESS", self.f.console_login(
                t, self.victim, ip=self.ip, success=True, mfa=self.stealthy,
                user_agent=CONSOLE_UA_LINUX if not self.stealthy else self.victim.cli_user_agent))
            self.key = random_key(self.rng, "ASIA")
        t += self._step()
        self._api(t, "INITIAL_ACCESS", "GetCallerIdentity", STS, read_only=True)
        self._finding(t, "INITIAL_ACCESS", 0.5, "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", 5.0,
                      f"Unusual console login was seen for principal {self.victim.name}.",
                      user=self.victim, key=self.key, remote_ip=self.ip, api="ConsoleLogin")
        self.info.keys.add(self.key)
        return t

    def _b_key_access(self, t):
        self._api(t, "INITIAL_ACCESS", "GetCallerIdentity", STS, read_only=True)
        self.info.keys.add(self.key)
        return t

    def _b_discovery(self, t, n_range=(6, 25)):
        calls = [("ListUsers", IAM), ("ListRoles", IAM), ("ListPolicies", IAM),
                 ("GetAccountAuthorizationDetails", IAM), ("ListAttachedUserPolicies", IAM),
                 ("ListBuckets", S3), ("DescribeInstances", EC2), ("DescribeSecurityGroups", EC2),
                 ("DescribeVpcs", EC2), ("ListGroups", IAM)]
        n = self.rng.randint(2, 5) if self.stealthy else self.rng.randint(*n_range)
        for _ in range(n):
            name, service = self.rng.choice(calls)
            params = {"userName": self.victim.name} if name == "ListAttachedUserPolicies" else {}
            denied = not self.stealthy and self.rng.random() < 0.3
            self._api(t, "DISCOVERY", name, service, params=params, read_only=True,
                      error="AccessDenied" if denied else None)
            t += self._step()
        return t

    def _b_discovery_short(self, t):
        return self._b_discovery(t, (3, 8))

    def _b_persistence(self, t):
        if self.rng.random() < 0.5:
            new_key = random_key(self.rng, "AKIA")
            self._api(t, "PERSISTENCE", "CreateAccessKey", IAM, params={"userName": self.victim.name},
                      response={"accessKey": {"userName": self.victim.name, "accessKeyId": new_key,
                                              "status": "Active"}})
            self.key = new_key
        else:
            backdoor_name = f"svc-backup-{self.rng.randint(100, 999)}"
            self._api(t, "PERSISTENCE", "CreateUser", IAM, params={"userName": backdoor_name})
            t += self._step()
            self._api(t, "PERSISTENCE", "CreateLoginProfile", IAM,
                      params={"userName": backdoor_name, "passwordResetRequired": False})
            t += self._step()
            new_key = random_key(self.rng, "AKIA")
            self._api(t, "PERSISTENCE", "CreateAccessKey", IAM, params={"userName": backdoor_name},
                      response={"accessKey": {"userName": backdoor_name, "accessKeyId": new_key,
                                              "status": "Active"}})
            # From here on the attacker acts as the backdoor user with the new key.
            self.actor = Principal(
                name=backdoor_name, kind="backdoor", identity_type="IAMUser",
                principal_id="AIDA" + random_key(self.rng, "")[:16], access_key=new_key,
                known_ips=[self.ip], work_start=0, work_end=24, cli_user_agent=self.ua)
            self.key = new_key
            self.info.identities.add(backdoor_name)
        self.info.keys.add(self.key)
        return t + self._step()

    def _b_privesc(self, t):
        target = self.actor.name
        technique = self.rng.choice(["attach", "attach", "inline", "group", "version"])
        if technique == "attach":
            self._api(t, "PRIVILEGE_ESCALATION", "AttachUserPolicy", IAM,
                      params={"userName": target, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        elif technique == "inline":
            self._api(t, "PRIVILEGE_ESCALATION", "PutUserPolicy", IAM,
                      params={"userName": target, "policyName": "maintenance",
                              "policyDocument": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'})
        elif technique == "group":
            self._api(t, "PRIVILEGE_ESCALATION", "AddUserToGroup", IAM,
                      params={"userName": target, "groupName": "admins"})
        else:
            arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/developer-boundary"
            self._api(t, "PRIVILEGE_ESCALATION", "CreatePolicyVersion", IAM,
                      params={"policyArn": arn, "setAsDefault": True,
                              "policyDocument": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'})
        self.info.resources.add(target)
        return t + self._step()

    def _b_network_exposure(self, t):
        inst = self.rng.choice(self.env.instances)
        self._api(t, "DEFENSE_EVASION", "AuthorizeSecurityGroupIngress", EC2,
                  params={"groupId": inst.security_group, "ipPermissions": {"items": [
                      {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                       "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}},
                  response={"_return": True})
        self.info.resources.add(inst.security_group)
        t += timedelta(minutes=self.rng.uniform(1, 4))
        for _ in range(self.rng.randint(3, 8)):
            self._emit(t, "DEFENSE_EVASION", self.f.flow(
                inst.eni, self.ip, inst.private_ip, self.rng.randint(40000, 60000), 22,
                self.rng.randint(5_000, 200_000), t), EventSource.VPC_FLOW)
            t += timedelta(seconds=self.rng.uniform(20, 90))
        self.exposed_instance = inst
        return t

    def _b_exfiltration(self, t):
        bucket = self.rng.choice(SENSITIVE_BUCKETS)
        self._api(t, "DISCOVERY", "ListBuckets", S3, read_only=True)
        t += self._step()
        self._api(t, "EXFILTRATION", "ListObjectsV2", S3, params={"bucketName": bucket, "list-type": "2"},
                  read_only=True, category="Data")
        n = self.rng.randint(3, 8) if self.stealthy else self.rng.randint(12, 80)
        for _ in range(n):
            t += self._step() if self.stealthy else timedelta(seconds=self.rng.uniform(1, 10))
            size = self.rng.randint(5 * MB, 120 * MB)
            self._api(t, "EXFILTRATION", "GetObject", S3,
                      params={"bucketName": bucket, "key": f"exports/{self.rng.getrandbits(32):08x}.csv"},
                      extra={"bytesTransferredIn": 0, "bytesTransferredOut": size},
                      read_only=True, category="Data")
        self.info.resources.add(f"arn:aws:s3:::{bucket}")
        if not self.stealthy and self.rng.random() < 0.25:
            t += self._step()
            self._api(t, "EXFILTRATION", "PutBucketPolicy", S3, params={
                "bucketName": bucket,
                "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}})
        inst = getattr(self, "exposed_instance", None)
        if inst is not None:  # staged through the exposed instance, then out over HTTPS
            for _ in range(self.rng.randint(2, 6)):
                t += timedelta(seconds=self.rng.uniform(30, 120))
                self._emit(t, "EXFILTRATION", self.f.flow(
                    inst.eni, inst.private_ip, self.ip, self.rng.randint(40000, 60000), 443,
                    self.rng.randint(50 * MB, 500 * MB), t), EventSource.VPC_FLOW)
        self._finding(t, "EXFILTRATION", 0.3, "Exfiltration:S3/AnomalousBehavior", 8.0,
                      f"Anomalous S3 GetObject activity by {self.actor.name}.",
                      bucket=bucket, remote_ip=self.ip, api="GetObject")
        return t

    def _b_defense_evasion(self, t):
        options = [
            ("StopLogging", "cloudtrail.amazonaws.com", {"name": TRAIL_ARN}),
            ("DeleteTrail", "cloudtrail.amazonaws.com", {"name": TRAIL_ARN}),
            ("DeleteDetector", "guardduty.amazonaws.com", {"detectorId": "12abc34d567e8fa901bc2d34e56789f0"}),
            ("DeleteFlowLogs", EC2, {"flowLogIds": ["fl-0a1b2c3d4e5f6"]}),
            ("PutEventSelectors", "cloudtrail.amazonaws.com", {"trailName": TRAIL_ARN}),
        ]
        for name, service, params in self.rng.sample(options, self.rng.randint(1, 2)):
            self._api(t, "DEFENSE_EVASION", name, service, params=params)
            if service == "cloudtrail.amazonaws.com":
                self.info.resources.add(TRAIL_ARN)
            t += self._step()
        self._finding(t, "DEFENSE_EVASION", 0.6, "Stealth:IAMUser/CloudTrailLoggingDisabled", 2.0,
                      "AWS CloudTrail trail was disabled.", user=self.victim, key=self.key,
                      remote_ip=self.ip, api="StopLogging")
        return t

    def _b_resource_abuse(self, t):
        region = self.rng.choice(["us-west-2", "eu-west-1", "ap-southeast-1"])
        self._api(t, "IMPACT", "CreateKeyPair", EC2, params={"keyName": "kp-tmp"}, region=region)
        t += self._step()
        self._api(t, "IMPACT", "CreateSecurityGroup", EC2, params={"groupName": "default-ssh"}, region=region,
                  response={"groupId": "sg-0ffee0000000001"})
        t += self._step()
        n = self.rng.randint(2, 4) if self.stealthy else self.rng.randint(4, 20)
        instances = [f"i-0{self.rng.getrandbits(60):015x}" for _ in range(n)]
        itype = self.rng.choice(["g4dn.xlarge", "p3.2xlarge", "c5.9xlarge"])
        self._api(t, "IMPACT", "RunInstances", EC2, region=region,
                  params={"instanceType": itype, "minCount": n, "maxCount": n, "keyName": "kp-tmp"},
                  response={"instancesSet": {"items": [{"instanceId": i, "instanceType": itype}
                                                       for i in instances]}})
        self.info.resources.update(instances)
        pool = f"203.0.113.{self.rng.randint(200, 254)}"
        self.info.ips.add(pool)
        for idx, instance_id in enumerate(instances[:4]):
            eni = f"eni-0{self.rng.getrandbits(60):015x}"
            private = f"10.9.{idx}.{self.rng.randint(10, 250)}"
            self.inventory.append({"resource_id": instance_id, "resource_type": "ec2_instance", "region": region,
                                   "attributes": {"enis": [eni], "private_ips": [private], "instance_type": itype}})
            hours = self.rng.randint(2, 5)
            for hour in range(hours):
                ts = t + timedelta(minutes=5 + 60 * hour + self.rng.uniform(0, 30))
                self._emit(ts, "IMPACT", self.f.flow(
                    eni, private, pool, self.rng.randint(40000, 60000), self.rng.choice([3333, 4444, 14444]),
                    self.rng.randint(200_000, 4 * MB), ts, seconds=3600), EventSource.VPC_FLOW)
            for step in range(hours * 6):
                ts = t + timedelta(minutes=5 + 10 * step)
                self._emit(ts, "IMPACT", self.f.metric(ts, instance_id, self.rng.uniform(92, 100), private, region),
                           EventSource.CLOUDWATCH)
        self._finding(t + timedelta(minutes=20), "IMPACT", 0.6, "CryptoCurrency:EC2/BitcoinTool.B!DNS", 8.0,
                      "EC2 instance is querying a domain name associated with cryptocurrency activity.",
                      instance_id=instances[0], remote_ip=pool, action_type="NETWORK_CONNECTION", outbound=True)
        return t

    def _b_insider_exfiltration(self, t):
        # An analyst already allowed to read the bucket, at a normal time from a normal IP.
        self.ip = self.victim.known_ips[0]
        self.ua = self.victim.cli_user_agent
        self.info.attacker_ip = self.ip
        self.info.ips = {self.ip}
        bucket = self.rng.choice(SENSITIVE_BUCKETS)
        n = self.rng.randint(25, 90)
        for _ in range(n):
            size = self.rng.randint(30 * MB, 200 * MB)
            self._api(t, "EXFILTRATION", "GetObject", S3,
                      params={"bucketName": bucket, "key": f"exports/{self.rng.getrandbits(32):08x}.csv"},
                      extra={"bytesTransferredIn": 0, "bytesTransferredOut": size}, read_only=True, category="Data")
            t += timedelta(seconds=self.rng.uniform(2, 30))
        self.info.resources.add(f"arn:aws:s3:::{bucket}")
        return t
