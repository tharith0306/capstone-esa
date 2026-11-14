"""Benign activity, including the noisy-but-legitimate behaviour that makes detection non-trivial:
typo'd logins, travel IPs, admins attaching policies, analysts pulling large exports from sensitive
buckets, CI runners on ever-changing IPs, and internet scanners hitting the servers."""

import random
from datetime import datetime, timedelta

from app.schemas.event import EventSource
from app.simulation.builders import NORMAL, RecordFactory, SimRecord
from app.simulation.environment import (
    AWS_ENDPOINT_IP,
    BUCKETS,
    DB_IP,
    OFFICE_IPS,
    Environment,
    Principal,
    client_ip,
    internet_ip,
    random_key,
)

CONSOLE_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
S3 = "s3.amazonaws.com"
EC2 = "ec2.amazonaws.com"
IAM = "iam.amazonaws.com"
MB = 1024 * 1024


class NormalActivity:
    def __init__(self, rng: random.Random, env: Environment, factory: RecordFactory):
        self.rng = rng
        self.env = env
        self.f = factory
        self.out: list[SimRecord] = []

    # ---------- helpers ----------
    def _ct(self, ts: datetime, record: dict) -> None:
        self.out.append(SimRecord(EventSource.CLOUDTRAIL, record, NORMAL, ts))

    def _flow(self, ts: datetime, record: dict) -> None:
        self.out.append(SimRecord(EventSource.VPC_FLOW, record, NORMAL, ts))

    def _gap(self, mean_seconds: float = 45) -> timedelta:
        return timedelta(seconds=max(1.0, self.rng.expovariate(1 / mean_seconds)))

    def _pick_ip(self, p: Principal, weekday: bool) -> str:
        r = self.rng.random()
        if r < 0.04:  # travel / new home network: legitimately new IP
            ip = f"192.0.2.{self.rng.randint(121, 249)}"
            p.known_ips.append(ip)
            return ip
        office = [ip for ip in p.known_ips if ip in OFFICE_IPS]
        if weekday and office and r < 0.75:
            return office[0]
        return self.rng.choice(p.known_ips)

    def _object(self, bucket: str) -> str:
        return f"{self.rng.choice(['reports', 'exports', 'data', 'tmp', 'img'])}/{self.rng.getrandbits(32):08x}.dat"

    # ---------- per-day generation ----------
    def day(self, day: datetime) -> None:
        weekday = day.weekday() < 5
        for p in self.env.principals:
            if p.kind == "service":
                self._service_day(p, day)
            elif p.kind == "ci":
                if weekday:
                    self._ci_day(p, day)
            else:
                for start in self._session_starts(p, day, weekday):
                    self._session(p, start, weekday)
        for inst in self.env.instances:
            self._instance_flows(inst, day)

    def _session_starts(self, p: Principal, day: datetime, weekday: bool) -> list[datetime]:
        if not weekday and self.rng.random() > 0.12:
            return []
        n = 1 if self.rng.random() < 0.6 else 2
        starts = [day + timedelta(hours=self.rng.uniform(p.work_start, p.work_end - 1)) for _ in range(n)]
        if self.rng.random() < 0.05:  # late-night work (IST evening/night)
            starts.append(day + timedelta(hours=self.rng.uniform(15, 20)))
        return sorted(starts)

    def _session(self, p: Principal, t: datetime, weekday: bool) -> None:
        ip = self._pick_ip(p, weekday)
        console = p.kind in ("admin", "analyst") or self.rng.random() < 0.4
        key = p.access_key
        ua = p.cli_user_agent
        if console:
            for _ in range(self.rng.choice([0] * 30 + [1] + [2])):  # occasional password typo
                self._ct(t, self.f.console_login(t, p, ip=ip, success=False, mfa=False, user_agent=CONSOLE_UA))
                t += self._gap(20)
            self._ct(t, self.f.console_login(t, p, ip=ip, success=True, mfa=p.mfa, user_agent=CONSOLE_UA))
            key = random_key(self.rng, "ASIA")
            ua = CONSOLE_UA
            t += self._gap(30)

        n_calls = {"developer": (10, 50), "admin": (8, 30), "analyst": (10, 60)}[p.kind]
        actions = {"developer": self._dev_action, "admin": self._admin_action, "analyst": self._analyst_action}[p.kind]
        for _ in range(self.rng.randint(*n_calls)):
            use_key = key if (not console or self.rng.random() < 0.6) else p.access_key
            use_ua = ua if use_key == key else p.cli_user_agent
            t = actions(p, t, ip, use_key, use_ua)
            t += self._gap()

    # ---------- action catalogues ----------
    def _read(self, t, p, ip, key, ua, name, service=EC2, params=None):
        self._ct(t, self.f.api(t, p, name, service, ip=ip, key=key, params=params or {},
                               read_only=True, user_agent=ua))

    def _get_object(self, t, p, ip, key, ua, bucket, size):
        self._ct(t, self.f.api(
            t, p, "GetObject", S3, ip=ip, key=key, params={"bucketName": bucket, "key": self._object(bucket)},
            extra={"bytesTransferredIn": 0, "bytesTransferredOut": size}, read_only=True,
            category="Data", user_agent=ua))

    def _put_object(self, t, p, ip, key, ua, bucket, size):
        self._ct(t, self.f.api(
            t, p, "PutObject", S3, ip=ip, key=key, params={"bucketName": bucket, "key": self._object(bucket)},
            extra={"bytesTransferredIn": size, "bytesTransferredOut": 0}, category="Data", user_agent=ua))

    def _dev_action(self, p, t, ip, key, ua) -> datetime:
        r = self.rng.random()
        if r < 0.25:
            self._read(t, p, ip, key, ua, "DescribeInstances")
        elif r < 0.35:
            self._read(t, p, ip, key, ua, "DescribeSecurityGroups")
        elif r < 0.55:
            self._get_object(t, p, ip, key, ua, self.rng.choice(["app-assets", "build-artifacts"]),
                             self.rng.randint(2_000, 5 * MB))
        elif r < 0.70:
            self._put_object(t, p, ip, key, ua, self.rng.choice(["app-assets", "build-artifacts"]),
                             self.rng.randint(2_000, 20 * MB))
        elif r < 0.80:
            self._read(t, p, ip, key, ua, "ListObjectsV2", S3, {"bucketName": "app-assets", "list-type": "2"})
        elif r < 0.85:
            self._read(t, p, ip, key, ua, "GetCallerIdentity", "sts.amazonaws.com")
        elif r < 0.88:
            denied = self.rng.random() < 0.4
            self._ct(t, self.f.api(t, p, "ListRoles", IAM, ip=ip, key=key, params={}, read_only=True,
                                   user_agent=ua, error="AccessDenied" if denied else None))
        elif r < 0.91:
            inst = f"i-0{self.rng.getrandbits(60):015x}"
            self._ct(t, self.f.api(
                t, p, "RunInstances", EC2, ip=ip, key=key, user_agent=ua,
                params={"instanceType": "t3.micro", "minCount": 1, "maxCount": 1},
                response={"instancesSet": {"items": [{"instanceId": inst, "instanceType": "t3.micro"}]}}))
            later = t + timedelta(minutes=self.rng.randint(20, 120))
            self._ct(later, self.f.api(later, p, "TerminateInstances", EC2, ip=ip, key=key, user_agent=ua,
                                       params={"instancesSet": {"items": [{"instanceId": inst}]}}))
        else:
            self._read(t, p, ip, key, ua, "DescribeVpcs")
        return t

    def _admin_action(self, p, t, ip, key, ua) -> datetime:
        r = self.rng.random()
        users = [u.name for u in self.env.of_kind("developer", "analyst")]
        if r < 0.20:
            self._read(t, p, ip, key, ua, self.rng.choice(["ListUsers", "ListRoles", "ListPolicies"]), IAM)
        elif r < 0.24:
            self._read(t, p, ip, key, ua, "ListAttachedUserPolicies", IAM, {"userName": self.rng.choice(users)})
        elif r < 0.26:
            self._read(t, p, ip, key, ua, "GetAccountAuthorizationDetails", IAM)
        elif r < 0.40:
            self._read(t, p, ip, key, ua, "DescribeInstances")
        elif r < 0.47:
            # legitimate permission management: the main overlap with privilege escalation
            policy = self.rng.choices(
                ["ReadOnlyAccess", "AmazonS3ReadOnlyAccess", "PowerUserAccess", "AdministratorAccess"],
                weights=[5, 5, 2, 1])[0]
            self._ct(t, self.f.api(t, p, "AttachUserPolicy", IAM, ip=ip, key=key, user_agent=ua,
                                   params={"userName": self.rng.choice(users),
                                           "policyArn": f"arn:aws:iam::aws:policy/{policy}"}))
        elif r < 0.51:
            target = self.rng.choice(users)
            self._ct(t, self.f.api(t, p, "CreateAccessKey", IAM, ip=ip, key=key, user_agent=ua,
                                   params={"userName": target},
                                   response={"accessKey": {"userName": target, "status": "Active",
                                                           "accessKeyId": random_key(self.rng, "AKIA")}}))
            t += self._gap(20)
            self._ct(t, self.f.api(t, p, "DeleteAccessKey", IAM, ip=ip, key=key, user_agent=ua,
                                   params={"userName": target, "accessKeyId": random_key(self.rng, "AKIA")}))
        elif r < 0.55:
            cidr = "0.0.0.0/0" if self.rng.random() < 0.1 else "198.51.100.0/24"
            port = 443 if cidr == "0.0.0.0/0" else self.rng.choice([22, 443, 8443])
            self._ct(t, self.f.api(
                t, p, "AuthorizeSecurityGroupIngress", EC2, ip=ip, key=key, user_agent=ua,
                params={"groupId": self.env.app_security_group, "ipPermissions": {"items": [
                    {"ipProtocol": "tcp", "fromPort": port, "toPort": port,
                     "ipRanges": {"items": [{"cidrIp": cidr}]}}]}},
                response={"_return": True}))
        elif r < 0.56:
            self._ct(t, self.f.api(t, p, "UpdateLoginProfile", IAM, ip=ip, key=key, user_agent=ua,
                                   params={"userName": self.rng.choice(users), "passwordResetRequired": True}))
        elif r < 0.565:
            self._ct(t, self.f.api(t, p, "PutEventSelectors", "cloudtrail.amazonaws.com", ip=ip, key=key,
                                   user_agent=ua, params={"trailName": "cloudshield-trail"}))
        elif r < 0.60:
            name = f"new-hire-{self.rng.randint(10, 99)}"
            self._ct(t, self.f.api(t, p, "CreateUser", IAM, ip=ip, key=key, user_agent=ua,
                                   params={"userName": name}))
        elif r < 0.75:
            self._read(t, p, ip, key, ua, "DescribeSecurityGroups")
        else:
            self._get_object(t, p, ip, key, ua, self.rng.choice(BUCKETS), self.rng.randint(2_000, 2 * MB))
        return t

    def _analyst_action(self, p, t, ip, key, ua) -> datetime:
        r = self.rng.random()
        if r < 0.15:
            bucket = self.rng.choice(["analytics-exports", "customer-data", "finance-reports"])
            self._read(t, p, ip, key, ua, "ListObjectsV2", S3, {"bucketName": bucket, "list-type": "2"})
        elif r < 0.85:
            bucket = self.rng.choices(["analytics-exports", "customer-data", "finance-reports"],
                                      weights=[6, 3, 1])[0]
            burst = 1
            if self.rng.random() < 0.03:  # quarterly export: many big objects from a sensitive bucket
                burst = self.rng.randint(15, 50)
            for _ in range(burst):
                size = self.rng.randint(1 * MB, 60 * MB) if burst == 1 else self.rng.randint(40 * MB, 150 * MB)
                self._get_object(t, p, ip, key, ua, bucket, size)
                t += self._gap(15)
        elif r < 0.92:
            self._put_object(t, p, ip, key, ua, "analytics-exports", self.rng.randint(1 * MB, 30 * MB))
        else:
            self._read(t, p, ip, key, ua, "GetCallerIdentity", "sts.amazonaws.com")
        return t

    def _service_day(self, p: Principal, day: datetime) -> None:
        ip = p.known_ips[0]
        t = day + timedelta(minutes=self.rng.uniform(0, 15))
        end = day + timedelta(days=1)
        while t < end:
            self._put_object(t, p, ip, p.access_key, p.cli_user_agent, "app-assets", self.rng.randint(5_000, 200_000))
            if self.rng.random() < 0.5:
                self._get_object(t + timedelta(seconds=5), p, ip, p.access_key, p.cli_user_agent,
                                 "app-assets", self.rng.randint(1_000, 50_000))
            if self.rng.random() < 0.3:
                self._ct(t, self.f.api(t, p, "Decrypt", "kms.amazonaws.com", ip="AWS Internal",
                                       key=p.access_key, user_agent="AWS Internal",
                                       params={"encryptionAlgorithm": "SYMMETRIC_DEFAULT"}, read_only=True))
            t += timedelta(minutes=self.rng.uniform(10, 20))

    def _ci_day(self, p: Principal, day: datetime) -> None:
        for _ in range(self.rng.randint(3, 10)):
            t = day + timedelta(hours=self.rng.uniform(p.work_start, p.work_end))
            ip = f"192.0.2.{self.rng.randint(128, 254)}"
            self._put_object(t, p, ip, p.access_key, p.cli_user_agent, "build-artifacts",
                             self.rng.randint(5 * MB, 50 * MB))
            t += self._gap(20)
            instances = [f"i-0{self.rng.getrandbits(60):015x}" for _ in range(self.rng.randint(1, 3))]
            self._ct(t, self.f.api(
                t, p, "RunInstances", EC2, ip=ip, key=p.access_key,
                params={"instanceType": "t3.medium", "minCount": len(instances), "maxCount": len(instances)},
                response={"instancesSet": {"items": [{"instanceId": i, "instanceType": "t3.medium"}
                                                     for i in instances]}}))
            t += self._gap(30)
            self._read(t, p, ip, p.access_key, p.cli_user_agent, "DescribeInstances")
            later = t + timedelta(minutes=self.rng.randint(15, 60))
            self._ct(later, self.f.api(later, p, "TerminateInstances", EC2, ip=ip, key=p.access_key,
                                       params={"instancesSet": {"items": [{"instanceId": i} for i in instances]}}))

    def _instance_flows(self, inst, day: datetime) -> None:
        for hour in range(24):
            base = day + timedelta(hours=hour)
            busy = 4 <= hour <= 14
            for _ in range(self.rng.randint(2, 5) if busy else self.rng.randint(1, 2)):
                ts = base + timedelta(minutes=self.rng.uniform(0, 59))
                self._flow(ts, self.f.flow(inst.eni, client_ip(self.rng), inst.private_ip,
                                           self.rng.randint(32768, 65535), 443,
                                           self.rng.randint(10_000, 800_000), ts))
            ts = base + timedelta(minutes=self.rng.uniform(0, 59))
            self._flow(ts, self.f.flow(inst.eni, inst.private_ip, DB_IP, self.rng.randint(32768, 65535),
                                       5432, self.rng.randint(5_000, 400_000), ts))
            ts = base + timedelta(minutes=self.rng.uniform(0, 59))
            size = self.rng.randint(10_000, 2_000_000)
            if self.rng.random() < 0.04:  # OS/package updates: large but benign outbound transfer
                size = self.rng.randint(80 * MB, 400 * MB)
            self._flow(ts, self.f.flow(inst.eni, inst.private_ip, AWS_ENDPOINT_IP,
                                       self.rng.randint(32768, 65535), 443, size, ts))
            if self.rng.random() < 0.25:  # internet background scanning, dropped by the security group
                scanner = internet_ip(self.rng)
                for _ in range(self.rng.randint(1, 6)):
                    ts = base + timedelta(minutes=self.rng.uniform(0, 59))
                    self._flow(ts, self.f.flow(inst.eni, scanner, inst.private_ip, self.rng.randint(1024, 65535),
                                               self.rng.choice([22, 23, 445, 3389, 8080, 6379]),
                                               self.rng.randint(40, 200), ts, action="REJECT"))
