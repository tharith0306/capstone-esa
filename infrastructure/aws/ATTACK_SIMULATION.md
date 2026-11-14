# Validating CloudShield on a real AWS account

The models are trained on simulated data. This runbook shows whether they hold up against
**real** CloudTrail, VPC Flow Logs, GuardDuty and CloudWatch telemetry. Record the results in the
table at the end; they are the most valuable numbers for the paper.

> Use a dedicated sandbox account. Every technique below runs against resources you own, using
> [Stratus Red Team](https://stratus-red-team.cloud/), an open-source tool built for exactly this
> kind of detection validation. Never point it at a shared or production account.

## 0. Deploy the lab (about 5 minutes)

```bash
cd infrastructure/aws/terraform
tofu init        # or: terraform init
tofu apply -var budget_email=you@example.com
tofu output -raw cloudshield_env >> ../../../backend/.env
```

In the IAM console, create access keys for `cloudshield-collector` and save them as an AWS CLI
profile:

```bash
aws configure --profile cloudshield-lab
```

Then add these lines to `backend/.env`:

```bash
CLOUDSHIELD_AWS_PROFILE=cloudshield-lab
CLOUDSHIELD_SEED_DEMO=false
```

Start CloudShield empty: `docker compose up -d`.

Leave the lab idle (or use it normally as `alice`) for **at least 24 hours** before any attack. CloudShield
compares each identity with its own history, and an empty history makes everything look new.

## 1. Baseline collection

```bash
docker compose exec backend python -m app.cli inventory
for s in cloudtrail cloudtrail_s3 vpc_flow guardduty cloudwatch sqs; do
  docker compose exec backend python -m app.cli collect $s
done
docker compose exec backend python -m app.cli analyze
```

Write down the number of incidents at MEDIUM or above in this attack-free period. That count is your
real-world false-positive rate.

## 2. Run the techniques

Install Stratus Red Team (`brew install stratus-red-team`). Use admin credentials for the sandbox
account, **not** the collector profile.

| CloudShield scenario | Stratus technique | Expected CloudShield result |
|---|---|---|
| Persistence / privilege escalation | `aws.persistence.iam-create-admin-user` | `privilege_escalation` incident with `IAM_USER_CREATED` + `POLICY_ATTACHED`; DEACTIVATE_ACCESS_KEY / DETACH_USER_POLICY proposed |
| Backdoor credentials | `aws.persistence.iam-backdoor-user` | `ACCESS_KEY_CREATED` on an existing user; key-linking correlation |
| Defense evasion | `aws.defense-evasion.cloudtrail-stop` | Rule alert + `defense_evasion` incident; START_CLOUDTRAIL_LOGGING proposed |
| Defense evasion | `aws.defense-evasion.cloudtrail-event-selectors` | `AUDIT_TRAIL_MODIFIED` |
| Defense evasion | `aws.defense-evasion.vpc-remove-flow-logs` | `FLOW_LOGS_DELETED` rule alert |
| Data exposure | `aws.exfiltration.s3-backdoor-bucket-policy` | `BUCKET_POLICY_CHANGED`; BLOCK_PUBLIC_ACCESS proposed |
| Discovery | `aws.discovery.ec2-enumerate-from-instance` | `reconnaissance` (role session from an instance) |
| Credential access | `aws.credential-access.ec2-get-password-data` | `INSTANCE_CREDENTIAL_ACCESS` |
| Resource abuse | `aws.execution.ec2-launch-unusual-instances` | `INSTANCE_LAUNCHED` burst in an unusual region / instance type |

For each technique:

```bash
stratus warmup   <technique>      # creates prerequisites (not part of the attack)
date -u                           # note the start time
stratus detonate <technique>
# CloudTrail delivers in ~5-15 min. EventBridge->SQS is near real time for management events.
docker compose exec backend python -m app.cli collect sqs
docker compose exec backend python -m app.cli collect cloudtrail
docker compose exec backend python -m app.cli analyze
stratus cleanup  <technique>
```

## 3. Credential-compromise chain (manual)

This is the multi-stage chain CloudShield is designed to reconstruct. Create an access key for the
lab user `bob` (ReadOnly plus whatever you grant in step 3). Then run the following, ideally from
another network such as a phone hotspot so the source IP is new:

```bash
export AWS_PROFILE=bob-lab
aws sts get-caller-identity
aws iam list-users; aws iam list-roles; aws s3 ls
aws s3 cp s3://<sensitive_bucket>/exports/customers-2026-11.csv /tmp/   # data event
# As an admin, grant bob AdministratorAccess to emulate escalation, then as bob:
aws iam create-access-key --user-name bob
aws ec2 describe-instances --region us-west-2
```

Expected result: one incident linking the new IP, `bob`, his access keys and the bucket. Check the
HMM timeline (`INITIAL_ACCESS → DISCOVERY → PERSISTENCE / PRIVILEGE_ESCALATION → EXFILTRATION`), the
SHAP reasons, and that the DEACTIVATE_ACCESS_KEY proposals target bob's keys.

## 4. Live response test (optional)

1. Create access keys for `cloudshield-responder` and save them as profile `cloudshield-responder`.
2. Set `CLOUDSHIELD_RESPONSE_MODE=live` and `CLOUDSHIELD_RESPONDER_PROFILE=cloudshield-responder` in `.env`.
3. Run `docker compose up -d`.
4. Have one admin **approve** and a **different** admin **execute** DEACTIVATE_ACCESS_KEY. The two-person rule enforces this.
5. Verify `Status=Inactive` in IAM, then **roll back** from the dashboard.

## 5. Record the results

| Technique | Detected (any alert) | Incident level | Correct class | Timeline complete | Minutes from detonation to incident | Notes |
|---|---|---|---|---|---|---|
| | | | | | | |

Also record the false-positive incidents per day from step 1. These numbers sit next to the
synthetic results in `ml_training/reports/experiments.md`.

## 6. Tear down

```bash
cd infrastructure/aws/terraform && tofu destroy -var budget_email=you@example.com
```

The evidence bucket uses Object Lock in governance mode. Delete it after retention expires, or with
`s3:BypassGovernanceRetention`.
