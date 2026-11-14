# Phase 1: AWS lab environment

CloudShield needs a small AWS account to monitor. **Use a dedicated sandbox account** (or an
AWS Organizations member account), never a personal account with real data and never root keys.

Replace `ACCOUNT_ID` and `REGION` (e.g. `ap-south-1`) in the JSON files and commands below.

## Cost notes

- CloudTrail: the first copy of management events is free; S3 data events are billed per event,
  which is why `data-event-selectors.json` limits them to one lab bucket.
- GuardDuty: 30-day free trial, then billed by volume. Disable the detector when not testing.
- VPC Flow Logs to CloudWatch Logs: billed per GB ingested. Keep the lab VPC quiet.
- Set an AWS Budget alert (e.g. USD 10) before you start.

## 1. Trail + S3 data events

```bash
aws s3api create-bucket --bucket cloudshield-trail-ACCOUNT_ID --region REGION \
  --create-bucket-configuration LocationConstraint=REGION
aws s3api put-bucket-policy --bucket cloudshield-trail-ACCOUNT_ID --policy file://trail-bucket-policy.json
aws cloudtrail create-trail --name cloudshield-trail --s3-bucket-name cloudshield-trail-ACCOUNT_ID \
  --is-multi-region-trail --enable-log-file-validation
aws cloudtrail put-event-selectors --trail-name cloudshield-trail \
  --advanced-event-selectors file://data-event-selectors.json
aws cloudtrail start-logging --name cloudshield-trail
```

Multi-region matters: IAM and console sign-in events are recorded in `us-east-1`.
`LookupEvents` (used by `app.cli collect cloudtrail`) only returns **management** events. S3
object reads/writes reach CloudShield through the trail files:

```bash
aws s3 sync s3://cloudshield-trail-ACCOUNT_ID/AWSLogs/ACCOUNT_ID/CloudTrail/ ./trail-files/
python -m app.cli ingest-file --source cloudtrail trail-files/**/*.json.gz
```

## 2. VPC Flow Logs → CloudWatch Logs

Create the log group `/cloudshield/vpc-flow` and an IAM role that VPC Flow Logs can assume to write
to it (console: *VPC → your VPC → Flow logs → Create*, which can create the role for you). Keep the
**default format**, since the normalizer parses the 14-field version-2 layout.

```bash
aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-XXXXXXXX --traffic-type ALL \
  --log-destination-type cloud-watch-logs --log-group-name /cloudshield/vpc-flow \
  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT_ID:role/cloudshield-flowlogs-role
```

## 3. GuardDuty

```bash
aws guardduty create-detector --enable
```

## 4. Lab resources

| Resource | Purpose |
|---|---|
| IAM user `alice` | Normal-behaviour baseline (console + MFA) |
| IAM user `bob` | Victim account for attack simulations (limited permissions, no MFA) |
| IAM role `app-server-role` | Instance role for the EC2 app server |
| EC2 `t3.micro` in the lab VPC | Application server / compromise target |
| S3 `cloudshield-lab-customer-data-ACCOUNT_ID` | "Sensitive" bucket with dummy CSVs; data events on |
| S3 `cloudshield-evidence-ACCOUNT_ID` | Raw evidence store: enable **versioning + Object Lock** at creation |

Only ever put synthetic data in the lab buckets.

## 5. Collector identity

Create an IAM user or role for CloudShield with **only** `collector-policy.json` attached, store its
credentials in a named profile (`aws configure --profile cloudshield-lab`), then:

```bash
export CLOUDSHIELD_AWS_PROFILE=cloudshield-lab CLOUDSHIELD_AWS_REGION=REGION
python -m app.cli collect cloudtrail
python -m app.cli collect vpc_flow --log-group /cloudshield/vpc-flow
python -m app.cli collect guardduty
```

The response engine (Phase 11) will get its own separate role with write permissions behind an
approval workflow. Never widen the collector's read-only policy for it.
