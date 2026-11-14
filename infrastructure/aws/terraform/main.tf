# CloudShield AWS lab: everything CloudShield monitors, plus the identities it uses.
# Apply only in a dedicated sandbox account:  tofu init && tofu apply   (or terraform)
# Tear down afterwards:                       tofu destroy

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { project = "cloudshield-lab", owner = var.owner_tag }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  prefix     = "cloudshield-${local.account_id}"
}

# ------------------------------------------------------------------ CloudTrail
resource "aws_s3_bucket" "trail" {
  bucket        = "${local.prefix}-trail"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = { StringEquals = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${local.account_id}:trail/cloudshield-trail" } }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = {
          "s3:x-amz-acl"  = "bucket-owner-full-control"
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${local.account_id}:trail/cloudshield-trail"
        } }
      },
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "cloudshield-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  advanced_event_selector {
    name = "All management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }
  advanced_event_selector {
    name = "S3 object events on the sensitive lab bucket only"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.customer_data.arn}/"]
    }
  }
  depends_on = [aws_s3_bucket_policy.trail]
}

# ------------------------------------------------------------------ data CloudShield protects
resource "aws_s3_bucket" "customer_data" {
  bucket        = "${local.prefix}-lab-customer-data"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "dummy" {
  for_each = toset(["exports/customers-2026-11.csv", "exports/orders-2026-11.csv", "reports/q3.csv"])
  bucket   = aws_s3_bucket.customer_data.id
  key      = each.value
  content  = "id,name,email\n1,Synthetic Person,person@example.com\n"
}

# Raw-evidence store: versioned + Object Lock (governance mode) so evidence cannot be silently overwritten.
resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.prefix}-evidence"
  object_lock_enabled = true
  force_destroy       = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.evidence_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------------ network + compute
data "aws_vpc" "default" {
  default = true
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/cloudshield/vpc-flow"
  retention_in_days = 14
}

resource "aws_iam_role" "flow_logs" {
  name = "cloudshield-flowlogs-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id          = data.aws_vpc.default.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}

resource "aws_security_group" "app" {
  name        = "cloudshield-lab-app"
  description = "Lab application server"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "app" {
  count                  = var.create_instance ? 1 : 0
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id]
  tags                   = { Name = "cloudshield-lab-app" }
}

# ------------------------------------------------------------------ GuardDuty
resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}

# ------------------------------------------------------------------ EventBridge -> SQS (near real time)
resource "aws_sqs_queue" "events" {
  name                       = "cloudshield-events"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 120
  sqs_managed_sse_enabled    = true
}

resource "aws_cloudwatch_event_rule" "security" {
  name        = "cloudshield-security-events"
  description = "CloudTrail API calls / sign-ins and GuardDuty findings for CloudShield"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail", "GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "sqs" {
  rule = aws_cloudwatch_event_rule.security.name
  arn  = aws_sqs_queue.events.arn
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.events.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.security.arn } }
    }]
  })
}

# ------------------------------------------------------------------ lab principals (no credentials created here)
resource "aws_iam_user" "lab" {
  for_each = toset(["alice", "bob"])
  name     = each.value
  tags     = { role = each.value == "bob" ? "attack-victim" : "baseline" }
}

resource "aws_iam_user_policy_attachment" "lab_readonly" {
  for_each   = aws_iam_user.lab
  user       = each.value.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

# ------------------------------------------------------------------ CloudShield identities
resource "aws_iam_user" "collector" {
  name = "cloudshield-collector"
}

resource "aws_iam_user_policy" "collector" {
  name = "cloudshield-collector-read-only"
  user = aws_iam_user.collector.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus", "cloudtrail:DescribeTrails"], Resource = "*" },
      { Effect = "Allow", Action = ["logs:FilterLogEvents"], Resource = "${aws_cloudwatch_log_group.flow.arn}:*" },
      { Effect = "Allow", Action = ["guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings"], Resource = "*" },
      { Effect = "Allow", Action = ["cloudwatch:GetMetricData", "ec2:DescribeInstances", "s3:ListAllMyBuckets", "iam:ListUsers"], Resource = "*" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"] },
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject"], Resource = "${aws_s3_bucket.evidence.arn}/raw-events/*" },
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.events.arn },
    ]
  })
}

# Write-scoped identity for *approved* response actions (separate from the collector).
resource "aws_iam_user" "responder" {
  name = "cloudshield-responder"
}

resource "aws_iam_user_policy" "responder" {
  name = "cloudshield-responder-actions"
  user = aws_iam_user.responder.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["iam:UpdateAccessKey", "iam:ListAccessKeys", "iam:DetachUserPolicy", "iam:AttachUserPolicy", "iam:RemoveUserFromGroup", "iam:AddUserToGroup"],
      Resource = [for u in aws_iam_user.lab : u.arn] },
      { Effect = "Allow", Action = ["ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress", "ec2:StopInstances", "ec2:StartInstances"], Resource = "*" },
      { Effect = "Allow", Action = ["cloudtrail:StartLogging"], Resource = aws_cloudtrail.main.arn },
      { Effect = "Allow", Action = ["s3:PutBucketPublicAccessBlock"], Resource = aws_s3_bucket.customer_data.arn },
    ]
  })
}

# ------------------------------------------------------------------ cost guard
resource "aws_budgets_budget" "lab" {
  name         = "cloudshield-lab"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
}
