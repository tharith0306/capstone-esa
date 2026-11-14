output "cloudshield_env" {
  description = "Paste into backend/.env (plus credentials for the collector profile)"
  value       = <<-EOT
    CLOUDSHIELD_AWS_REGION=${var.region}
    CLOUDSHIELD_TRAIL_BUCKET=${aws_s3_bucket.trail.id}
    CLOUDSHIELD_VPC_FLOW_LOG_GROUP=${aws_cloudwatch_log_group.flow.name}
    CLOUDSHIELD_SQS_QUEUE_URL=${aws_sqs_queue.events.id}
    CLOUDSHIELD_EVIDENCE_BACKEND=s3
    CLOUDSHIELD_EVIDENCE_BUCKET=${aws_s3_bucket.evidence.id}
  EOT
}

output "sensitive_bucket" {
  value = aws_s3_bucket.customer_data.id
}

output "next_steps" {
  value = "Create access keys for cloudshield-collector (and later cloudshield-responder) in the console, store them as AWS CLI profiles, then follow infrastructure/aws/ATTACK_SIMULATION.md."
}
