variable "region" {
  description = "Home region of the lab"
  type        = string
  default     = "ap-south-1"
}

variable "owner_tag" {
  description = "Tag value identifying who owns the lab resources"
  type        = string
  default     = "cloudshield-capstone"
}

variable "office_cidr" {
  description = "CIDR allowed to reach the lab app on 443 (your public IP /32)"
  type        = string
  default     = "198.51.100.0/24"
}

variable "create_instance" {
  description = "Launch one t3.micro app server (small hourly cost)"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty (30-day free trial, then billed by volume)"
  type        = bool
  default     = true
}

variable "evidence_retention_days" {
  description = "Object Lock retention for raw evidence"
  type        = number
  default     = 7
}

variable "monthly_budget_usd" {
  description = "Budget alert threshold"
  type        = string
  default     = "10"
}

variable "budget_email" {
  description = "Email address that receives the budget alert"
  type        = string
}
