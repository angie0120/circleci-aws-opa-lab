provider "aws" {
  region = "us-east-1"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Intentionally non-compliant: missing encryption, plus public-read ACL
resource "aws_s3_bucket" "policy_violation_bucket" {
  bucket = "circleci-lab-violation-${random_string.suffix.result}"
}

resource "aws_s3_bucket_acl" "policy_violation_bucket_acl" {
  bucket = aws_s3_bucket.policy_violation_bucket.id
  acl    = "public-read"
}
