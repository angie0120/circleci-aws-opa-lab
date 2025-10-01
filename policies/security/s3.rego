package aws.s3.security

# Deny S3 buckets without encryption
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  not input.server_side_encryption_configuration
  msg := "S3 buckets must have server-side encryption enabled"
}

# Deny S3 buckets that allow public read
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  input.acl == "public-read"
  msg := "S3 buckets must not have public-read ACL"
}

# Warn (non-fatal) if versioning is missing
warn[msg] {
  input.resource_type == "aws_s3_bucket"
  not input.versioning
  msg := "Consider enabling versioning for S3 buckets"
}
