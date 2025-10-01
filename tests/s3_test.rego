package aws.s3.security

# encrypted bucket should pass (no denies)
test_encrypted_bucket_allowed {
  count(deny) == 0 with input as {
    "resource_type": "aws_s3_bucket",
    "server_side_encryption_configuration": {
      "rule": {
        "apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}
      }
    },
    "versioning": {"enabled": true}
  }
}

# unencrypted bucket should be denied
test_unencrypted_bucket_denied {
  count(deny) > 0 with input as {
    "resource_type": "aws_s3_bucket"
  }
}

# public-read bucket should be denied
test_public_read_bucket_denied {
  count(deny) > 0 with input as {
    "resource_type": "aws_s3_bucket",
    "acl": "public-read",
    "server_side_encryption_configuration": {}
  }
}
