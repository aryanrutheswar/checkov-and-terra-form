# ==============================================================================
# VULNERABLE S3 BUCKET CONFIGURATION
# Common Misconfigurations:
# 1. Bucket ACL is set to "public-read"
# 2. No server-side encryption enabled (unencrypted at rest)
# 3. Versioning disabled (data loss risk)
# 4. Access logging disabled (no audit trail)
# 5. Public access block missing
# ==============================================================================

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "company-data-lake-raw-${var.environment}"
  force_destroy = true

  tags = {
    Environment = var.environment
  }
}

# Misconfiguration: Explicit public-read ACL
resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read" # Flawed: exposes bucket contents publicly
}

# Misconfiguration: Encryption uses default AES256 instead of Customer Managed Key (CMK)
resource "aws_s3_bucket_server_side_encryption_configuration" "vulnerable_sse" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
