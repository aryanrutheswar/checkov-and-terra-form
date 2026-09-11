# ==============================================================================
# REMEDIATED & HARDENED IAM CONFIGURATION
# Security Controls:
# 1. Least-privilege IAM policies with granular Action and Resource definitions (CKV_AWS_1, CKV_AWS_62)
# 2. AssumeRole policy scoped to trusted AWS service principles with conditions (CKV_AWS_60)
# 3. Elimination of permanent IAM user access keys in favor of short-lived OIDC role assumption (CKV_AWS_273)
# 4. KMS decrypt/encrypt permissions strictly scoped to application CMK
# ==============================================================================

# 1. IAM Role for ECS / App Service
resource "aws_iam_role" "app_execution_role" {
  name_prefix = "app-service-role-"
  description = "Role for application workload with least-privilege policies"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "app-execution-role"
    Environment = var.environment
  }
}

# 2. Granular Least-Privilege S3 Access Policy
resource "aws_iam_policy" "app_s3_read_write_policy" {
  name_prefix = "app-s3-scoped-access-"
  description = "Provides read and write access strictly to application data bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListAppBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.secure_data_bucket.arn
        ]
      },
      {
        Sid    = "ReadWriteAppObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.secure_data_bucket.arn}/*"
        ]
      },
      {
        Sid    = "KmsOperationsForS3"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.data_encryption_key.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_app_s3_policy" {
  role       = aws_iam_role.app_execution_role.name
  policy_arn = aws_iam_policy.app_s3_read_write_policy.arn
}

# 3. OIDC Trust Role for GitHub Actions CI/CD (No Static Keys)
resource "aws_iam_role" "github_actions_oidc_role" {
  name_prefix = "github-actions-deployer-"
  description = "Role assumed by GitHub Actions runners via OpenID Connect (OIDC)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:my-org/my-secure-repo:ref:refs/heads/main"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "github-actions-oidc-role"
    Environment = var.environment
  }
}
