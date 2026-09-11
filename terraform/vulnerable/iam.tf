# ==============================================================================
# VULNERABLE IAM POLICY & ROLE CONFIGURATION
# Common Misconfigurations:
# 1. Over-permissive wildcard permissions ("Action": "*", "Resource": "*")
# 2. Hardcoded access keys generated for long-term use
# 3. Role trust policy allowing wildcard Principal ("*")
# ==============================================================================

resource "aws_iam_role" "vulnerable_app_role" {
  name = "app-service-role-vulnerable"

  # Flawed: Overly permissive trust policy
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = "*" # Flawed: Anyone in AWS could assume this role if misconfigured
      }
    ]
  })
}

resource "aws_iam_policy" "vulnerable_admin_policy" {
  name        = "app-overprivileged-policy"
  description = "Application policy with blanket admin permissions"

  # Flawed: Full administrative wildcard rights
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vulnerable_attach" {
  role       = aws_iam_role.vulnerable_app_role.name
  policy_arn = aws_iam_policy.vulnerable_admin_policy.arn
}

resource "aws_iam_user" "vulnerable_deployer" {
  name = "legacy-deployer-service-account"
}

# Flawed: Creating long-lived static credentials
resource "aws_iam_access_key" "vulnerable_deployer_key" {
  user = aws_iam_user.vulnerable_deployer.name
}
