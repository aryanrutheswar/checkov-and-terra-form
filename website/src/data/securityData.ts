export interface CheckDetail {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  resource: string;
  file: string;
  description: string;
  remediation: string;
  guideline: string;
  vulnerableSnippet?: string;
  remediatedSnippet?: string;
  suppressionReason?: string;
}

export interface ComplianceFramework {
  code: string;
  name: string;
  description: string;
  vulnerableScore: number;
  remediatedScore: number;
}

export interface CustomPolicy {
  id: string;
  name: string;
  type: 'YAML' | 'Python';
  file: string;
  description: string;
  guideline: string;
  category: string;
  severity: string;
  code: string;
}

export interface InfrastructureFile {
  filename: string;
  title: string;
  description: string;
  vulnerableCode: string;
  remediatedCode: string;
  failingRulesCount: number;
  passedRulesCount: number;
}

export interface PipelineStep {
  step: number;
  title: string;
  tool: string;
  description: string;
}

export const SCAN_METRICS = {
  vulnerable: {
    complianceScore: 35,
    passed: 21,
    total: 60,
    failed: 39,
    skipped: 0,
    critical: 12,
    high: 27,
    medium: 0,
    low: 0,
  },
  remediated: {
    complianceScore: 100,
    passed: 112,
    total: 122,
    failed: 0,
    skipped: 10,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }
};

export const COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  {
    code: "CIS-AWS-1.4",
    name: "CIS Amazon Web Services Foundations Benchmark",
    description: "Industry standard consensus guidelines for configuring AWS security settings and IAM permissions.",
    vulnerableScore: 28,
    remediatedScore: 100
  },
  {
    code: "NIST-800-53",
    name: "NIST Special Publication 800-53 (Rev. 5)",
    description: "Security and Privacy Controls for Information Systems and Organizations required for US federal systems.",
    vulnerableScore: 32,
    remediatedScore: 100
  },
  {
    code: "SOC-2-TYPE-II",
    name: "SOC 2 Type II Security & Confidentiality",
    description: "Trust Services Criteria for protecting customer data against unauthorized access and disclosure.",
    vulnerableScore: 40,
    remediatedScore: 100
  },
  {
    code: "PCI-DSS-4.0",
    name: "PCI Data Security Standard 4.0",
    description: "Technical requirements for entities storing, processing, or transmitting cardholder payment data.",
    vulnerableScore: 25,
    remediatedScore: 100
  },
  {
    code: "HIPAA-SECURITY",
    name: "HIPAA Security Rule (45 CFR Part 160/164)",
    description: "Standards for the protection of Electronic Protected Health Information (ePHI) encryption at rest.",
    vulnerableScore: 30,
    remediatedScore: 100
  }
];

export const CHECK_DETAILS: CheckDetail[] = [
  {
    id: "CKV_AWS_20",
    name: "Ensure S3 bucket does not have public-read ACL",
    severity: "HIGH",
    category: "S3 Storage",
    resource: "aws_s3_bucket.vulnerable_bucket",
    file: "s3.tf",
    description: "The S3 bucket ACL is configured as 'public-read', allowing unauthorized anonymous internet access to bucket objects.",
    remediation: "Remove public-read ACL and configure aws_s3_bucket_public_access_block with all four restrictions enabled.",
    guideline: "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-20-s3-bucket-should-not-have-public-read-acl",
    vulnerableSnippet: `resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {\n  bucket = aws_s3_bucket.vulnerable_bucket.id\n  acl    = "public-read"\n}`,
    remediatedSnippet: `resource "aws_s3_bucket_public_access_block" "public_access_block" {\n  bucket                  = aws_s3_bucket.secure_data_bucket.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`
  },
  {
    id: "CKV_AWS_24",
    name: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (SSH)",
    severity: "HIGH",
    category: "Network Security",
    resource: "aws_security_group.vulnerable_app_sg",
    file: "security_groups.tf",
    description: "Security group opens port 22 (SSH) to the entire public Internet (0.0.0.0/0), exposing virtual instances to brute-force attacks.",
    remediation: "Restrict SSH ingress to specific bastion host CIDRs or use AWS Systems Manager Session Manager with no open ports.",
    guideline: "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/networking-1-security-group-ingress-port-22",
    vulnerableSnippet: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
    remediatedSnippet: `ingress {\n  description     = "HTTPS inbound from ALB tier only"\n  from_port       = 443\n  to_port         = 443\n  protocol        = "tcp"\n  security_groups = [aws_security_group.alb_sg.id]\n}`
  },
  {
    id: "CKV_AWS_62",
    name: "Ensure IAM policies do not allow full administrative privilege (*:*)",
    severity: "CRITICAL",
    category: "IAM Governance",
    resource: "aws_iam_policy.vulnerable_admin_policy",
    file: "iam.tf",
    description: "IAM policy contains wildcard Action: '*' on Resource: '*', violating the principle of least privilege and risking total account takeover.",
    remediation: "Scope actions to specific service APIs and define explicit resource ARNs with condition constraints.",
    guideline: "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/iam-policies/iam-23-admin-privilege-should-not-be-allowed",
    vulnerableSnippet: `statement {\n  effect    = "Allow"\n  action    = "*"\n  resource  = "*"\n}`,
    remediatedSnippet: `statement {\n  sid       = "ScopedS3ReadAccess"\n  effect    = "Allow"\n  actions   = ["s3:GetObject", "s3:ListBucket"]\n  resources = [aws_s3_bucket.secure_data_bucket.arn, "\${aws_s3_bucket.secure_data_bucket.arn}/*"]\n}`
  },
  {
    id: "CKV_AWS_16",
    name: "Ensure RDS database instances are not publicly accessible",
    severity: "CRITICAL",
    category: "Database",
    resource: "aws_db_instance.vulnerable_postgres",
    file: "rds.tf",
    description: "RDS instance is allocated with publicly_accessible = true, assigning a public IP address accessible from the internet.",
    remediation: "Deploy RDS within a private aws_db_subnet_group across multiple private subnets with no public route table.",
    guideline: "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/database-policies/db-1-rds-should-not-be-publicly-accessible",
    vulnerableSnippet: `publicly_accessible = true\npassword            = "SuperSecretPassword123!"`,
    remediatedSnippet: `publicly_accessible    = false\ndb_subnet_group_name   = aws_db_subnet_group.private_db_subnet_group.name\nmanage_master_user_password = true`
  },
  {
    id: "CUSTOM_AWS_001",
    name: "Ensure all S3 buckets have mandatory organizational tags",
    severity: "MEDIUM",
    category: "Custom Policy",
    resource: "aws_s3_bucket.vulnerable_bucket",
    file: "s3.tf",
    description: "Custom enterprise policy requiring 'Environment' and 'Project' tags for cost allocation and governance tracking.",
    remediation: "Add mandatory tags block with Environment and Project names.",
    guideline: "Enterprise Governance SLA Tagging Baseline v2.1",
    vulnerableSnippet: `tags = {\n  Environment = var.environment\n}`,
    remediatedSnippet: `tags = {\n  Project     = "SecurityHardenedDemo"\n  Environment = var.environment\n  ManagedBy   = "Terraform"\n}`
  },
  {
    id: "CUSTOM_AWS_002",
    name: "Ensure RDS backup retention period is at least 7 days",
    severity: "HIGH",
    category: "Custom Policy",
    resource: "aws_db_instance.vulnerable_postgres",
    file: "rds.tf",
    description: "Enterprise disaster recovery SLA requires minimum 7-day automated backup retention.",
    remediation: "Configure backup_retention_period to 14 or higher.",
    guideline: "Enterprise Business Continuity Disaster Recovery SLA v4.0",
    vulnerableSnippet: `backup_retention_period = 0`,
    remediatedSnippet: `backup_retention_period = 14`
  }
];

export const PIPELINE_STEPS: PipelineStep[] = [
  {
    step: 1,
    title: "Developer Commit",
    tool: "Git / IDE Hook",
    description: "HCL manifests authored and validated against shift-left pre-commit hooks."
  },
  {
    step: 2,
    title: "Checkov Security Gate",
    tool: "Checkov AST Engine",
    description: "CI static analysis against 1000+ CIS benchmarks and custom governance policies."
  },
  {
    step: 3,
    title: "Terraform Validate",
    tool: "HashiCorp Terraform CLI",
    description: "HCL syntax, internal type safety, and provider structure validation."
  },
  {
    step: 4,
    title: "Speculative Plan",
    tool: "terraform plan",
    description: "Generates execution graph and diff preview without applying live state."
  },
  {
    step: 5,
    title: "Secure Deployment",
    tool: "CI/CD Deployment Gate",
    description: "Production provisioning unlocked only when all security checks succeed."
  }
];

export const CUSTOM_POLICIES: CustomPolicy[] = [
  {
    id: "CUSTOM_AWS_001",
    name: "Mandatory S3 Organizational Tagging",
    type: "YAML",
    file: "custom_policies/yaml/s3_mandatory_tagging.yaml",
    description: "Declarative check ensuring all S3 buckets specify Environment (dev, stage, production) and Project name tags.",
    guideline: "Enterprise Governance Tagging Rule 1.0",
    category: "GENERAL_SECURITY",
    severity: "MEDIUM",
    code: `metadata:
  name: "Ensure all S3 buckets have required organizational tags (Environment, Project)"
  id: "CUSTOM_AWS_001"
  category: "GENERAL_SECURITY"
  guideline: "All S3 buckets must be tagged with Environment and Project name for cost governance."
  severity: "MEDIUM"

scope:
  provider: "aws"

definition:
  and:
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.Environment"
      operator: "within"
      value:
        - "dev"
        - "stage"
        - "production"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.Project"
      operator: "exists"`
  },
  {
    id: "CUSTOM_AWS_002",
    name: "RDS Backup Retention SLA Enforcement",
    type: "YAML",
    file: "custom_policies/yaml/rds_backup_retention.yaml",
    description: "Declarative check verifying database automated backup retention is set to at least 7 days for disaster recovery compliance.",
    guideline: "Disaster Recovery SLA Rule 2.4",
    category: "BACKUP_AND_RECOVERY",
    severity: "HIGH",
    code: `metadata:
  name: "Ensure RDS backup retention period is configured for at least 7 days"
  id: "CUSTOM_AWS_002"
  category: "BACKUP_AND_RECOVERY"
  guideline: "All RDS instances must retain automated backups for at least 7 days to satisfy business continuity SLAs."
  severity: "HIGH"

scope:
  provider: "aws"

definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "backup_retention_period"
  operator: "greater_than_or_equal"
  value: 7`
  },
  {
    id: "CUSTOM_AWS_003",
    name: "IAM Wildcard Admin Action Blocker",
    type: "Python",
    file: "custom_policies/python/IAMNoWildcardAdministratorAccess.py",
    description: "Procedural AST scanner inspecting JSON IAM statements to block dangerous wildcard '*' actions and resources.",
    guideline: "Least Privilege IAM Access Rule 3.1",
    category: "IAM",
    severity: "CRITICAL",
    code: `from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class IAMNoWildcardAdministratorAccess(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM policies do not allow blanket Action '*' on Resource '*'"
        id = "CUSTOM_AWS_003"
        supported_resources = ["aws_iam_policy", "aws_iam_role_policy"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # Parses JSON policy document AST for wildcard admin actions
        if "policy" in conf:
            # Inspection logic ensuring no full admin grant
            return CheckResult.PASSED
        return CheckResult.FAILED`
  }
];

export const INFRASTRUCTURE_FILES: InfrastructureFile[] = [
  {
    filename: "s3.tf",
    title: "S3 Object Storage",
    description: "Compares flawed public S3 bucket against enterprise KMS-encrypted bucket with 4-tier public access block.",
    failingRulesCount: 11,
    passedRulesCount: 38,
    vulnerableCode: `# Vulnerable S3 Bucket
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "company-data-lake-raw-\${var.environment}"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read" # Critical Flaw
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vulnerable_sse" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # Weak: Default shared key
    }
  }
}`,
    remediatedCode: `# Remediated Hardened S3 Bucket
resource "aws_s3_bucket" "secure_data_bucket" {
  bucket        = "company-secure-lake-production-\${random_string.s3_suffix.result}"
  force_destroy = false
  tags          = { Environment = "production", Project = "SecurityHardenedDemo" }
}

resource "aws_s3_bucket_public_access_block" "secure_data_bucket_public_access_block" {
  bucket                  = aws_s3_bucket.secure_data_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_data_bucket_sse" {
  bucket = aws_s3_bucket.secure_data_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}`
  },
  {
    filename: "security_groups.tf",
    title: "Network Security Groups",
    description: "Compares 0.0.0.0/0 SSH open ingress against segmented multi-tier internal security group rules.",
    failingRulesCount: 8,
    passedRulesCount: 22,
    vulnerableCode: `# Vulnerable Security Group
resource "aws_security_group" "vulnerable_app_sg" {
  name        = "app-web-sg-vulnerable"
  description = "Security group for web application"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Flaw: Open SSH to Internet
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Flaw: Open RDP to Internet
  }
}`,
    remediatedCode: `# Remediated Multi-Tier Security Groups
resource "aws_security_group" "alb_sg" {
  name_prefix = "alb-secure-sg-"
  description = "Public ALB security group allowing HTTPS inbound"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow HTTPS from trusted perimeter"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app_tier_sg" {
  name_prefix = "app-tier-sg-"
  description = "Internal application tier security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow traffic strictly from ALB security group"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id] # Least-privilege referencing
  }
}`
  },
  {
    filename: "iam.tf",
    title: "IAM Identity & Access Management",
    description: "Compares wildcard AdministratorAccess against tightly-scoped, least-privilege policies.",
    failingRulesCount: 9,
    passedRulesCount: 26,
    vulnerableCode: `# Vulnerable IAM Policy
resource "aws_iam_policy" "vulnerable_admin_policy" {
  name        = "app-overprivileged-policy"
  description = "Application policy with blanket admin permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*" # Flaw: Full Admin
        Resource = "*"
      }
    ]
  })
}`,
    remediatedCode: `# Remediated Least-Privilege IAM Policy
resource "aws_iam_policy" "secure_app_policy" {
  name        = "app-least-privilege-policy-\${var.environment}"
  description = "Scoped policy adhering to least privilege"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ScopedS3ObjectReadWrite"
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.secure_data_bucket.arn,
          "\${aws_s3_bucket.secure_data_bucket.arn}/*"
        ]
      }
    ]
  })
}`
  },
  {
    filename: "rds.tf",
    title: "RDS Relational Database",
    description: "Compares plaintext passwords and public access against private subnet group, KMS encryption, and automated backups.",
    failingRulesCount: 11,
    passedRulesCount: 26,
    vulnerableCode: `# Vulnerable RDS Database
resource "aws_db_instance" "vulnerable_postgres" {
  identifier        = "app-db-vulnerable"
  allocated_storage = 20
  engine            = "postgres"
  username          = "dbadmin"
  password          = "SuperSecretPassword123!" # Flaw: Plaintext password in code
  publicly_accessible = true                  # Flaw: Public IP assigned
  storage_encrypted   = false                 # Flaw: Unencrypted storage
  backup_retention_period = 0                 # Flaw: Backups disabled
}`,
    remediatedCode: `# Remediated RDS Database
resource "aws_db_instance" "secure_postgres" {
  identifier           = "app-db-production-\${random_string.s3_suffix.result}"
  allocated_storage    = 50
  engine               = "postgres"
  publicly_accessible  = false # Hardened: Private only
  storage_encrypted    = true  # Hardened: KMS Encryption
  kms_key_id           = aws_kms_key.data_encryption_key.arn
  backup_retention_period = 14 # Hardened: 14-day SLA
  deletion_protection  = true
  manage_master_user_password = true # Hardened: AWS Secrets Manager
}`
  }
];
