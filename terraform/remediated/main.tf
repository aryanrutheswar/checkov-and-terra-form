terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "SecurityHardenedDemo"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Compliance  = "CIS-AWS-Benchmark"
    }
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region for deployment"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
}

variable "vpc_id" {
  type        = string
  description = "Target VPC ID"
  default     = "vpc-0123456789abcdef0"
}

variable "database_subnet_ids" {
  type        = list(string)
  description = "Subnets for RDS Database"
  default     = ["subnet-0123456789abcdef1", "subnet-0123456789abcdef2"]
}

# Customer-Managed KMS Key for Encryption-at-Rest
resource "aws_kms_key" "data_encryption_key" {
  description             = "Customer managed KMS key for S3 and RDS storage encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true # Hardened: automatic annual key rotation (CKV_AWS_7)

  # Explicit KMS Key Policy restricting administration to account root (CKV2_AWS_64)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "cmk-data-encryption-${var.environment}"
  }
}

resource "aws_kms_alias" "data_encryption_key_alias" {
  name          = "alias/app-data-key-${var.environment}"
  target_key_id = aws_kms_key.data_encryption_key.key_id
}
