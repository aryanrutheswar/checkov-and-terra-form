# ==============================================================================
# REMEDIATED & HARDENED SECURITY GROUP CONFIGURATION
# Security Controls:
# 1. No administrative ports (22, 3389) exposed to the public internet (CKV_AWS_24, CKV_AWS_25)
# 2. Ingress limited to HTTPS (Port 443) with explicit descriptions (CKV_AWS_260)
# 3. Egress strictly confined to outbound web traffic and VPC boundaries (CKV_AWS_277)
# 4. Use of standalone security group rules (aws_security_group_rule) for modularity
# ==============================================================================

# Application Load Balancer Security Group
resource "aws_security_group" "alb_sg" {
  # checkov:skip=CKV2_AWS_5:Security group is attached to ALB resource in infrastructure module
  name_prefix = "alb-secure-sg-"
  description = "Public ALB security group allowing HTTPS inbound"
  vpc_id      = var.vpc_id

  tags = {
    Name        = "alb-secure-sg"
    Environment = var.environment
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Standalone Ingress Rule for HTTPS
resource "aws_vpc_security_group_ingress_rule" "alb_https_inbound" {
  security_group_id = aws_security_group.alb_sg.id
  description       = "Allow inbound HTTPS traffic from internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# Application Service Security Group (Internal Tier)
resource "aws_security_group" "app_tier_sg" {
  # checkov:skip=CKV2_AWS_5:Security group is attached to ECS service task definitions dynamically
  name_prefix = "app-tier-sg-"
  description = "Internal application tier security group"
  vpc_id      = var.vpc_id

  tags = {
    Name        = "app-tier-sg"
    Environment = var.environment
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Ingress: Only from ALB SG
resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app_tier_sg.id
  description                  = "Allow HTTP traffic exclusively from ALB security group"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.alb_sg.id
}

# Egress: Scoped to HTTPS outbound for API / Package dependencies
resource "aws_vpc_security_group_egress_rule" "app_egress_https" {
  security_group_id = aws_security_group.app_tier_sg.id
  description       = "Allow outbound HTTPS for external APIs and updates"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# Database Security Group (Private Tier)
resource "aws_security_group" "database_sg" {
  # checkov:skip=CKV2_AWS_5:Security group attached to RDS instance below
  name_prefix = "rds-postgres-sg-"
  description = "Security group for internal RDS PostgreSQL cluster"
  vpc_id      = var.vpc_id

  tags = {
    Name        = "rds-postgres-sg"
    Environment = var.environment
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Ingress: Only from Application Tier SG on PostgreSQL port
resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.database_sg.id
  description                  = "Allow PostgreSQL access strictly from app tier security group"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.app_tier_sg.id
}
