# ==============================================================================
# VULNERABLE SECURITY GROUP CONFIGURATION
# Common Misconfigurations:
# 1. SSH (Port 22) exposed to the entire internet (0.0.0.0/0)
# 2. RDP (Port 3389) open to the internet
# 3. Unrestricted egress without traffic inspection
# 4. Missing rule descriptions for compliance and auditability
# ==============================================================================

resource "aws_security_group" "vulnerable_app_sg" {
  name        = "app-web-sg-vulnerable"
  description = "Security group for web application"
  vpc_id      = "vpc-12345678"

  # Flawed: Global ingress on SSH port
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Flawed: Global ingress on RDP port
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Unrestricted egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "vulnerable-app-sg"
    Environment = var.environment
  }
}
