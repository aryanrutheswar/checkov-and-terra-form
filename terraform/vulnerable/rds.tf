# ==============================================================================
# VULNERABLE RDS DATABASE CONFIGURATION
# Common Misconfigurations:
# 1. Database instance is publicly accessible on the internet
# 2. Storage encryption at rest is disabled
# 3. Backup retention period is 0 (backups disabled)
# 4. Plaintext password hardcoded in resource definition
# 5. IAM Database Authentication disabled
# 6. Deletion protection disabled
# ==============================================================================

resource "aws_db_instance" "vulnerable_postgres" {
  identifier        = "app-db-vulnerable"
  allocated_storage = 20
  engine            = "postgres"
  engine_version    = "15.3"
  instance_class    = "db.t3.micro"

  # Flawed: Plaintext credentials stored directly in version control
  username = "dbadmin"
  password = "SuperSecretPassword123!"

  # Flawed: Publicly accessible
  publicly_accessible = true

  # Flawed: Encryption at rest disabled
  storage_encrypted = false

  # Flawed: No automated backups retained
  backup_retention_period = 0

  # Flawed: Automated minor version upgrades disabled
  auto_minor_version_upgrade = false

  # Flawed: No deletion protection
  deletion_protection = false

  skip_final_snapshot = true

  tags = {
    Environment = var.environment
  }
}
