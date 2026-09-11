output "kms_key_arn" {
  description = "Customer Managed KMS Key ARN"
  value       = aws_kms_key.data_encryption_key.arn
}

output "secure_bucket_id" {
  description = "The ID of the hardened S3 bucket"
  value       = aws_s3_bucket.secure_data_bucket.id
}

output "database_endpoint" {
  description = "The endpoint of the hardened RDS database"
  value       = aws_db_instance.secure_postgres.endpoint
}
