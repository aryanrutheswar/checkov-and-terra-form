output "vulnerable_bucket_arn" {
  description = "ARN of the vulnerable S3 bucket"
  value       = aws_s3_bucket.vulnerable_bucket.arn
}

output "vulnerable_db_endpoint" {
  description = "Endpoint of the vulnerable RDS instance"
  value       = aws_db_instance.vulnerable_postgres.endpoint
}
