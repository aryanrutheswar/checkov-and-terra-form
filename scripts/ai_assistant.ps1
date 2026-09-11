# ==============================================================================
# AI DevSecOps Assistant & Auto-Remediation Helper (PowerShell)
# Usage:
#   .\scripts\ai_assistant.ps1 -Interactive
#   .\scripts\ai_assistant.ps1 -Query "How to fix CKV_AWS_18"
#   .\scripts\ai_assistant.ps1 -ReportPath "./reports/results_json.json"
#   .\scripts\ai_assistant.ps1 -Remediate "s3"
# ==============================================================================

param(
    [switch]$Interactive = $false,

    [string]$Query = "",

    [string]$ReportPath = "",

    [string]$Remediate = "",

    [ValidateSet("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW")]
    [string]$SeverityFilter = "ALL"
)

function Write-Header {
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host "  AI DevSecOps Security Assistant & Remediation Suite  " -ForegroundColor Cyan
    Write-Host "  IaC Checkov Rule Intelligence & Automated HCL Patching  " -ForegroundColor DarkCyan
    Write-Host "==========================================================" -ForegroundColor Cyan
}

# HCL Code Snippets
$SnippetS3Logging = @"
resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.vulnerable_bucket.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "s3-access-logs/"
}
"@

$SnippetS3Versioning = @"
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
"@

$SnippetS3KMS = @"
resource "aws_s3_bucket_server_side_encryption_configuration" "kms_sse" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.app_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}
"@

$SnippetS3PublicBlock = @"
resource "aws_s3_bucket_public_access_block" "public_block" {
  bucket                  = aws_s3_bucket.vulnerable_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"@

$SnippetSGSSH = @"
ingress {
  description = "Restricted SSH access from corporate VPN"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.100.0.0/16"]
}
"@

$SnippetIAMWildcard = @"
statement {
  effect    = "Allow"
  actions   = ["s3:GetObject", "s3:ListBucket"]
  resources = [aws_s3_bucket.app.arn]
}
"@

$SnippetTagging = @"
tags = {
  Environment = "production"
  Owner       = "secops-team"
  ManagedBy   = "terraform"
}
"@

# Rule Knowledge Base
$RuleDatabase = @{
    "CKV_AWS_18" = @{
        Title       = "Ensure S3 bucket has access logging enabled"
        Severity    = "HIGH"
        Frameworks  = @("CIS AWS 1.4 Section 3.6", "NIST 800-53 AU-2", "SOC 2 CC6.1", "PCI-DSS 10.2")
        Description = "S3 bucket access logging provides detailed records of requests made to a bucket, critical for security auditing."
        Remediation = "Attach an aws_s3_bucket_logging resource pointing to a dedicated centralized log archive bucket."
        Snippet     = $SnippetS3Logging
    }
    "CKV_AWS_21" = @{
        Title       = "Ensure S3 bucket has versioning enabled"
        Severity    = "HIGH"
        Frameworks  = @("CIS AWS 1.4 Section 3.7", "NIST 800-53 CP-9", "SOC 2 A1.2", "HIPAA 164.308")
        Description = "S3 Versioning protects against accidental deletion or overwrite by storing multiple versions of objects."
        Remediation = "Configure aws_s3_bucket_versioning with target status = 'Enabled'."
        Snippet     = $SnippetS3Versioning
    }
    "CKV_AWS_145" = @{
        Title       = "Ensure S3 bucket uses Customer Managed Key (SSE-KMS)"
        Severity    = "HIGH"
        Frameworks  = @("NIST 800-53 SC-13", "PCI-DSS 3.4", "HIPAA 164.312", "SOC 2 CC6.1")
        Description = "Customer Managed KMS Keys (CMK) provide cryptographically isolated key governance and key rotation control."
        Remediation = "Define an aws_kms_key and configure aws_s3_bucket_server_side_encryption_configuration."
        Snippet     = $SnippetS3KMS
    }
    "CKV_AWS_53" = @{
        Title       = "Ensure S3 bucket block public access is enabled"
        Severity    = "CRITICAL"
        Frameworks  = @("CIS AWS 1.4 Section 2.1.5", "NIST 800-53 AC-3", "SOC 2 CC6.3")
        Description = "Enforces the S3 Public Access Block at bucket level to block public ACLs and policies."
        Remediation = "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true."
        Snippet     = $SnippetS3PublicBlock
    }
    "CKV_AWS_24" = @{
        Title       = "Ensure no Security Groups allow ingress from 0.0.0.0/0 to Port 22 (SSH)"
        Severity    = "CRITICAL"
        Frameworks  = @("CIS AWS 1.4 Section 5.2", "NIST 800-53 AC-17", "PCI-DSS 1.3.2")
        Description = "Exposing SSH (Port 22) to unrestricted internet exposes instances to automated brute-force attacks."
        Remediation = "Restrict SSH ingress to trusted bastion CIDR blocks or leverage AWS Systems Manager (SSM) Session Manager."
        Snippet     = $SnippetSGSSH
    }
    "CKV_AWS_109" = @{
        Title       = "Ensure IAM policies do not allow permissions management wildcard (*)"
        Severity    = "CRITICAL"
        Frameworks  = @("CIS AWS 1.4 Section 1.16", "NIST 800-53 AC-6", "SOC 2 CC6.3")
        Description = "Wildcard administrator policies grant unrestricted action privileges, violating Least Privilege."
        Remediation = "Replace wildcard actions '*' with explicit actions (e.g. s3:GetObject, ec2:DescribeInstances)."
        Snippet     = $SnippetIAMWildcard
    }
    "CUSTOM_AWS_001" = @{
        Title       = "Ensure S3 buckets have mandatory cost tracking tags (Environment, Owner, Compliance)"
        Severity    = "MEDIUM"
        Frameworks  = @("Internal DevSecOps Policy - Tagging-SLA")
        Description = "Custom check ensuring S3 resources specify required metadata tags for audit trails and cost governance."
        Remediation = "Add Environment, Owner, and ManagedBy attributes to the resource tags map."
        Snippet     = $SnippetTagging
    }
}

function Show-RuleDetails($ruleId) {
    if ($RuleDatabase.ContainsKey($ruleId)) {
        $rule = $RuleDatabase[$ruleId]
        Write-Host "`n[Rule ID]: $ruleId" -ForegroundColor Yellow
        Write-Host "Title:       $($rule.Title)" -ForegroundColor White
        Write-Host "Severity:    $($rule.Severity)" -ForegroundColor Red
        Write-Host "Frameworks:  $($rule.Frameworks -join ', ')" -ForegroundColor Cyan
        Write-Host "`nDescription:" -ForegroundColor Gray
        Write-Host "$($rule.Description)" -ForegroundColor White
        Write-Host "`nRecommended Remediation:" -ForegroundColor Green
        Write-Host "$($rule.Remediation)" -ForegroundColor White
        Write-Host "`nTerraform HCL Fix Example:" -ForegroundColor DarkGreen
        Write-Host "$($rule.Snippet)" -ForegroundColor Green
    } else {
        Write-Host "`n[Policy Analyzed]: '$ruleId'. Ensure strict compliance according to security best practices." -ForegroundColor Yellow
    }
}

function Invoke-ReportAnalysis($path) {
    if (-not (Test-Path $path)) {
        Write-Host "[ERROR]: Report file not found at: $path" -ForegroundColor Red
        return
    }

    Write-Host "`n[ANALYSIS]: Analyzing Checkov JSON Security Report: $path" -ForegroundColor Cyan
    try {
        $jsonContent = Get-Content -Path $path -Raw | ConvertFrom-Json

        $failedChecks = @()
        if ($jsonContent -is [array]) {
            foreach ($item in $jsonContent) {
                if ($item.results.failed_checks) {
                    $failedChecks += $item.results.failed_checks
                }
            }
        } elseif ($jsonContent.results.failed_checks) {
            $failedChecks = $jsonContent.results.failed_checks
        }

        if ($failedChecks.Count -eq 0) {
            Write-Host "[SUCCESS]: 0 policy violations detected in the report!" -ForegroundColor Green
            return
        }

        Write-Host "Found $($failedChecks.Count) security policy violation(s):`n" -ForegroundColor Yellow

        $index = 1
        foreach ($check in $failedChecks) {
            $severity = if ($check.severity) { $check.severity } else { "HIGH" }
            
            if ($SeverityFilter -ne "ALL" -and $severity -ne $SeverityFilter) {
                continue
            }

            Write-Host "[$index] Check ID: $($check.check_id)" -ForegroundColor Red
            Write-Host "    Name:        $($check.check_name)" -ForegroundColor White
            Write-Host "    Resource:    $($check.resource)" -ForegroundColor Cyan
            Write-Host "    File Path:   $($check.file_path):$($check.file_line_range[0])" -ForegroundColor Gray
            if ($check.guideline) {
                Write-Host "    Guideline:   $($check.guideline)" -ForegroundColor DarkCyan
            }

            if ($RuleDatabase.ContainsKey($check.check_id)) {
                $rule = $RuleDatabase[$check.check_id]
                Write-Host "    AI Remediation Suggestion:" -ForegroundColor Green
                Write-Host "       $($rule.Remediation)" -ForegroundColor DarkGreen
            }

            Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
            $index++
        }
    }
    catch {
        Write-Host "[ERROR]: Error parsing JSON report: $_" -ForegroundColor Red
    }
}

function Show-RemediationPatch($target) {
    Write-Host "`n[PATCH]: Generating Unified AI Remediation Diff for Target: '$target'..." -ForegroundColor Cyan

    $patchS3 = @"
--- terraform/vulnerable/s3.tf
+++ terraform/remediated/s3.tf
@@ -1,15 +1,38 @@
 resource "aws_s3_bucket" "financial_records" {
   bucket = "acme-financial-records-prod-2026"
-  acl    = "public-read-write"
+  # Public ACL removed. Access restricted to IAM & KMS principles.
 }

+# Enforce 4-tier Public Access Block (CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56)
+resource "aws_s3_bucket_public_access_block" "financial_records_block" {
+  bucket                  = aws_s3_bucket.financial_records.id
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
+}

+# Enforce SSE-KMS Key Encryption (CKV_AWS_145)
+resource "aws_s3_bucket_server_side_encryption_configuration" "kms_sse" {
+  bucket = aws_s3_bucket.financial_records.id
+  rule {
+    apply_server_side_encryption_by_default {
+      kms_master_key_id = aws_kms_key.s3_kms_key.arn
+      sse_algorithm     = "aws:kms"
+    }
+    bucket_key_enabled = true
+  }
+}
"@

    Write-Host $patchS3 -ForegroundColor Green
}

function Start-InteractiveSession {
    Write-Header
    Write-Host "Type 'help' for commands, 'rules' for database rules, 'report' to analyze reports, or ask a question." -ForegroundColor Gray
    Write-Host "Type 'exit' or 'quit' to close.`n" -ForegroundColor Gray

    while ($true) {
        $userQuery = Read-Host "AI-DevSecOps>"
        if ([string]::IsNullOrWhiteSpace($userQuery)) { continue }

        $cmd = $userQuery.Trim().ToLower()

        if ($cmd -eq "exit" -or $cmd -eq "quit") {
            Write-Host "Goodbye! Stay secure!" -ForegroundColor Cyan
            break
        }
        elseif ($cmd -eq "help") {
            Write-Host "`nAvailable Commands:" -ForegroundColor Yellow
            Write-Host "  rules        - List all supported rules in knowledge base" -ForegroundColor White
            Write-Host "  report       - Analyze default Checkov scan report (./reports/results_json.json)" -ForegroundColor White
            Write-Host "  remediate    - Show unified HCL remediation patch diff" -ForegroundColor White
            Write-Host "  CKV_AWS_18   - Query specific Checkov policy info" -ForegroundColor White
            Write-Host "  exit / quit  - Exit interactive assistant`n" -ForegroundColor White
        }
        elseif ($cmd -eq "rules") {
            Write-Host "`nSupported Security Policies in Knowledge Base:" -ForegroundColor Yellow
            foreach ($k in $RuleDatabase.Keys) {
                Write-Host " - $k : $($RuleDatabase[$k].Title) [$($RuleDatabase[$k].Severity)]" -ForegroundColor Cyan
            }
            Write-Host ""
        }
        elseif ($cmd -eq "report") {
            $defaultReport = "./reports/results_json.json"
            if (-not (Test-Path $defaultReport)) {
                $defaultReport = "./reports/scan_vulnerable_results_json.json"
            }
            Invoke-ReportAnalysis -path $defaultReport
        }
        elseif ($cmd -eq "remediate") {
            Show-RemediationPatch -target "s3"
        }
        else {
            $foundKey = $null
            foreach ($k in $RuleDatabase.Keys) {
                if ($userQuery.ToUpper().Contains($k)) {
                    $foundKey = $k
                    break
                }
            }

            if ($foundKey) {
                Show-RuleDetails $foundKey
            }
            elseif ($cmd.Contains("s3") -or $cmd.Contains("bucket")) {
                Show-RuleDetails "CKV_AWS_18"
                Show-RuleDetails "CKV_AWS_21"
            }
            elseif ($cmd.Contains("ssh") -or $cmd.Contains("port 22") -or $cmd.Contains("security group")) {
                Show-RuleDetails "CKV_AWS_24"
            }
            elseif ($cmd.Contains("iam") -or $cmd.Contains("wildcard")) {
                Show-RuleDetails "CKV_AWS_109"
            }
            elseif ($cmd.Contains("tag") -or $cmd.Contains("custom")) {
                Show-RuleDetails "CUSTOM_AWS_001"
            }
            else {
                Write-Host "`nAI Assistant Analysis:" -ForegroundColor Cyan
                Write-Host "Analyzing query '$userQuery' against DevSecOps IaC standards..." -ForegroundColor White
                Write-Host "Recommendation: Ensure IaC templates follow Shift-Left security principles by enforcing local pre-commit hooks and checkov CLI scans before git push." -ForegroundColor Gray
            }
        }
    }
}

# MAIN EXECUTION ROUTINE
Write-Header

if ($Interactive) {
    Start-InteractiveSession
}
elseif ($ReportPath -ne "") {
    Invoke-ReportAnalysis -path $ReportPath
}
elseif ($Remediate -ne "") {
    Show-RemediationPatch -target $Remediate
}
elseif ($Query -ne "") {
    $matched = $false
    foreach ($k in $RuleDatabase.Keys) {
        if ($Query.ToUpper().Contains($k)) {
            Show-RuleDetails $k
            $matched = $true
            break
        }
    }
    if (-not $matched) {
        Write-Host "`nAI Assistant Query Analysis:" -ForegroundColor Cyan
        Write-Host "Query: $Query" -ForegroundColor White
        Write-Host "Recommendation: Check IaC code with 'checkov -d ./terraform/vulnerable' and consult CIS AWS Benchmarks." -ForegroundColor Gray
    }
}
else {
    $defaultReport = "./reports/results_json.json"
    if (Test-Path $defaultReport) {
        Invoke-ReportAnalysis -path $defaultReport
    } else {
        Write-Host "Usage Tips:" -ForegroundColor Yellow
        Write-Host "  .\scripts\ai_assistant.ps1 -Interactive" -ForegroundColor White
        Write-Host "  .\scripts\ai_assistant.ps1 -Query 'How to fix CKV_AWS_18'" -ForegroundColor White
        Write-Host "  .\scripts\ai_assistant.ps1 -ReportPath './reports/results_json.json'" -ForegroundColor White
        Write-Host "  .\scripts\ai_assistant.ps1 -Remediate 's3'" -ForegroundColor White
    }
}
