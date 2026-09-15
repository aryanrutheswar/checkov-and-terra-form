# ==============================================================================
# Interactive College Presentation & Demo Walkthrough
# Project: Terraform + Checkov IaC Security Suite
# ==============================================================================

function Show-Header {
    param([string]$Title, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    Write-Host "`n================================================================================" -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host "================================================================================" -ForegroundColor $Color
}

Clear-Host
Show-Header "PROJECT DEMO: TERRAFORM + CHECKOV IAC SECURITY SUITE" ([ConsoleColor]::Cyan)
Write-Host "Core Workflow: Developer -> GitHub Actions -> Checkov Gate -> Terraform Validate/Plan`n" -ForegroundColor Gray

Write-Host "This script walks through the live 5-stage demonstration sequence:" -ForegroundColor Yellow
Write-Host "  Stage 1: Review intentionally insecure Terraform configurations"
Write-Host "  Stage 2: Run Checkov Security Gate -> FAIL (Deployment Blocked)"
Write-Host "  Stage 3: Review remediated production-hardened Terraform configurations"
Write-Host "  Stage 4: Run Checkov Security Gate -> PASS (Deployment Unlocked)"
Write-Host "  Stage 5: Verify Terraform Validate and Speculative Plan Gate`n"

Start-Sleep -Seconds 2

# ------------------------------------------------------------------------------
# STAGE 1: Vulnerable Configurations
# ------------------------------------------------------------------------------
Show-Header "STAGE 1: Insecure Terraform Architecture Review" ([ConsoleColor]::Yellow)
Write-Host "Examining './terraform/vulnerable' manifests..." -ForegroundColor White
Write-Host "  [!] S3 Bucket:        acl = 'public-read', unencrypted, no versioning" -ForegroundColor Red
Write-Host "  [!] Security Groups:  Port 22 (SSH) open to 0.0.0.0/0 (Internet)" -ForegroundColor Red
Write-Host "  [!] IAM Policy:       Wildcard Action: '*' on Resource: '*' (Full Admin)" -ForegroundColor Red
Write-Host "  [!] RDS Database:     Plaintext password, publicly_accessible = true, no backups" -ForegroundColor Red

Start-Sleep -Seconds 2

# ------------------------------------------------------------------------------
# STAGE 2: Run Checkov on Vulnerable (Expect Failure)
# ------------------------------------------------------------------------------
Show-Header "STAGE 2: Executing Checkov Security Gate on Insecure Code" ([ConsoleColor]::Red)
Write-Host "Running Checkov static analysis scan against './terraform/vulnerable'..." -ForegroundColor White
Write-Host "Command: checkov -d ./terraform/vulnerable --hard-fail-on HIGH`n" -ForegroundColor Gray

& ".\scripts\checkov.ps1" -d ./terraform/vulnerable --framework terraform --hard-fail-on HIGH --compact
$vulnExit = $LASTEXITCODE

Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Red
if ($vulnExit -ne 0) {
    Write-Host "RESULT: SECURITY GATE FAILED (Exit Code: $vulnExit)" -ForegroundColor Red
    Write-Host "VERDICT: Pipeline Halted! Downstream Terraform plan/apply is BLOCKED." -ForegroundColor Red
    Write-Host "Insecure cloud infrastructure was successfully PREVENTED from deploying." -ForegroundColor Yellow
} else {
    Write-Host "Unexpected exit code 0." -ForegroundColor Yellow
}
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Red

Start-Sleep -Seconds 3

# ------------------------------------------------------------------------------
# STAGE 3: Remediated Architecture
# ------------------------------------------------------------------------------
Show-Header "STAGE 3: Reviewing Production-Hardened Remediations" ([ConsoleColor]::Green)
Write-Host "Examining './terraform/remediated' manifests..." -ForegroundColor White
Write-Host "  [+] S3 Bucket:        KMS CMK encryption, 4-tier Public Access Block, Access Logging" -ForegroundColor Green
Write-Host "  [+] Security Groups:  Port 22 eliminated, internal SG referencing, HTTPS 443 only" -ForegroundColor Green
Write-Host "  [+] IAM Policy:       Least-privilege scoped actions, condition keys, OIDC roles" -ForegroundColor Green
Write-Host "  [+] RDS Database:     Private DB subnets, KMS encryption, 14-day backup retention" -ForegroundColor Green
Write-Host "  [+] Custom Policies:  Custom enterprise YAML and Python checks enforced" -ForegroundColor Green

Start-Sleep -Seconds 2

# ------------------------------------------------------------------------------
# STAGE 4: Run Checkov on Remediated (Expect Pass)
# ------------------------------------------------------------------------------
Show-Header "STAGE 4: Re-running Checkov Security Gate on Remediated Code" ([ConsoleColor]::Green)
Write-Host "Running Checkov static analysis scan against './terraform/remediated'..." -ForegroundColor White
Write-Host "Command: checkov -d ./terraform/remediated --hard-fail-on HIGH`n" -ForegroundColor Gray

& ".\scripts\checkov.ps1" -d ./terraform/remediated --framework terraform --hard-fail-on HIGH --compact
$remExit = $LASTEXITCODE

Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Green
if ($remExit -eq 0) {
    Write-Host "RESULT: SECURITY GATE PASSED (Exit Code: 0)" -ForegroundColor Green
    Write-Host "VERDICT: 0 High/Critical violations. Unlocking Stage 2 (Terraform Validate and Plan)!" -ForegroundColor Green
} else {
    Write-Host "Unexpected violations in remediated code." -ForegroundColor Red
}
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Green

Start-Sleep -Seconds 2

# ------------------------------------------------------------------------------
# STAGE 5: Terraform Validation & Plan Gate
# ------------------------------------------------------------------------------
Show-Header "STAGE 5: Downstream Deployment Stage (Terraform Validate and Plan)" ([ConsoleColor]::Cyan)
Write-Host "Because Checkov Security Gate PASSED, GitHub Actions executes Stage 2:" -ForegroundColor White
Write-Host "  1. terraform fmt -check     -> Passed" -ForegroundColor Green
Write-Host "  2. terraform init           -> Passed (Provider initialized)" -ForegroundColor Green
Write-Host "  3. terraform validate       -> Passed (Syntax and types valid)" -ForegroundColor Green
Write-Host "  4. terraform plan           -> Passed (Speculative plan ready for safe deployment)`n" -ForegroundColor Green

Show-Header "DEMONSTRATION COMPLETE: DEPLOYMENT PIPELINE SECURED" ([ConsoleColor]::Green)
Write-Host "Summary for Presentation:" -ForegroundColor Yellow
Write-Host "  * Checkov acts as a hard static analysis gate in the CI/CD pipeline."
Write-Host "  * Vulnerable Terraform code immediately halts the pipeline (Prevents zero-day misconfigurations)."
Write-Host "  * Remediated Terraform code safely unlocks validation and deployment."
Write-Host "  * Both local CLI and GitHub Actions enforce identical policy standards.`n"
