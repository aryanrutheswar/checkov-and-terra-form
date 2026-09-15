# ==============================================================================
# Checkov Security Scan Runner (PowerShell)
# Usage:
#   .\scripts\run_scans.ps1 -Target "vulnerable"
#   .\scripts\run_scans.ps1 -Target "remediated" -Severity "HIGH" -Framework "terraform"
# ==============================================================================

param(
    [ValidateSet("vulnerable", "remediated", "all")]
    [string]$Target = "remediated",

    [ValidateSet("terraform", "dockerfile", "kubernetes", "all")]
    [string]$Framework = "terraform",

    [ValidateSet("LOW", "MEDIUM", "HIGH", "CRITICAL")]
    [string]$Severity = "HIGH",

    [ValidateSet("cli", "json", "sarif", "all")]
    [string]$ExportFormat = "all",

    [switch]$SoftFail = $false,

    [switch]$AIAssistant = $false
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  IaC Security Scanner: Checkov Multi-Framework Suite" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$checkovCmd = Get-Command checkov -ErrorAction SilentlyContinue
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue

if (-not $checkovCmd -and -not $pythonCmd) {
    Write-Warning "Neither Checkov nor Python was found in PATH."
    Write-Host "Install checkov via: pip install checkov" -ForegroundColor Yellow
    exit 1
}

# Create reports directory
if (-not (Test-Path -Path "./reports")) {
    New-Item -ItemType Directory -Path "./reports" | Out-Null
}

$targetsToScan = @()
if ($Target -eq "all") {
    $targetsToScan += "vulnerable"
    $targetsToScan += "remediated"
}
else {
    $targetsToScan += $Target
}

$overallExitCode = 0

foreach ($t in $targetsToScan) {
    Write-Host "`n>>> Scanning target suite: ./terraform/$t (Framework: $Framework)" -ForegroundColor Green
    $scanDir = "./terraform/$t"
    $reportDir = "./reports"

    $argsList = @(
        "-d", $scanDir,
        "--external-checks-dir", "./custom_policies/yaml",
        "--external-checks-dir", "./custom_policies/python",
        "--hard-fail-on", $Severity
    )

    if ($Framework -ne "all") {
        $argsList += @("--framework", $Framework)
    }

    if ($ExportFormat -eq "all") {
        $argsList += @("--output", "cli", "--output", "json", "--output", "sarif", "--output-file-path", $reportDir)
    } else {
        $argsList += @("--output", $ExportFormat, "--output-file-path", $reportDir)
    }

    if ($SoftFail) {
        $argsList += "--soft-fail"
    }

    if ($checkovCmd) {
        & checkov @argsList
    }
    else {
        $pyArgs = @("-c", "import sys; from checkov.main import Checkov; sys.argv=['checkov'] + sys.argv[1:]; sys.exit(Checkov().run())") + $argsList
        & python @pyArgs
    }
    $exitCode = $LASTEXITCODE

    # Copy target specific reports for archival
    if (Test-Path "./reports/results_json.json") {
        Copy-Item "./reports/results_json.json" -Destination "./reports/scan_${t}_results_json.json" -Force -ErrorAction SilentlyContinue
    }

    if ($exitCode -eq 0) {
        Write-Host "`n[PASSED] Target '$t' passed security policy checks with 0 critical/high violations." -ForegroundColor Green
    }
    else {
        Write-Host "`n[VIOLATIONS DETECTED] Target '$t' identified policy violations (Exit code: $exitCode)." -ForegroundColor Red
        $overallExitCode = $exitCode
    }
}

Write-Host "`nReports generated in ./reports/" -ForegroundColor Cyan

if ($AIAssistant) {
    Write-Host "`n🤖 Launching AI DevSecOps Assistant Analysis..." -ForegroundColor Cyan
    & ".\scripts\ai_assistant.ps1"
}

if ($overallExitCode -ne 0 -and -not $SoftFail) {
    Write-Host "`n[SECURITY GATE FAILED] Halting pipeline execution due to high/critical violations." -ForegroundColor Red
    exit $overallExitCode
}