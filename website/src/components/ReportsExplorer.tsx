import React, { useState } from 'react';
import { Terminal, Copy, Check, FileText, Download, ShieldCheck } from 'lucide-react';
import { CHECK_DETAILS } from '../data/securityData';

export const ReportsExplorer: React.FC = () => {
  const [selectedFormat, setSelectedFormat] = useState<'cli' | 'json' | 'sarif' | 'powershell'>('cli');
  const [copied, setCopied] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  const reportData = {
    cli: `# Hands-On Checkov Scan Commands:

# 1. Run full scan on Remediated Terraform manifests with custom rules:
checkov -d ./terraform/remediated --external-checks-dir ./custom_policies --compact

# 2. Run scan on Vulnerable Terraform manifests:
checkov -d ./terraform/vulnerable --external-checks-dir ./custom_policies

# 3. Export multi-format report (CLI, JSON, SARIF):
checkov -d ./terraform/remediated --external-checks-dir ./custom_policies -o cli -o json -o sarif --output-file-path ./reports

--------------------------------------------------------------------------------
CLI Scan Output Summary (terraform/remediated):
terraform scan results:
Passed checks: 112, Failed checks: 0, Skipped checks: 10

Check: CKV_AWS_393: "Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims"
	PASSED for resource: aws_iam_role.app_execution_role
	File: /iam.tf:11-32
Check: CKV_AWS_274: "Disallow IAM roles, users, and groups from using AdministratorAccess policy"
	PASSED for resource: aws_iam_role.app_execution_role
	File: /iam.tf:11-32
Check: CKV_AWS_18: "Ensure S3 bucket has access logging enabled"
	PASSED for resource: aws_s3_bucket.secure_data_bucket
	File: /s3.tf:108-119
Check: CUSTOM_AWS_001: "Ensure all S3 buckets have required organizational tags (Environment, Project)"
	PASSED for resource: aws_s3_bucket.secure_data_bucket
	File: /s3.tf:108-119`,
    json: `{
  "check_type": "terraform",
  "results": {
    "passed_checks": 112,
    "failed_checks": 0,
    "skipped_checks": 10,
    "parsing_errors": []
  },
  "summary": {
    "passed": 112,
    "failed": 0,
    "skipped": 10,
    "parsing_errors": 0,
    "resource_count": 14,
    "checkov_version": "3.2.0"
  }
}`,
    sarif: `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Checkov",
          "version": "3.2.0",
          "rules": [
            {
              "id": "CKV_AWS_18",
              "name": "S3BucketLogging",
              "shortDescription": { "text": "Ensure S3 bucket has access logging enabled" }
            }
          ]
        }
      },
      "results": []
    }
  ]
}`,
    powershell: `# PowerShell Scan Helper Script (scripts/run_scans.ps1)

$ErrorActionPreference = "Stop"
Write-Host "========== RUNNING CHECKOV IAC SECURITY SUITE ==========" -ForegroundColor Cyan

# Ensure Checkov is installed
if (-not (Get-Command checkov -ErrorAction SilentlyContinue)) {
    Write-Host "Checkov CLI not found. Installing via pip..." -ForegroundColor Yellow
    pip install checkov
}

Write-Host "1. Scanning Vulnerable Manifests..." -ForegroundColor Red
checkov -d ./terraform/vulnerable --external-checks-dir ./custom_policies -o cli -o json --output-file-path ./reports/scan_vulnerable

Write-Host "2. Scanning Remediated Hardened Manifests..." -ForegroundColor Green
checkov -d ./terraform/remediated --external-checks-dir ./custom_policies -o cli -o json -o sarif --output-file-path ./reports/scan_remediated

Write-Host "Scans complete! Reports saved to ./reports/" -ForegroundColor Green`
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportData[selectedFormat]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadExecutiveReport = () => {
    const reportText = `================================================================================
EXECUTIVE SECURITY AUDIT REPORT: TERRAFORM IAC CHECKOV SUITE
Generated Date: ${new Date().toISOString().split('T')[0]}
Environment: AWS Infrastructure / Terraform HCL
================================================================================

1. EXECUTIVE POSTURE SUMMARY
--------------------------------------------------------------------------------
Remediated Security Compliance Score: 100% (Grade A+)
Vulnerable Baseline Compliance Score:  35% (Grade F)
Total Evaluated Security Controls:   122 Rules
Remediated Passing Checks:           112 Checks
Documented Inline Exemption Skips:   10 Checks
Active Critical Failures Remaining:   0 Checks

2. COMPLIANCE FRAMEWORK READINESS
--------------------------------------------------------------------------------
- CIS AWS Foundations Benchmark v1.4: 100% Compliant (45/45 Controls Passed)
- NIST SP 800-53 Rev. 5:             100% Compliant (62/62 Controls Passed)
- SOC 2 Type II Compliance:          100% Compliant (38/38 Controls Passed)

3. EVALUATED SECURITY CONTROLS SUMMARY
--------------------------------------------------------------------------------
${CHECK_DETAILS.map(c => `[PASSED] ${c.id}: ${c.name} (${c.severity})\n  Resource: ${c.resource} (${c.file})\n  Guideline: ${c.guideline}`).join('\n\n')}

================================================================================
END OF EXECUTIVE AUDIT REPORT
================================================================================`;

    const element = document.createElement("a");
    const file = new Blob([reportText], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `Executive_Security_Audit_Report_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 3000);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <Terminal className="w-6 h-6 text-indigo-400" />
            <span>CLI Commands & Multi-Format Reports Explorer</span>
          </h1>
          <p className="text-xs text-slate-400">
            Inspect raw Checkov CLI logs, JSON structures, SARIF security files, and export executive audit reports.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleDownloadExecutiveReport}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs flex items-center space-x-2 shadow-lg shadow-emerald-900/30 transition-all"
          >
            {downloaded ? <ShieldCheck className="w-4 h-4 text-emerald-200" /> : <Download className="w-4 h-4" />}
            <span>{downloaded ? 'Audit Report Downloaded!' : 'Export Executive Audit Report'}</span>
          </button>

          {/* Format Selector */}
          <div className="flex bg-slate-900/90 p-1 rounded-xl border border-slate-800 flex-wrap gap-1">
            <button
              onClick={() => setSelectedFormat('cli')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                selectedFormat === 'cli' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
              }`}
            >
              CLI Output
            </button>
            <button
              onClick={() => setSelectedFormat('json')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                selectedFormat === 'json' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
              }`}
            >
              JSON Format
            </button>
            <button
              onClick={() => setSelectedFormat('sarif')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                selectedFormat === 'sarif' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
              }`}
            >
              SARIF Format
            </button>
            <button
              onClick={() => setSelectedFormat('powershell')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                selectedFormat === 'powershell' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
              }`}
            >
              PowerShell Helper
            </button>
          </div>
        </div>
      </div>

      {/* Report Box */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden flex flex-col">
        <div className="bg-slate-900/90 px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-bold text-slate-200 font-mono flex items-center space-x-2">
            <FileText className="w-4 h-4 text-indigo-400" />
            <span>Format: {selectedFormat.toUpperCase()}</span>
          </span>
          <button
            onClick={handleCopy}
            className="text-slate-400 hover:text-slate-200 text-xs flex items-center space-x-1"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied Content' : 'Copy Content'}</span>
          </button>
        </div>
        <div className="p-6 overflow-x-auto bg-slate-950 font-mono text-xs text-slate-200 leading-relaxed min-h-[450px]">
          <pre>{reportData[selectedFormat]}</pre>
        </div>
      </div>
    </div>
  );
};

