import React, { useState } from 'react';
import { Play, ShieldCheck, ShieldAlert, Code2, Sparkles, RefreshCw } from 'lucide-react';

export const InteractiveSandbox: React.FC = () => {
  const presets = [
    {
      title: "S3 Bucket Public ACL (Flawed)",
      code: `resource "aws_s3_bucket" "my_bucket" {
  bucket = "company-sensitive-logs"
}

resource "aws_s3_bucket_acl" "my_bucket_acl" {
  bucket = aws_s3_bucket.my_bucket.id
  acl    = "public-read" # Flawed: exposes bucket publicly
}`
    },
    {
      title: "S3 Hardened (KMS + Public Access Block)",
      code: `resource "aws_s3_bucket" "secure_bucket" {
  bucket = "company-secure-lake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`
    },
    {
      title: "IAM Wildcard Admin Policy (Flawed)",
      code: `resource "aws_iam_policy" "admin" {
  name = "admin-access"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}`
    }
  ];

  const [code, setCode] = useState(presets[0].code);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<{
    status: 'PASSED' | 'FAILED';
    passedCount: number;
    failedCount: number;
    checks: Array<{ id: string; name: string; status: 'PASSED' | 'FAILED'; fix: string }>;
  } | null>(null);

  const handleScan = () => {
    setScanning(true);
    setTimeout(() => {
      setScanning(false);

      const hasPublicAcl = code.includes('public-read') || code.includes('public-read-write');
      const hasWildcardIam = code.includes('"Action": "*"') || code.includes('Action   = "*"') || code.includes('Resource = "*"');
      const hasKms = code.includes('aws:kms') && code.includes('kms_master_key_id');

      const checks = [];
      if (hasPublicAcl) {
        checks.push({
          id: 'CKV_AWS_20',
          name: 'Ensure S3 Bucket does not allow public read ACL',
          status: 'FAILED' as const,
          fix: 'Remove "public-read" ACL and attach aws_s3_bucket_public_access_block.'
        });
      } else {
        checks.push({
          id: 'CKV_AWS_20',
          name: 'Ensure S3 Bucket does not allow public read ACL',
          status: 'PASSED' as const,
          fix: 'Compliant configuration.'
        });
      }

      if (hasWildcardIam) {
        checks.push({
          id: 'CKV_AWS_62',
          name: 'Ensure IAM policies do not allow full "*:*" administrative privileges',
          status: 'FAILED' as const,
          fix: 'Scope Action array strictly to required API calls (e.g. s3:GetObject, s3:PutObject).'
        });
      } else {
        checks.push({
          id: 'CKV_AWS_62',
          name: 'Ensure IAM policies do not allow full "*:*" administrative privileges',
          status: 'PASSED' as const,
          fix: 'Compliant least-privilege scoping.'
        });
      }

      if (!hasKms && code.includes('aws_s3_bucket')) {
        checks.push({
          id: 'CKV_AWS_145',
          name: 'Ensure S3 bucket is encrypted with KMS Customer Managed Key',
          status: 'FAILED' as const,
          fix: 'Configure aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = "aws:kms".'
        });
      } else if (hasKms) {
        checks.push({
          id: 'CKV_AWS_145',
          name: 'Ensure S3 bucket is encrypted with KMS Customer Managed Key',
          status: 'PASSED' as const,
          fix: 'Compliant KMS CMK encryption enabled.'
        });
      }

      const failedCount = checks.filter(c => c.status === 'FAILED').length;
      const passedCount = checks.filter(c => c.status === 'PASSED').length;

      setScanResult({
        status: failedCount > 0 ? 'FAILED' : 'PASSED',
        passedCount,
        failedCount,
        checks
      });
    }, 500);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <Play className="w-6 h-6 text-indigo-400" />
            <span>Live IaC Security Scanner Sandbox</span>
          </h1>
          <p className="text-xs text-slate-400">
            Paste custom Terraform HCL code or select preset snippets to perform instant simulated Checkov policy analysis.
          </p>
        </div>

        {/* Presets Button Bar */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-slate-400">Presets:</span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setCode(p.code);
                setScanResult(null);
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-800 hover:border-indigo-500/40 text-slate-300 transition-all"
            >
              {p.title}
            </button>
          ))}
        </div>
      </div>

      {/* Editor & Scan Panel Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* HCL Input Panel */}
        <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden flex flex-col">
          <div className="bg-slate-900/90 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-200 font-mono flex items-center space-x-2">
              <Code2 className="w-4 h-4 text-indigo-400" />
              <span>Terraform Manifest Editor</span>
            </span>
            <button
              onClick={handleScan}
              disabled={scanning}
              className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-1.5 transition-all shadow-lg shadow-indigo-600/20 disabled:opacity-50"
            >
              {scanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
              <span>{scanning ? 'Scanning...' : 'Run Security Check'}</span>
            </button>
          </div>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="w-full h-[400px] p-4 bg-slate-950 font-mono text-xs text-indigo-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 resize-none leading-relaxed"
            placeholder="Paste your Terraform HCL code here..."
          />
        </div>

        {/* Scan Results Panel */}
        <div className="glass-panel rounded-2xl border border-slate-800 p-6 space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2 border-b border-slate-800 pb-3">
              <ShieldCheck className="w-5 h-5 text-indigo-400" />
              <span>Checkov Analysis Report</span>
            </h2>

            {!scanResult && (
              <div className="py-16 text-center text-slate-500 space-y-2">
                <Code2 className="w-10 h-10 mx-auto text-slate-700" />
                <p className="text-xs">Click "Run Security Check" to evaluate code against active Checkov policies.</p>
              </div>
            )}

            {scanResult && (
              <div className="space-y-4 mt-4">
                {/* Result Summary Badge */}
                <div className={`p-4 rounded-xl border flex items-center justify-between ${
                  scanResult.status === 'PASSED' 
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                }`}>
                  <div className="flex items-center space-x-3">
                    {scanResult.status === 'PASSED' ? (
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-6 h-6 text-rose-400" />
                    )}
                    <div>
                      <span className="text-sm font-bold block">
                        {scanResult.status === 'PASSED' ? 'Manifest Security Evaluation Passed' : 'Security Violations Detected'}
                      </span>
                      <span className="text-xs opacity-80">
                        {scanResult.passedCount} Passed, {scanResult.failedCount} Failed
                      </span>
                    </div>
                  </div>
                </div>

                {/* Individual Check Results */}
                <div className="space-y-3">
                  {scanResult.checks.map(check => (
                    <div key={check.id} className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-indigo-400">{check.id}</span>
                        <span className={`text-[11px] font-bold px-2 py-0.5 rounded ${
                          check.status === 'PASSED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                        }`}>
                          {check.status}
                        </span>
                      </div>
                      <h3 className="text-xs font-bold text-slate-200">{check.name}</h3>
                      <p className="text-xs text-slate-400 font-mono text-[11px]">Fix: {check.fix}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
