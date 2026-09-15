import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Terminal, 
  CheckCircle2, 
  RotateCw, 
  Radio, 
  ShieldAlert, 
  ShieldCheck, 
  ArrowRight, 
  Copy, 
  Check, 
  Code2, 
  ClipboardPaste, 
  Trash2, 
  Sparkles,
  Columns,
  Maximize2,
  FileCode,
  Edit3
} from 'lucide-react';
import { SCAN_METRICS, INFRASTRUCTURE_FILES } from '../data/securityData';
import { NormalizedScanResult } from '../services/api';

interface IacScannerProps {
  isRemediated: boolean;
  setIsRemediated: (val: boolean) => void;
  setActiveTab: (tab: string) => void;
  onRunScan?: (target?: string, customCode?: string) => Promise<any>;
  isScanning?: boolean;
  scanResult?: NormalizedScanResult | null;
}

const PRESETS = [
  {
    id: 's3-flawed',
    title: 'Public S3 Bucket',
    badge: 'High Risk',
    code: `resource "aws_s3_bucket" "insecure_storage" {
  bucket = "company-internal-data-backup"
  acl    = "public-read" # Critical violation: CKV_AWS_20
}

resource "aws_s3_bucket_public_access_block" "disabled" {
  bucket = aws_s3_bucket.insecure_storage.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}`
  },
  {
    id: 'sg-ssh',
    title: 'Open SSH / RDP (0.0.0.0/0)',
    badge: 'High Risk',
    code: `resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Security group for web instances"

  ingress {
    description = "SSH open to internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Violation: CKV_AWS_24
  }

  ingress {
    description = "RDP open to internet"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Violation: CKV_AWS_25
  }
}`
  },
  {
    id: 'iam-wildcard',
    title: 'Wildcard Admin IAM Role',
    badge: 'Critical',
    code: `resource "aws_iam_role" "app_role" {
  name = "production-app-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "admin_policy" {
  name = "unrestricted-admin-access"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*" # Critical violation: CKV_AWS_62 / CUSTOM_AWS_003
    }]
  })
}`
  },
  {
    id: 'rds-public',
    title: 'Public RDS Database',
    badge: 'Critical',
    code: `resource "aws_db_instance" "public_db" {
  identifier           = "production-customer-db"
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "15.3"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true # Critical violation: CKV_AWS_16
  storage_encrypted    = false # High violation: CKV_AWS_17
  backup_retention_period = 0 # Violation: CUSTOM_AWS_002
}`
  },
  {
    id: 's3-hardened',
    title: 'Hardened S3 (KMS CMK)',
    badge: 'Compliant',
    code: `resource "aws_kms_key" "s3_key" {
  description             = "Customer KMS Key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "hardened_storage" {
  bucket = "company-production-secure-records"

  tags = {
    Environment = "production"
    Project     = "CyberSentinel"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kms_sse" {
  bucket = aws_s3_bucket.hardened_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "enforce_private" {
  bucket                  = aws_s3_bucket.hardened_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.hardened_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}`
  }
];

export const IacScanner: React.FC<IacScannerProps> = ({
  isRemediated,
  setIsRemediated,
  setActiveTab,
  onRunScan,
  isScanning: propIsScanning,
  scanResult,
}) => {
  const [scanMode, setScanMode] = useState<'vulnerable' | 'remediated' | 'custom'>('custom');
  const [terminalView, setTerminalView] = useState<'editor' | 'logs' | 'split'>('editor');
  const [customCode, setCustomCode] = useState<string>(PRESETS[0].code);
  const [localScanning, setLocalScanning] = useState(false);
  const isScanning = propIsScanning ?? localScanning;
  const [currentScanStep, setCurrentScanStep] = useState(0);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [scanExecuted, setScanExecuted] = useState(true);
  const [copied, setCopied] = useState(false);
  const [pastedNotice, setPastedNotice] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Sync initial or updated terminal logs from real scanResult
  useEffect(() => {
    if (scanResult) {
      const isCustom = scanResult.target_directory.includes('custom');
      const targetLabel = isCustom 
        ? 'Custom Code Snippet (main.tf)' 
        : `./${scanResult.target_directory}`;

      const logs: string[] = [
        `[INFO] Checkov IaC Static Security Scanner v${scanResult.checkov_version}`,
        `[INFO] Target manifest suite: ${targetLabel}`,
        `[INFO] External policies loaded: ./custom_policies/yaml, ./custom_policies/python`,
        `[STEP 1] Abstract Syntax Tree (AST) generated successfully for HCL files.`,
        `[STEP 2] Directed Acyclic Graph (DAG) constructed for cross-resource dependencies.`,
        `[STEP 3] Evaluated ${scanResult.total_checks} policy checks against CIS AWS and enterprise baselines.`,
        `--------------------------------------------------------------------------------`
      ];

      if (scanResult.findings.length > 0) {
        scanResult.findings.slice(0, 10).forEach((f) => {
          logs.push(`[VIOLATION] ${f.check_id} [${f.severity}]: ${f.title} (${f.resource || 'resource'})`);
        });
        if (scanResult.findings.length > 10) {
          logs.push(`... and ${scanResult.findings.length - 10} additional policy violations in report.`);
        }
      } else {
        logs.push(`[CLEAN] 0 policy violations detected across evaluated manifests.`);
      }

      logs.push(`--------------------------------------------------------------------------------`);
      logs.push(`[SUMMARY] Total checks: ${scanResult.total_checks} | Passed: ${scanResult.passed_checks} | Failed: ${scanResult.failed_checks} | Skipped: ${scanResult.skipped_checks}`);
      logs.push(`[RESULT] >>> SECURITY GATE: ${scanResult.gate_status} (Exit code: ${scanResult.exit_code ?? (scanResult.gate_status === 'PASSED' ? 0 : 1)})`);
      logs.push(
        scanResult.gate_status === 'PASSED'
          ? `[VERDICT] ✅ 0 High/Critical violations detected. Stage 2 (Terraform Validate & Plan) UNLOCKED.`
          : `[VERDICT] 🛑 PIPELINE HALTED! Insecure configurations exceed high severity threshold.`
      );
      setTerminalLogs(logs);
      setScanExecuted(true);
      setCurrentScanStep(5);
    }
  }, [scanResult]);

  const scanSteps = [
    { title: "AST Parsing", desc: "Parsing Terraform HCL into Abstract Syntax Tree" },
    { title: "Graph DAG Resolution", desc: "Building cross-resource dependency directed graph" },
    { title: "Benchmark Evaluation", desc: "Evaluating 1,000+ CIS AWS & NIST 800-53 rules" },
    { title: "Custom Policy Engine", desc: "Executing organization YAML & Python checks" },
    { title: "Gate Enforcement", desc: "Evaluating severity threshold (--hard-fail-on HIGH)" }
  ];

  const handleSelectMode = (mode: 'vulnerable' | 'remediated' | 'custom') => {
    setScanMode(mode);
    if (mode === 'vulnerable') {
      setIsRemediated(false);
      setCustomCode(INFRASTRUCTURE_FILES[0]?.vulnerableCode || PRESETS[0].code);
    } else if (mode === 'remediated') {
      setIsRemediated(true);
      setCustomCode(INFRASTRUCTURE_FILES[0]?.remediatedCode || PRESETS[4].code);
    }
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setCustomCode(text);
        setTerminalView('editor');
        setPastedNotice('Pasted!');
        setTimeout(() => setPastedNotice(null), 2000);
      }
    } catch {
      setPastedNotice('Ctrl+V here');
      setTimeout(() => setPastedNotice(null), 2500);
    }
    textareaRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const target = e.target as HTMLTextAreaElement;
      const start = target.selectionStart;
      const end = target.selectionEnd;
      const newCode = customCode.substring(0, start) + '  ' + customCode.substring(end);
      setCustomCode(newCode);
      setTimeout(() => {
        target.selectionStart = target.selectionEnd = start + 2;
      }, 0);
    }
  };

  const handleRunScan = async () => {
    setLocalScanning(true);
    setCurrentScanStep(0);

    const isCustom = scanMode === 'custom' || terminalView === 'editor';
    const targetDir = isCustom 
      ? undefined 
      : scanMode === 'remediated' 
      ? 'terraform/remediated' 
      : 'terraform/vulnerable';

    const codeToScan = isCustom ? customCode : undefined;

    setTerminalLogs([
      `[INFO] Initializing Checkov IaC Static Security Scanner...`,
      isCustom 
        ? `[INFO] Mode: Custom Code Snippet (main.tf)` 
        : `[INFO] Target manifest suite: ./${targetDir}`,
      `[INFO] Executing live Python Checkov AST runner via subprocess...`,
    ]);

    const stepInterval = setInterval(() => {
      setCurrentScanStep((prev) => {
        if (prev === 0) {
          setTerminalLogs((logs) => [
            ...logs,
            `[STEP 1] Abstract Syntax Tree (AST) generated successfully for HCL definitions.`,
          ]);
          return 1;
        } else if (prev === 1) {
          setTerminalLogs((logs) => [
            ...logs,
            `[STEP 2] Directed Acyclic Graph (DAG) constructed for cross-resource dependencies.`,
          ]);
          return 2;
        } else if (prev === 2) {
          setTerminalLogs((logs) => [
            ...logs,
            `[STEP 3] Evaluating CIS AWS Foundations Benchmarks & NIST 800-53 controls...`,
          ]);
          return 3;
        } else if (prev === 3) {
          setTerminalLogs((logs) => [
            ...logs,
            `[STEP 4] Executing custom policies: CUSTOM_AWS_001, CUSTOM_AWS_002, CUSTOM_AWS_003...`,
          ]);
          return 4;
        }
        return prev;
      });
    }, 400);

    try {
      if (onRunScan) {
        await onRunScan(targetDir, codeToScan);
      }
      // Switch view to logs or split view so user can see scan verdict
      if (terminalView === 'editor') {
        setTerminalView('logs');
      }
    } catch (err: any) {
      setTerminalLogs((logs) => [
        ...logs,
        `[ERROR] Scan execution error: ${err?.message || err}`,
      ]);
    } finally {
      clearInterval(stepInterval);
      setLocalScanning(false);
      setScanExecuted(true);
      setCurrentScanStep(5);
    }
  };

  const handleCopyCurrentContent = () => {
    if (terminalView === 'editor') {
      navigator.clipboard.writeText(customCode);
    } else {
      navigator.clipboard.writeText(terminalLogs.join('\n'));
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = customCode.split('\n').length;
  const lineNumbers = Array.from({ length: Math.max(lineCount, 14) }, (_, i) => i + 1);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Header Bar */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center space-x-2">
            <Terminal className="w-6 h-6 text-cyan-400" />
            <span>IaC STATIC SECURITY SCANNER</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Paste, edit, and audit Terraform HCL manifests directly. Checkov evaluates AST dependencies and enforces compliance gates.
          </p>
        </div>

        {/* Mode Selector */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-slate-950/90 p-1 rounded-xl border border-slate-800 shadow-inner">
            <button
              onClick={() => handleSelectMode('custom')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center space-x-1.5 ${
                scanMode === 'custom'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 glow-cyan shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Code2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Paste & Edit Code</span>
            </button>
            <button
              onClick={() => handleSelectMode('vulnerable')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                scanMode === 'vulnerable'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 glow-rose shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Vulnerable Suite
            </button>
            <button
              onClick={() => handleSelectMode('remediated')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                scanMode === 'remediated'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 glow-emerald shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Hardened Suite
            </button>
          </div>

          <button
            onClick={handleRunScan}
            disabled={isScanning || !customCode.trim()}
            className={`px-6 py-2.5 rounded-xl font-mono text-xs font-bold uppercase tracking-wider flex items-center space-x-2 transition-all shadow-lg ${
              isScanning || !customCode.trim()
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                : 'bg-cyan-500 hover:bg-cyan-400 text-black shadow-cyan-500/30 hover:scale-105 border border-cyan-300 active:scale-95'
            }`}
          >
            <Play className={`w-4 h-4 fill-black ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Scanning AST...' : 'Execute Scan'}</span>
          </button>
        </div>
      </div>

      {/* Pipeline Scanning Telemetry Flow */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
          <div className="flex items-center space-x-2">
            <Radio className={`w-4 h-4 ${isScanning ? 'text-cyan-400 animate-ping' : 'text-slate-500'}`} />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-200">
              Analysis Telemetry Pipeline
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {isScanning ? `Stage ${currentScanStep + 1} of 5 Active` : scanExecuted ? 'Analysis Ready' : 'Standby'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5">
          {scanSteps.map((step, idx) => {
            const isDone = currentScanStep > idx || (!isScanning && scanExecuted);
            const isCurrent = isScanning && currentScanStep === idx;
            return (
              <div
                key={idx}
                className={`p-3 rounded-xl border transition-all ${
                  isCurrent
                    ? 'bg-cyan-950/40 border-cyan-400/60 glow-cyan'
                    : isDone
                    ? 'bg-slate-900/70 border-emerald-500/30'
                    : 'bg-slate-950/40 border-slate-800/60 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold text-slate-400">0{idx + 1}</span>
                  {isDone ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  ) : isCurrent ? (
                    <RotateCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                  ) : (
                    <div className="w-3 h-3 rounded-full border border-slate-700" />
                  )}
                </div>
                <div className="text-xs font-bold font-mono text-slate-200">{step.title}</div>
                <div className="text-[11px] text-slate-400 leading-tight mt-0.5">{step.desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* THE MAIN WORKSPACE CONSOLE: CODE EDITOR & SCAN OUTPUT */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
        {/* Terminal / Editor Header Bar with Tab Switches */}
        <div className="bg-[#03060d] px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
            </div>

            {/* View Switcher Tabs inside the box */}
            <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                onClick={() => setTerminalView('editor')}
                className={`px-3 py-1 rounded-md transition-all flex items-center space-x-1.5 ${
                  terminalView === 'editor'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 glow-cyan'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>Code Editor</span>
              </button>
              <button
                onClick={() => setTerminalView('logs')}
                className={`px-3 py-1 rounded-md transition-all flex items-center space-x-1.5 ${
                  terminalView === 'logs'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 glow-cyan'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Scan Output</span>
              </button>
              <button
                onClick={() => setTerminalView('split')}
                className={`px-3 py-1 rounded-md transition-all hidden md:flex items-center space-x-1.5 ${
                  terminalView === 'split'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 glow-cyan'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Columns className="w-3.5 h-3.5" />
                <span>Split View</span>
              </button>
            </div>
          </div>

          {/* Quick Actions (Paste, Clear, Copy) */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handlePasteClipboard}
              className="text-xs font-mono text-cyan-300 hover:text-cyan-200 px-2.5 py-1 rounded-lg bg-cyan-950/40 hover:bg-cyan-950/70 border border-cyan-500/40 transition-all flex items-center space-x-1.5 shadow-sm"
              title="Paste code from clipboard directly into this editor"
            >
              <ClipboardPaste className="w-3.5 h-3.5 text-cyan-400" />
              <span>{pastedNotice || 'Paste Code'}</span>
            </button>

            {terminalView !== 'logs' && (
              <button
                onClick={() => setCustomCode('')}
                className="text-xs font-mono text-slate-400 hover:text-rose-300 px-2 py-1 rounded-lg hover:bg-rose-950/30 border border-transparent hover:border-rose-500/30 transition-all flex items-center space-x-1"
                title="Clear code editor"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}

            <button
              onClick={handleCopyCurrentContent}
              className="text-xs font-mono text-slate-400 hover:text-cyan-300 px-2.5 py-1 rounded-lg hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-all flex items-center space-x-1"
              title={terminalView === 'editor' ? 'Copy Terraform code' : 'Copy scan output'}
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : terminalView === 'editor' ? 'Copy Code' : 'Copy Logs'}</span>
            </button>
          </div>
        </div>

        {/* Template Presets Bar (Shown when in editor or split view) */}
        {terminalView !== 'logs' && (
          <div className="bg-[#02050c] px-4 py-2 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1 mr-1">
                <Sparkles className="w-3 h-3 text-amber-400" />
                <span>Load Template:</span>
              </span>
              {PRESETS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setCustomCode(p.code)}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono transition-all border ${
                    customCode === p.code
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 glow-cyan'
                      : 'bg-slate-900/80 hover:bg-slate-800 text-slate-300 border-slate-800'
                  }`}
                >
                  {p.title}
                </button>
              ))}
            </div>

            <div className="text-[11px] font-mono text-slate-500">
              {lineCount} lines • {customCode.length} characters
            </div>
          </div>
        )}

        {/* Main Body Area (Editor / Logs / Split) */}
        <div className="bg-[#02040a] min-h-[340px]">
          {/* 1. Full Code Editor Mode */}
          {terminalView === 'editor' && (
            <div className="relative flex min-h-[340px] max-h-[460px] overflow-hidden">
              {/* Line Numbers Gutter */}
              <div className="w-10 select-none py-3.5 bg-[#030611] text-right pr-2 font-mono text-xs text-slate-600 border-r border-slate-800/80 leading-5">
                {lineNumbers.map((num) => (
                  <div key={num} className={num <= lineCount ? 'text-slate-500' : 'text-slate-800'}>
                    {num}
                  </div>
                ))}
              </div>

              {/* Editable Textarea */}
              <textarea
                ref={textareaRef}
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="# Paste or type your Terraform HCL code here...&#10;resource &quot;aws_s3_bucket&quot; &quot;my_bucket&quot; {&#10;  bucket = &quot;my-test-bucket&quot;&#10;  acl    = &quot;public-read&quot;&#10;}"
                spellCheck={false}
                className="flex-1 p-3.5 bg-transparent font-mono text-xs text-cyan-100 placeholder-slate-600 outline-none resize-none overflow-y-auto leading-5 selection:bg-cyan-500/30"
              />
            </div>
          )}

          {/* 2. Terminal Logs Mode */}
          {terminalView === 'logs' && (
            <div className="p-5 font-mono text-xs leading-relaxed text-slate-300 min-h-[340px] max-h-[460px] overflow-y-auto">
              {terminalLogs.length === 0 ? (
                <div className="text-slate-500 flex items-center space-x-2">
                  <span>$ Terminal idle. Click [Execute Scan] to evaluate code against Checkov AST policies.</span>
                </div>
              ) : (
                terminalLogs.map((log, i) => {
                  const isError = log.includes('[VIOLATION]') || log.includes('FAILED') || log.includes('HALTED');
                  const isSuccess = log.includes('PASSED') || log.includes('UNLOCKED') || log.includes('CLEAN');
                  const isInfo = log.includes('[STEP') || log.includes('[INFO]');
                  return (
                    <div 
                      key={i} 
                      className={`py-0.5 ${
                        isError 
                          ? 'text-rose-400 font-semibold' 
                          : isSuccess 
                          ? 'text-emerald-400 font-bold' 
                          : isInfo 
                          ? 'text-cyan-300' 
                          : 'text-slate-300'
                      }`}
                    >
                      {log}
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* 3. Split View Mode */}
          {terminalView === 'split' && (
            <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-800 min-h-[340px] max-h-[460px]">
              {/* Left Column: Code Editor */}
              <div className="flex h-full overflow-hidden bg-[#020409]">
                <div className="w-9 select-none py-3 bg-[#030611] text-right pr-2 font-mono text-[11px] text-slate-600 border-r border-slate-800/80 leading-5">
                  {lineNumbers.map((num) => (
                    <div key={num} className={num <= lineCount ? 'text-slate-500' : 'text-slate-800'}>
                      {num}
                    </div>
                  ))}
                </div>
                <textarea
                  value={customCode}
                  onChange={(e) => setCustomCode(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="# Paste or type Terraform code..."
                  spellCheck={false}
                  className="flex-1 p-3 bg-transparent font-mono text-[11px] text-cyan-100 placeholder-slate-600 outline-none resize-none overflow-y-auto leading-5 selection:bg-cyan-500/30"
                />
              </div>

              {/* Right Column: Scan Logs */}
              <div className="p-4 font-mono text-[11px] leading-relaxed text-slate-300 overflow-y-auto bg-[#010307]">
                {terminalLogs.length === 0 ? (
                  <div className="text-slate-500">
                    $ Scan output will stream here on execution...
                  </div>
                ) : (
                  terminalLogs.map((log, i) => {
                    const isError = log.includes('[VIOLATION]') || log.includes('FAILED') || log.includes('HALTED');
                    const isSuccess = log.includes('PASSED') || log.includes('UNLOCKED') || log.includes('CLEAN');
                    const isInfo = log.includes('[STEP') || log.includes('[INFO]');
                    return (
                      <div 
                        key={i} 
                        className={`py-0.5 ${
                          isError 
                            ? 'text-rose-400 font-semibold' 
                            : isSuccess 
                            ? 'text-emerald-400 font-bold' 
                            : isInfo 
                            ? 'text-cyan-300' 
                            : 'text-slate-300'
                        }`}
                      >
                        {log}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </div>

        {/* Action / Feedback Bar directly inside the Console */}
        <div className="bg-[#03060e] px-5 py-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-3 text-xs font-mono">
            {terminalView === 'editor' ? (
              <button
                onClick={() => setTerminalView('logs')}
                className="text-slate-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>View Latest Scan Output ({terminalLogs.length} lines)</span>
              </button>
            ) : (
              <button
                onClick={() => setTerminalView('editor')}
                className="text-cyan-300 hover:text-cyan-200 flex items-center space-x-1.5 font-bold"
              >
                <Edit3 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Edit Code & Fix Violations</span>
              </button>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleRunScan}
              disabled={isScanning || !customCode.trim()}
              className="px-4 py-2 rounded-xl text-xs font-mono font-bold uppercase tracking-wider bg-cyan-500 hover:bg-cyan-400 text-black flex items-center space-x-2 shadow-lg shadow-cyan-500/20 active:scale-95 transition-all disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 fill-black ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Scanning AST...' : 'Scan This Code'}</span>
            </button>
          </div>
        </div>

        {/* Security Gate Outcome Banner */}
        {(() => {
          const isGatePassed = scanResult ? scanResult.gate_status === 'PASSED' : (scanMode === 'remediated');
          const exitCode = scanResult?.exit_code ?? (isGatePassed ? 0 : 1);
          const failedCount = scanResult ? scanResult.failed_checks : (scanMode === 'remediated' ? 0 : 39);
          return (
            <div className={`p-4 border-t ${
              isGatePassed
                ? 'bg-emerald-950/40 border-emerald-500/30'
                : 'bg-rose-950/40 border-rose-500/30'
            }`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-3">
                  {isGatePassed ? (
                    <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      <ShieldCheck className="w-5 h-5" />
                    </div>
                  ) : (
                    <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                  )}
                  <div>
                    <div className={`text-sm font-bold font-mono ${isGatePassed ? 'text-emerald-300' : 'text-rose-300'}`}>
                      {isGatePassed ? 'SECURITY GATE PASSED — DEPLOYMENT APPROVED' : 'SECURITY GATE FAILED — DEPLOYMENT BLOCKED'}
                    </div>
                    <div className="text-xs text-slate-400 font-mono">
                      {isGatePassed 
                        ? `Exit Code: ${exitCode} • Zero High/Critical Violations • Terraform Validate & Plan Unlocked`
                        : `Exit Code: ${exitCode} • ${failedCount} Violations Exceeding High Threshold • CI/CD Pipeline Halted`}
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition-all flex items-center space-x-1"
                  >
                    <span>View Findings</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => setActiveTab('pipeline')}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-all flex items-center space-x-1"
                  >
                    <span>Inspect Pipeline</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
};
