import React, { useState } from 'react';
import { PIPELINE_STEPS } from '../data/securityData';
import { 
  GitBranch, 
  CheckCircle2, 
  XCircle, 
  Check, 
  Copy, 
  Flame, 
  ShieldCheck, 
  ShieldAlert,
  Lock
} from 'lucide-react';

export const PipelineVisualizer: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'ci-pipeline' | 'threat-model'>('ci-pipeline');
  const [activeWorkflow, setActiveWorkflow] = useState<'github' | 'gitlab' | 'precommit'>('github');
  const [demoGateState, setDemoGateState] = useState<'passed' | 'failed'>('passed');
  const [copied, setCopied] = useState(false);

  const workflows = {
    github: {
      title: ".github/workflows/checkov-iac-scan.yml",
      code: `name: "IaC Security Gate & Terraform Pipeline"

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]
  workflow_dispatch:
    inputs:
      target_suite:
        description: "Target Terraform Suite"
        default: "terraform/remediated"
        type: choice
        options: [ "terraform/remediated", "terraform/vulnerable" ]

jobs:
  # STAGE 1: Checkov Static Analysis Security Gate
  security-gate:
    name: "Stage 1: Checkov Security Gate"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install checkov
      - name: Execute Checkov Security Scan
        run: |
          checkov -d "./\${{ inputs.target_suite || 'terraform/remediated' }}" \\
            --external-checks-dir ./custom_policies/yaml \\
            --external-checks-dir ./custom_policies/python \\
            --framework terraform \\
            --output cli --output sarif --output json --output-file-path ./reports \\
            --hard-fail-on HIGH

  # STAGE 2: Terraform Validation & Speculative Plan
  # Strictly depends on Stage 1 (needs: [security-gate])
  terraform-validate-and-plan:
    name: "Stage 2: Terraform Validate & Plan"
    needs: [security-gate] # <--- HARD DEPENDENCY GATE
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with: { terraform_version: "1.7.5" }
      - run: terraform -chdir="./\${{ inputs.target_suite || 'terraform/remediated' }}" fmt -check
      - run: terraform -chdir="./\${{ inputs.target_suite || 'terraform/remediated' }}" init -backend=false
      - run: terraform -chdir="./\${{ inputs.target_suite || 'terraform/remediated' }}" validate
      - run: terraform -chdir="./\${{ inputs.target_suite || 'terraform/remediated' }}" plan -no-color`
    },
    gitlab: {
      title: ".gitlab-ci.yml",
      code: `stages:
  - security-gate
  - terraform-plan

checkov_security_gate:
  stage: security-gate
  image: bridgecrew/checkov:latest
  script:
    - checkov -d ./terraform/remediated --hard-fail-on HIGH
  artifacts:
    reports:
      junit: reports/results_junitxml.xml

terraform_plan:
  stage: terraform-plan
  needs: [checkov_security_gate] # Gated execution
  image: hashicorp/terraform:1.7
  script:
    - terraform init -backend=false
    - terraform validate
    - terraform plan`
    },
    precommit: {
      title: ".pre-commit-config.yaml",
      code: `repos:
  - repo: https://github.com/bridgecrewio/checkov.git
    rev: '3.3.11'
    hooks:
      - id: checkov
        name: Checkov Shift-Left Pre-Commit Gate
        entry: checkov
        language: python
        types: [terraform]
        args: [
          "-d", "./terraform/remediated",
          "--external-checks-dir", "./custom_policies",
          "--compact",
          "--hard-fail-on", "HIGH"
        ]`
    }
  };

  const threatChains = [
    {
      id: "CHAIN-01",
      title: "Public Internet to S3 Exfiltration Vector",
      blastRadius: "CRITICAL (9.8/10)",
      description: "An attacker scans open Port 22 SSH ingress, compromises the EC2 instance, uses the wildcard IAM AdministratorAccess role to list buckets, and exfiltrates unencrypted S3 data.",
      nodes: [
        { name: "Public Internet", type: "Entry Vector", icon: "🌐", status: "Untrusted Source" },
        { name: "SG-001 (Port 22 Ingress 0.0.0.0/0)", type: "Network Security Flaw", icon: "🔓", status: "CKV_AWS_24 Violation" },
        { name: "IAM Role (AdministratorAccess *)", type: "Privilege Escalation", icon: "🔑", status: "CKV_AWS_60 Violation" },
        { name: "Production S3 Bucket (Public Read)", type: "Data Exfiltration", icon: "💥", status: "CKV_AWS_18 Violation" }
      ],
      remediations: ["CKV_AWS_24: Restrict SSH Ingress", "CKV_AWS_60: Restrict IAM Wildcards", "CKV_AWS_18: Enforce S3 Public Access Block"]
    },
    {
      id: "CHAIN-02",
      title: "RDS Unencrypted Snapshot Breach Vector",
      blastRadius: "HIGH (8.4/10)",
      description: "Database instance deployed without KMS storage encryption and public accessibility allows unauthenticated snapshot theft and service compromise.",
      nodes: [
        { name: "Internal VPC Network", type: "Access Vector", icon: "📡", status: "VPC Perimeter" },
        { name: "PostgreSQL RDS (Unencrypted Storage)", type: "Data Storage Flaw", icon: "🗄️", status: "CKV_AWS_16 Violation" },
        { name: "Public Database Endpoint", type: "Exposure Flaw", icon: "⚠️", status: "CKV_AWS_17 Violation" },
        { name: "Unencrypted Snapshot Breach", type: "Impact", icon: "🚨", status: "Data Compromise" }
      ],
      remediations: ["CKV_AWS_16: Enable Storage Encryption with KMS", "CKV_AWS_17: Restrict Public Accessibility to Private Subnets"]
    }
  ];

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header Controls */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center space-x-2">
            <GitBranch className="w-6 h-6 text-cyan-400" />
            <span>CI/CD SHIFT-LEFT SECURITY GATE & THREAT VISUALIZER</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Visualizing the 2-stage automated pipeline gate where Checkov static analysis controls downstream Terraform validation and deployment.
          </p>
        </div>

        {/* View Switcher */}
        <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('ci-pipeline')}
            className={`px-3.5 py-1.5 rounded-lg font-semibold transition-all ${
              activeTab === 'ci-pipeline' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            2-Stage Gated Pipeline
          </button>
          <button
            onClick={() => setActiveTab('threat-model')}
            className={`px-3.5 py-1.5 rounded-lg font-semibold transition-all flex items-center space-x-1.5 ${
              activeTab === 'threat-model' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Attack Chain Visualizer</span>
          </button>
        </div>
      </div>

      {activeTab === 'ci-pipeline' ? (
        <div className="space-y-6">
          {/* Interactive Gate State Simulator */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-200">
                  Live Security Gate Simulation
                </h2>
                <p className="text-xs text-slate-400 font-mono">
                  Toggle pipeline outcome to observe how GitHub Actions conditionally blocks downstream jobs.
                </p>
              </div>

              <div className="flex items-center space-x-2 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
                <button
                  onClick={() => setDemoGateState('passed')}
                  className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
                    demoGateState === 'passed' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 glow-emerald' : 'text-slate-400'
                  }`}
                >
                  ✓ Simulate Pass (Remediated)
                </button>
                <button
                  onClick={() => setDemoGateState('failed')}
                  className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
                    demoGateState === 'failed' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 glow-rose' : 'text-slate-400'
                  }`}
                >
                  ✗ Simulate Fail (Vulnerable)
                </button>
              </div>
            </div>

            {/* 2-Stage Gated Pipeline Architecture Diagram */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
              {/* Box 1: Stage 1 */}
              <div className="p-5 rounded-2xl bg-slate-950/80 border border-cyan-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                    STAGE 01
                  </span>
                  <span className="text-xs font-mono text-slate-400">checkov-security-gate</span>
                </div>
                <h3 className="font-bold text-sm text-slate-100 font-mono">Checkov Static Analysis</h3>
                <ul className="text-xs font-mono text-slate-400 space-y-1">
                  <li>• Scans AST & Resource Graph</li>
                  <li>• Evaluates CIS AWS Benchmark</li>
                  <li>• Runs Custom YAML/Python Policies</li>
                  <li>• Enforces: <code className="text-cyan-300">--hard-fail-on HIGH</code></li>
                </ul>
                <div className={`p-2.5 rounded-xl border text-xs font-mono font-bold flex items-center space-x-2 ${
                  demoGateState === 'passed' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                }`}>
                  {demoGateState === 'passed' ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                  <span>{demoGateState === 'passed' ? 'STAGE 1 PASSED (Exit Code: 0)' : 'STAGE 1 FAILED (Exit Code: 1)'}</span>
                </div>
              </div>

              {/* Box 2: The Security Gate Decision */}
              <div className={`p-5 rounded-2xl border flex flex-col justify-between space-y-3 ${
                demoGateState === 'passed'
                  ? 'bg-emerald-950/20 border-emerald-500/40 glow-emerald'
                  : 'bg-rose-950/20 border-rose-500/40 glow-rose'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    GATEWAY
                  </span>
                  <Lock className={`w-4 h-4 ${demoGateState === 'passed' ? 'text-emerald-400' : 'text-rose-400'}`} />
                </div>
                <div>
                  <h3 className="font-bold text-sm font-mono text-slate-100">Conditional Gate Decision</h3>
                  <p className="text-xs font-mono text-slate-400 mt-1">
                    {demoGateState === 'passed'
                      ? 'Zero High or Critical violations detected. Gate unlocks downstream jobs.'
                      : '39 Violations detected. GitHub Actions immediately cancels downstream jobs.'}
                  </p>
                </div>
                <div className={`p-2.5 rounded-xl border text-xs font-mono font-bold text-center ${
                  demoGateState === 'passed' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                }`}>
                  {demoGateState === 'passed' ? '➔ UNLOCK STAGE 2' : '🛑 HALT PIPELINE (BLOCKED)'}
                </div>
              </div>

              {/* Box 3: Stage 2 */}
              <div className={`p-5 rounded-2xl border space-y-3 ${
                demoGateState === 'passed'
                  ? 'bg-slate-950/80 border-cyan-500/30'
                  : 'bg-slate-950/40 border-slate-800/40 opacity-50'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                    STAGE 02
                  </span>
                  <span className="text-xs font-mono text-slate-500">needs: [security-gate]</span>
                </div>
                <h3 className="font-bold text-sm text-slate-100 font-mono">Terraform Validate & Plan</h3>
                <ul className="text-xs font-mono text-slate-400 space-y-1">
                  <li>• <code className="text-slate-300">terraform fmt -check</code></li>
                  <li>• <code className="text-slate-300">terraform init -backend=false</code></li>
                  <li>• <code className="text-slate-300">terraform validate</code></li>
                  <li>• <code className="text-slate-300">terraform plan -no-color</code></li>
                </ul>
                <div className={`p-2.5 rounded-xl border text-xs font-mono font-bold flex items-center space-x-2 ${
                  demoGateState === 'passed'
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-slate-900 text-slate-500 border-slate-800'
                }`}>
                  {demoGateState === 'passed' ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                  <span>{demoGateState === 'passed' ? 'STAGE 2 APPROVED FOR DEPLOY' : 'SKIPPED / PREVENTED FROM RUNNING'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Workflow Code Viewer */}
          <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden space-y-0">
            <div className="bg-[#03060d] px-6 py-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center space-x-3">
                <span className="text-xs font-mono text-slate-400">Select Workflow Spec:</span>
                <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800">
                  <button
                    onClick={() => setActiveWorkflow('github')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                      activeWorkflow === 'github' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    GitHub Actions (Active)
                  </button>
                  <button
                    onClick={() => setActiveWorkflow('gitlab')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                      activeWorkflow === 'gitlab' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    GitLab CI/CD
                  </button>
                  <button
                    onClick={() => setActiveWorkflow('precommit')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                      activeWorkflow === 'precommit' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Pre-Commit Hook
                  </button>
                </div>
              </div>

              <button
                onClick={() => handleCopy(workflows[activeWorkflow].code)}
                className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center space-x-1.5 transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Workflow'}</span>
              </button>
            </div>

            <div className="p-6 bg-[#020409] font-mono text-xs text-slate-200 overflow-x-auto min-h-[380px]">
              <pre className="leading-relaxed">{workflows[activeWorkflow].code}</pre>
            </div>
          </div>
        </div>
      ) : (
        /* Threat Vector & Blast Radius Visualizer */
        <div className="space-y-6">
          <div className="glass-panel p-6 rounded-2xl border border-rose-500/30 bg-rose-950/10 space-y-6">
            <div>
              <h2 className="text-lg font-bold font-mono text-slate-100 flex items-center space-x-2">
                <Flame className="w-5 h-5 text-rose-400" />
                <span>IaC Threat Vector & Blast Radius Simulation</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Visualizing how misconfigurations in raw Terraform chain together to form catastrophic cloud attack paths.
              </p>
            </div>

            <div className="space-y-6">
              {threatChains.map((chain) => (
                <div key={chain.id} className="p-6 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-4">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                    <div>
                      <span className="text-[10px] font-mono font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                        {chain.id}
                      </span>
                      <h3 className="text-sm font-bold text-slate-100 mt-1">{chain.title}</h3>
                    </div>
                    <div className="text-right">
                      <span className="text-xs font-mono text-slate-400">Estimated Blast Radius: </span>
                      <span className="text-xs font-mono font-bold text-rose-400">{chain.blastRadius}</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300">{chain.description}</p>

                  {/* Attack Nodes Chain */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
                    {chain.nodes.map((node, i) => (
                      <div key={i} className="p-4 rounded-xl bg-[#03060f] border border-slate-800/80 space-y-1 relative">
                        <div className="text-xl mb-1">{node.icon}</div>
                        <div className="text-xs font-bold text-slate-200">{node.name}</div>
                        <div className="text-[11px] font-mono text-cyan-400">{node.type}</div>
                        <div className="text-[10px] font-mono text-rose-400">{node.status}</div>
                      </div>
                    ))}
                  </div>

                  {/* Remediations Checkpoints */}
                  <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-2">
                    <div className="text-xs font-mono font-bold text-emerald-400 flex items-center space-x-1.5">
                      <ShieldCheck className="w-4 h-4" />
                      <span>Checkov Shift-Left Prevention Gate:</span>
                    </div>
                    <ul className="text-xs font-mono text-slate-300 space-y-1">
                      {chain.remediations.map((rem, i) => (
                        <li key={i}>✓ {rem}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
