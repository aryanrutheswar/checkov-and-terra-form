import React, { useState } from 'react';
import { PIPELINE_STEPS } from '../data/securityData';
import { GitBranch, CheckCircle2, Check, Copy, Flame, ShieldCheck } from 'lucide-react';

export const PipelineVisualizer: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'ci-pipeline' | 'threat-model'>('ci-pipeline');
  const [activeWorkflow, setActiveWorkflow] = useState<'github' | 'gitlab' | 'precommit'>('github');
  const [copied, setCopied] = useState(false);

  const workflows = {
    github: {
      title: ".github/workflows/checkov-iac-scan.yml",
      code: `name: "Checkov IaC Security & SARIF Pipeline"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  scan:
    name: "Checkov Static Analysis Scan"
    runs-on: "ubuntu-latest"
    permissions:
      contents: "read"
      security-events: "write" # Required for SARIF upload to GitHub Security Tab

    steps:
      - name: "Checkout Code"
        uses: "actions/checkout@v4"

      - name: "Run Checkov Scan Engine"
        id: "checkov"
        uses: "bridgecrewio/checkov-action@master"
        with:
          directory: "./terraform/remediated"
          framework: "terraform"
          output_format: "cli,sarif"
          output_file_path: "reports/results"
          external_checks_dir: "custom_policies/yaml,custom_policies/python"
          soft_fail: false
          hard_fail_on: "HIGH,CRITICAL"

      - name: "Upload SARIF File to GitHub Security Tab"
        uses: "github/codeql-action/upload-sarif@v3"
        if: always()
        with:
          sarif_file: "reports/results_sarif.sarif"`
    },
    gitlab: {
      title: ".gitlab-ci.yml",
      code: `stages:
  - test
  - security-gate

checkov_iac_scan:
  stage: security-gate
  image:
    name: bridgecrew/checkov:latest
    entrypoint: [""]
  script:
    - checkov -d ./terraform/remediated --external-checks-dir ./custom_policies -o junitxml -o cli > checkov-report.xml
  artifacts:
    name: "checkov-scan-report"
    when: always
    paths:
      - checkov-report.xml
    reports:
      junit: checkov-report.xml`
    },
    precommit: {
      title: ".pre-commit-config.yaml",
      code: `repos:
  - repo: https://github.com/bridgecrewio/checkov.git
    rev: '3.2.0'
    hooks:
      - id: checkov
        name: Checkov Static Code Analysis Hook
        entry: checkov
        language: python
        types: [terraform]
        args: [
          "-d", "./terraform/remediated",
          "--external-checks-dir", "./custom_policies",
          "--compact",
          "--soft-fail"
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
      description: "Database instance deployed without KMS storage encryption and single-AZ availability allows unauthenticated snapshot theft and service downtime.",
      nodes: [
        { name: "Internal VPC Network", type: "Access Vector", icon: "📡", status: "VPC Perimeter" },
        { name: "PostgreSQL RDS (Unencrypted Storage)", type: "Data Storage Flaw", icon: "🗄️", status: "CKV_AWS_16 Violation" },
        { name: "Single-AZ Deployment (No Multi-AZ)", type: "Availability Flaw", icon: "⚠️", status: "CKV_AWS_157 Violation" },
        { name: "Unencrypted Snapshot Theft", type: "Impact", icon: "🚨", status: "Data Exposure" }
      ],
      remediations: ["CKV_AWS_16: Enable Storage Encryption with KMS", "CKV_AWS_157: Enable Multi-AZ Replication"]
    }
  ];

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const currentWf = workflows[activeWorkflow];

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Top Header & Sub-Tab Switcher */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <GitBranch className="w-6 h-6 text-indigo-400" />
            <span>Shift-Left CI/CD & Threat Model Visualizer</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automate security gates before deployment and visualize infrastructure attack vectors & blast radius metrics.
          </p>
        </div>

        <div className="flex bg-slate-900 p-1 rounded-xl border border-slate-800 self-start md:self-auto">
          <button
            onClick={() => setActiveTab('ci-pipeline')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all flex items-center space-x-2 ${
              activeTab === 'ci-pipeline'
                ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 shadow-lg'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitBranch className="w-4 h-4" />
            <span>CI/CD Pipeline Spec</span>
          </button>
          <button
            onClick={() => setActiveTab('threat-model')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all flex items-center space-x-2 ${
              activeTab === 'threat-model'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-lg'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Flame className="w-4 h-4 text-rose-400" />
            <span>Threat Vector Visualizer</span>
          </button>
        </div>
      </div>

      {activeTab === 'ci-pipeline' ? (
        <div className="space-y-6">
          {/* Step Flow Diagram */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {PIPELINE_STEPS.map((step) => (
              <div key={step.step} className="glass-panel p-4 rounded-xl border border-slate-800 space-y-2 relative">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-extrabold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                    Step 0{step.step}
                  </span>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                </div>
                <h3 className="text-xs font-bold text-slate-200">{step.title}</h3>
                <p className="text-[11px] text-indigo-300 font-mono">{step.tool}</p>
                <p className="text-[11px] text-slate-400 leading-tight">{step.description}</p>
              </div>
            ))}
          </div>

          {/* Pipeline Config Viewer */}
          <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden space-y-0">
            <div className="bg-slate-900/90 px-6 py-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center space-x-3">
                <span className="text-xs font-medium text-slate-400">Select Workflow Spec:</span>
                <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800">
                  <button
                    onClick={() => setActiveWorkflow('github')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      activeWorkflow === 'github' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
                    }`}
                  >
                    GitHub Actions
                  </button>
                  <button
                    onClick={() => setActiveWorkflow('gitlab')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      activeWorkflow === 'gitlab' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
                    }`}
                  >
                    GitLab CI
                  </button>
                  <button
                    onClick={() => setActiveWorkflow('precommit')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      activeWorkflow === 'precommit' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
                    }`}
                  >
                    Pre-Commit Hooks
                  </button>
                </div>
              </div>

              <button
                onClick={() => handleCopy(currentWf.code)}
                className="text-slate-400 hover:text-slate-200 text-xs flex items-center space-x-1.5 self-start md:self-auto"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied Workflow' : 'Copy Workflow Config'}</span>
              </button>
            </div>

            <div className="p-6 bg-slate-950 font-mono text-xs text-slate-200 leading-relaxed overflow-x-auto">
              <div className="text-xs font-bold text-indigo-400 pb-3 font-mono"># {currentWf.title}</div>
              <pre>{currentWf.code}</pre>
            </div>
          </div>
        </div>
      ) : (
        /* Threat Vector Visualizer View */
        <div className="space-y-6">
          {threatChains.map((chain) => (
            <div key={chain.id} className="glass-panel p-6 rounded-2xl border border-rose-500/30 bg-rose-950/10 space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-rose-500/20 pb-4">
                <div>
                  <div className="flex items-center space-x-3">
                    <span className="text-xs font-mono font-bold text-rose-400 bg-rose-500/20 px-2.5 py-0.5 rounded border border-rose-500/30">
                      {chain.id}
                    </span>
                    <h2 className="text-base font-bold text-slate-100">{chain.title}</h2>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 max-w-3xl">{chain.description}</p>
                </div>
                <div className="text-right self-start md:self-auto">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Blast Radius Score</span>
                  <span className="text-sm font-extrabold text-rose-400 font-mono">{chain.blastRadius}</span>
                </div>
              </div>

              {/* Node Chain Graph */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative">
                {chain.nodes.map((node, nIdx) => (
                  <div key={node.name} className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2 relative group hover:border-rose-500/50 transition-all">
                    <div className="flex items-center justify-between">
                      <span className="text-2xl">{node.icon}</span>
                      <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800">
                        Node 0{nIdx + 1}
                      </span>
                    </div>
                    <h3 className="text-xs font-bold text-slate-200">{node.name}</h3>
                    <span className="text-[11px] font-semibold text-indigo-400 block">{node.type}</span>
                    <span className="text-[10px] font-mono text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded block text-center border border-rose-500/20">
                      {node.status}
                    </span>
                  </div>
                ))}
              </div>

              {/* Remediation Checkpoints */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                <span className="text-xs font-bold text-emerald-400 flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Required Checkov Policy Remediation Checkpoints:</span>
                </span>
                <div className="flex flex-wrap gap-2 pt-1">
                  {chain.remediations.map((rem) => (
                    <span key={rem} className="text-xs font-mono text-slate-300 bg-slate-800/90 px-3 py-1 rounded-lg border border-slate-700">
                      {rem}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

