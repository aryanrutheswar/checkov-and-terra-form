import React, { useState } from 'react';
import { CUSTOM_POLICIES } from '../data/securityData';
import { FileCode, Play, Cpu, Code2, Copy, Check } from 'lucide-react';

export const CustomPolicyStudio: React.FC = () => {
  const [selectedPolicyIndex, setSelectedPolicyIndex] = useState(0);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const policy = CUSTOM_POLICIES[selectedPolicyIndex];

  const handleRunPolicyTest = () => {
    setTestResult('EVALUATING...');
    setTimeout(() => {
      setTestResult(`SUCCESS: Rule ${policy.id} evaluated against Terraform AST graph.
- Rule ID: ${policy.id}
- Engine: ${policy.type === 'YAML' ? 'Checkov Declarative YAML Parser' : 'Checkov Procedural Python AST Scanner'}
- Supported Resources: ${policy.type === 'YAML' ? 'aws_s3_bucket / aws_db_instance' : 'aws_iam_policy / aws_s3_bucket_server_side_encryption_configuration'}
- Result: PASSED on remediated manifests, FAILED on vulnerable baseline.`);
    }, 600);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(policy.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <FileCode className="w-6 h-6 text-indigo-400" />
            <span>Custom Policy-as-Code Studio</span>
          </h1>
          <p className="text-xs text-slate-400">
            Author and inspect proprietary enterprise security policies written in declarative YAML or procedural Python AST checks.
          </p>
        </div>

        {/* Policy Selector Tabs */}
        <div className="flex bg-slate-900/90 p-1 rounded-xl border border-slate-800 flex-wrap gap-1">
          {CUSTOM_POLICIES.map((p, idx) => (
            <button
              key={p.id}
              onClick={() => {
                setSelectedPolicyIndex(idx);
                setTestResult(null);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                selectedPolicyIndex === idx
                  ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {p.id} ({p.type})
            </button>
          ))}
        </div>
      </div>

      {/* Main Studio View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Side: Metadata & Guidelines */}
        <div className="space-y-4">
          <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-indigo-400 px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20">
                {policy.id}
              </span>
              <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                policy.type === 'YAML' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
              }`}>
                {policy.type} Check Engine
              </span>
            </div>

            <h2 className="text-lg font-bold text-slate-100">{policy.name}</h2>
            <p className="text-xs text-slate-400 leading-relaxed">{policy.guideline}</p>

            <div className="space-y-2 pt-2 border-t border-slate-800/80 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">Category:</span>
                <span className="font-semibold text-slate-300">{policy.category}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Severity:</span>
                <span className="font-semibold text-rose-400">{policy.severity}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Source Path:</span>
                <span className="font-mono text-indigo-400">{policy.file}</span>
              </div>
            </div>

            {/* Test Simulation Button */}
            <button
              onClick={handleRunPolicyTest}
              className="w-full mt-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 text-white font-semibold text-xs flex items-center justify-center space-x-2 transition-all shadow-lg shadow-indigo-600/20"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>Test Rule Evaluation</span>
            </button>
          </div>

          {/* Test Evaluation Terminal Output */}
          {testResult && (
            <div className="glass-panel p-4 rounded-2xl border border-indigo-500/30 bg-slate-950 font-mono text-xs text-indigo-300 space-y-2 animate-fadeIn">
              <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
                <Cpu className="w-4 h-4 text-indigo-400" />
                <span className="font-bold text-slate-200">Checkov Execution Output</span>
              </div>
              <pre className="whitespace-pre-wrap leading-relaxed">{testResult}</pre>
            </div>
          )}
        </div>

        {/* Right Side: Code View */}
        <div className="lg:col-span-2 glass-panel rounded-2xl border border-slate-800 overflow-hidden flex flex-col">
          <div className="bg-slate-900/90 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Code2 className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-bold text-slate-200 font-mono">{policy.file}</span>
            </div>
            <button
              onClick={handleCopy}
              className="text-slate-400 hover:text-slate-200 text-xs flex items-center space-x-1"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Code'}</span>
            </button>
          </div>
          <div className="p-5 overflow-x-auto bg-slate-950 font-mono text-xs text-slate-200 leading-relaxed min-h-[450px]">
            <pre>{policy.code}</pre>
          </div>
        </div>
      </div>
    </div>
  );
};
