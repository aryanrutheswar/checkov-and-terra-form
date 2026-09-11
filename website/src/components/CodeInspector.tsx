import React, { useState } from 'react';
import { INFRASTRUCTURE_FILES, CHECK_DETAILS } from '../data/securityData';
import { Code2, ShieldCheck, ShieldAlert, FileText, AlertTriangle, Copy, Check, Sparkles, GitPullRequest } from 'lucide-react';

export const CodeInspector: React.FC = () => {
  const [selectedFileIndex, setSelectedFileIndex] = useState(0);
  const [viewMode, setViewMode] = useState<'split' | 'vulnerable' | 'remediated' | 'ai-patch'>('split');
  const [copied, setCopied] = useState(false);
  const [patchApplied, setPatchApplied] = useState(false);

  const currentFile = INFRASTRUCTURE_FILES[selectedFileIndex];
  const fileChecks = CHECK_DETAILS.filter(c => c.file === currentFile.filename);

  const generatePatch = () => {
    const vulnLines = currentFile.vulnerableCode.split('\n');
    const remLines = currentFile.remediatedCode.split('\n');
    
    let diff = `--- a/terraform/vulnerable/${currentFile.filename}\n+++ b/terraform/remediated/${currentFile.filename}\n@@ -1,${vulnLines.length} +1,${remLines.length} @@\n`;
    
    vulnLines.forEach(line => {
      if (line.trim()) diff += `- ${line}\n`;
    });
    remLines.forEach(line => {
      if (line.trim()) diff += `+ ${line}\n`;
    });
    return diff;
  };

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleApplyPatch = () => {
    setPatchApplied(true);
    setTimeout(() => setPatchApplied(false), 4000);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header Controls */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <Code2 className="w-6 h-6 text-indigo-400" />
            <span>Terraform HCL Security Inspector</span>
          </h1>
          <p className="text-xs text-slate-400">
            Compare side-by-side vulnerable anti-patterns against production-hardened Checkov remediated HCL manifests.
          </p>
        </div>

        {/* File Tabs & View Mode Switcher */}
        <div className="flex flex-wrap items-center gap-3">
          {/* File Switcher */}
          <div className="flex bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            {INFRASTRUCTURE_FILES.map((file, idx) => (
              <button
                key={file.filename}
                onClick={() => {
                  setSelectedFileIndex(idx);
                  setPatchApplied(false);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  selectedFileIndex === idx
                    ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {file.filename}
              </button>
            ))}
          </div>

          {/* View Mode Switcher */}
          <div className="flex bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setViewMode('split')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                viewMode === 'split' ? 'bg-slate-800 text-slate-100' : 'text-slate-400'
              }`}
            >
              Split View
            </button>
            <button
              onClick={() => setViewMode('vulnerable')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                viewMode === 'vulnerable' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400'
              }`}
            >
              Vulnerable
            </button>
            <button
              onClick={() => setViewMode('remediated')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                viewMode === 'remediated' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400'
              }`}
            >
              Remediated
            </button>
            <button
              onClick={() => setViewMode('ai-patch')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1 ${
                viewMode === 'ai-patch'
                  ? 'bg-gradient-to-r from-indigo-500/30 to-purple-500/30 text-purple-300 border border-purple-500/40'
                  : 'text-purple-400 hover:text-purple-300'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>AI Patch Studio</span>
            </button>
          </div>
        </div>
      </div>

      {/* Security Summary Bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center space-x-3">
          <FileText className="w-5 h-5 text-indigo-400" />
          <div>
            <span className="text-xs font-semibold text-slate-400">Target File</span>
            <p className="text-sm font-bold text-slate-200 font-mono">{currentFile.filename}</p>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center space-x-3">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <div>
            <span className="text-xs font-semibold text-slate-400">Vulnerable Baseline Flaws</span>
            <p className="text-sm font-bold text-rose-400">{currentFile.failingRulesCount} Checkov Violations</p>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center space-x-3">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <div>
            <span className="text-xs font-semibold text-slate-400">Hardened Remediated Posture</span>
            <p className="text-sm font-bold text-emerald-400">{currentFile.passedRulesCount} Security Controls Passed</p>
          </div>
        </div>
      </div>

      {/* AI Patch Studio View */}
      {viewMode === 'ai-patch' ? (
        <div className="space-y-4">
          <div className="glass-panel p-5 rounded-2xl border border-purple-500/30 bg-purple-950/10 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-300">
                <Sparkles className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                  <span>AI Auto-Remediation Unified Patch Generator</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    AST / HCL Transformer
                  </span>
                </h3>
                <p className="text-xs text-slate-400">
                  Generates 1-click unified git patches to automatically resolve all {currentFile.failingRulesCount} Checkov policy failures in {currentFile.filename}.
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={() => handleCopy(generatePatch())}
                className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center space-x-1.5 transition-all"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                <span>{copied ? 'Patch Copied!' : 'Copy Git Patch'}</span>
              </button>
              <button
                onClick={handleApplyPatch}
                disabled={patchApplied}
                className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center space-x-2 transition-all shadow-lg ${
                  patchApplied
                    ? 'bg-emerald-600 text-white shadow-emerald-900/40'
                    : 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-indigo-900/40'
                }`}
              >
                {patchApplied ? (
                  <>
                    <ShieldCheck className="w-4 h-4 text-emerald-200" />
                    <span>Patch Applied Successfully!</span>
                  </>
                ) : (
                  <>
                    <GitPullRequest className="w-4 h-4" />
                    <span>Apply Remediation Patch</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {patchApplied && (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center justify-between animate-fadeIn">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Simulated auto-remediation complete: <strong>{currentFile.filename}</strong> has been updated to production-hardened Checkov compliance.</span>
              </div>
              <span className="font-mono text-emerald-400">0 Violations Remaining</span>
            </div>
          )}

          {/* Unified Diff Output Box */}
          <div className="glass-panel rounded-2xl border border-purple-500/30 overflow-hidden flex flex-col">
            <div className="bg-slate-900/90 px-4 py-3 border-b border-purple-500/30 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span className="text-xs font-mono font-bold text-purple-300">patch/{currentFile.filename}.patch</span>
              </div>
              <span className="text-[11px] font-mono text-slate-400">Git Unified Diff Syntax</span>
            </div>
            <div className="p-4 overflow-x-auto bg-slate-950 font-mono text-xs leading-relaxed max-h-[500px] space-y-1">
              <div className="text-slate-500">--- a/terraform/vulnerable/{currentFile.filename}</div>
              <div className="text-slate-500">+++ b/terraform/remediated/{currentFile.filename}</div>
              <div className="text-purple-400 font-bold">@@ -1,15 +1,28 @@ Checkov Remediated HCL Transformation</div>
              {currentFile.vulnerableCode.split('\n').map((line, idx) => (
                <div key={`vuln-${idx}`} className="text-rose-400/90 bg-rose-950/20 px-2 py-0.5 rounded">
                  - {line}
                </div>
              ))}
              {currentFile.remediatedCode.split('\n').map((line, idx) => (
                <div key={`rem-${idx}`} className="text-emerald-400/90 bg-emerald-950/20 px-2 py-0.5 rounded">
                  + {line}
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        /* Code Viewer Grid */
        <div className={`grid gap-6 ${viewMode === 'split' ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
          {/* Vulnerable Code Box */}
          {(viewMode === 'split' || viewMode === 'vulnerable') && (
            <div className="glass-panel rounded-2xl border border-rose-500/30 overflow-hidden flex flex-col">
              <div className="bg-slate-900/90 px-4 py-3 border-b border-rose-500/30 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span className="text-xs font-bold text-rose-300">vulnerable/{currentFile.filename}</span>
                </div>
                <button
                  onClick={() => handleCopy(currentFile.vulnerableCode)}
                  className="text-slate-400 hover:text-slate-200 text-xs flex items-center space-x-1"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="p-4 overflow-x-auto bg-slate-950 font-mono text-xs text-rose-200/90 leading-relaxed max-h-[500px]">
                <pre>{currentFile.vulnerableCode}</pre>
              </div>
            </div>
          )}

          {/* Remediated Code Box */}
          {(viewMode === 'split' || viewMode === 'remediated') && (
            <div className="glass-panel rounded-2xl border border-emerald-500/30 overflow-hidden flex flex-col">
              <div className="bg-slate-900/90 px-4 py-3 border-b border-emerald-500/30 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-bold text-emerald-300">remediated/{currentFile.filename}</span>
                </div>
                <button
                  onClick={() => handleCopy(currentFile.remediatedCode)}
                  className="text-slate-400 hover:text-slate-200 text-xs flex items-center space-x-1"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="p-4 overflow-x-auto bg-slate-950 font-mono text-xs text-emerald-200/90 leading-relaxed max-h-[500px]">
                <pre>{currentFile.remediatedCode}</pre>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Rules Mapped to Selected File */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-indigo-400" />
          <span>Security Checks Evaluated on {currentFile.filename}</span>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {fileChecks.map(check => (
            <div key={check.id} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-indigo-400">{check.id}</span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-rose-500/10 text-rose-400">
                  {check.severity}
                </span>
              </div>
              <h3 className="text-xs font-bold text-slate-200">{check.name}</h3>
              <p className="text-xs text-slate-400">{check.guideline}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

