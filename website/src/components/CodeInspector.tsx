import React, { useState } from 'react';
import { INFRASTRUCTURE_FILES, CHECK_DETAILS } from '../data/securityData';
import { 
  Code2, 
  ShieldCheck, 
  ShieldAlert, 
  FileText, 
  AlertTriangle, 
  Copy, 
  Check, 
  Sparkles, 
  GitPullRequest,
  ChevronDown,
  ChevronUp,
  ExternalLink
} from 'lucide-react';
import { NormalizedScanResult, Finding } from '../services/api';

interface CodeInspectorProps {
  scanResult?: NormalizedScanResult | null;
  isRemediated?: boolean;
}

export const CodeInspector: React.FC<CodeInspectorProps> = ({ scanResult, isRemediated = false }) => {
  const [selectedFileIndex, setSelectedFileIndex] = useState(0);
  const [viewMode, setViewMode] = useState<'split' | 'vulnerable' | 'remediated' | 'ai-patch'>('split');
  const [copied, setCopied] = useState(false);
  const [patchApplied, setPatchApplied] = useState(false);
  const [inspectedCheckId, setInspectedCheckId] = useState<string | null>(null);

  const currentFile = INFRASTRUCTURE_FILES[selectedFileIndex];

  // Find real checkov findings matching current file
  const realFileFindings: Finding[] = (scanResult && scanResult.findings)
    ? scanResult.findings.filter(f => f.file.toLowerCase() === currentFile.filename.toLowerCase())
    : [];

  const failingCount = scanResult 
    ? realFileFindings.length 
    : currentFile.failingRulesCount;
  const passedCount = isRemediated 
    ? currentFile.passedRulesCount 
    : (scanResult ? 0 : currentFile.passedRulesCount);

  // Fallback checks from CHECK_DETAILS
  const fallbackChecks = CHECK_DETAILS.filter(c => c.file === currentFile.filename);

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
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center space-x-2">
            <Code2 className="w-6 h-6 text-cyan-400" />
            <span>SECURITY FINDINGS & HCL CODE INSPECTOR</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Analyze real Checkov findings, inspect root-cause vulnerabilities, and compare flawed HCL anti-patterns against hardened manifests.
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
                  setInspectedCheckId(null);
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
            <p className="text-sm font-bold text-rose-400">{failingCount} Checkov Violations</p>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center space-x-3">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <div>
            <span className="text-xs font-semibold text-slate-400">Hardened Remediated Posture</span>
            <p className="text-sm font-bold text-emerald-400">{passedCount} Security Controls Passed</p>
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
                  Generates 1-click unified git patches to automatically resolve all Checkov policy failures in {currentFile.filename}.
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
                    <span>Patch Applied (Simulated)</span>
                  </>
                ) : (
                  <>
                    <GitPullRequest className="w-4 h-4" />
                    <span>Inspect Remediation Patch</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {patchApplied && (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center justify-between animate-fadeIn">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Simulated remediation preview: <strong>{currentFile.filename}</strong> matches production-hardened Checkov compliance.</span>
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

      {/* Rules Mapped to Selected File (Requirement #7 and #10: Real Checkov findings) */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-indigo-400" />
            <span>Security Findings & Remediation Inspector for {currentFile.filename}</span>
          </h2>
          <span className="text-xs font-mono text-slate-400">
            {realFileFindings.length > 0 ? `${realFileFindings.length} Active Findings` : `${fallbackChecks.length} Evaluated Rules`}
          </span>
        </div>

        <div className="space-y-4">
          {(realFileFindings.length > 0 ? realFileFindings : fallbackChecks).map((check: any) => {
            const checkId = check.check_id || check.id;
            const checkTitle = check.title || check.name;
            const isInspected = inspectedCheckId === checkId;
            return (
              <div key={checkId} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3 transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                      {checkId}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      check.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                      check.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                      'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    }`}>
                      {check.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      File: <code className="text-slate-300">{check.file}</code>
                      {check.line ? ` : Line ${check.line}` : ''}
                    </span>
                    {check.resource && (
                      <span className="text-xs font-mono text-slate-400 hidden md:inline">
                        • Resource: <span className="text-cyan-300">{check.resource}</span>
                      </span>
                    )}
                  </div>

                  <button
                    onClick={() => setInspectedCheckId(isInspected ? null : checkId)}
                    className="px-3 py-1 rounded-lg text-xs font-mono bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center space-x-1.5 transition-all self-start sm:self-auto"
                  >
                    <span>{isInspected ? 'Hide Remediation' : 'Inspect Remediation'}</span>
                    {isInspected ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div>
                  <h3 className="text-xs font-bold text-slate-200">{checkTitle}</h3>
                  <p className="text-xs text-slate-400 mt-0.5">{check.description || check.guideline}</p>
                </div>

                {/* Inspect Remediation Deep-Dive (Requirement #10) */}
                {isInspected && (
                  <div className="mt-3 p-4 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-3 animate-fadeIn">
                    <div className="space-y-1">
                      <span className="text-[11px] font-mono font-bold text-rose-400 uppercase tracking-wider">
                        Why this configuration is insecure:
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {check.description || 'Violates CIS AWS security benchmarks by introducing overly permissive access or missing mandatory encryption controls.'}
                      </p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 pt-1">
                      <div className="space-y-1">
                        <span className="text-[11px] font-mono text-rose-400 flex items-center space-x-1">
                          <ShieldAlert className="w-3 h-3" />
                          <span>Vulnerable Terraform Pattern ({check.file}{check.line ? ` : L${check.line}` : ''}):</span>
                        </span>
                        <div className="p-3 rounded-lg bg-[#0a0507] border border-rose-900/40 text-xs font-mono text-rose-200/90 overflow-x-auto max-h-36">
                          <pre>{check.code_snippet || check.vulnerableSnippet || currentFile.vulnerableCode}</pre>
                        </div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[11px] font-mono text-emerald-400 flex items-center space-x-1">
                          <ShieldCheck className="w-3 h-3" />
                          <span>Recommended Secure Configuration:</span>
                        </span>
                        <div className="p-3 rounded-lg bg-[#040d0c] border border-emerald-900/40 text-xs font-mono text-emerald-200/90 overflow-x-auto max-h-36">
                          <pre>{check.remediatedSnippet || currentFile.remediatedCode}</pre>
                        </div>
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-500/20 text-xs font-mono space-y-1">
                      <span className="text-cyan-400 font-bold">Remediation Guidance: </span>
                      <p className="text-slate-300">{check.remediation}</p>
                      {check.guideline && (
                        <div className="pt-1">
                          <a 
                            href={check.guideline} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:text-cyan-300 underline inline-flex items-center space-x-1"
                          >
                            <span>View Official Benchmark Documentation</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
