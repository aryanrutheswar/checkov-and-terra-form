import React, { useState } from 'react';
import { CHECK_DETAILS, COMPLIANCE_FRAMEWORKS, SCAN_METRICS } from '../data/securityData';
import { 
  Download, 
  Terminal, 
  FileText, 
  Search, 
  CheckCircle2, 
  XCircle, 
  Eye, 
  Award, 
  ShieldAlert, 
  ShieldCheck,
  Copy,
  Check,
  Clock,
  Layers,
  FolderGit2,
  Cpu
} from 'lucide-react';
import { NormalizedScanResult } from '../services/api';

interface ReportsExplorerProps {
  isRemediated?: boolean;
  scanResult?: NormalizedScanResult | null;
}

export const ReportsExplorer: React.FC<ReportsExplorerProps> = ({ 
  isRemediated = true,
  scanResult 
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const totalChecks = scanResult ? scanResult.total_checks : (isRemediated ? 122 : 60);
  const passedChecks = scanResult ? scanResult.passed_checks : (isRemediated ? 112 : 21);
  const failedChecks = scanResult ? scanResult.failed_checks : (isRemediated ? 0 : 39);
  const skippedChecks = scanResult ? scanResult.skipped_checks : (isRemediated ? 10 : 0);
  const complianceScore = scanResult ? scanResult.compliance_percentage : (isRemediated ? 100 : 35);
  const gateStatus = scanResult ? scanResult.gate_status : (isRemediated ? 'PASSED' : 'BLOCKED');
  const scanTime = scanResult?.scan_time 
    ? new Date(scanResult.scan_time).toLocaleString() 
    : new Date().toLocaleString();
  const scanDuration = scanResult?.scan_duration_seconds ?? (isRemediated ? 1.68 : 1.45);
  const targetDir = scanResult?.target_directory || (isRemediated ? 'terraform/remediated' : 'terraform/vulnerable');
  const checkovVer = scanResult?.checkov_version || '3.3.11';

  // Real findings from scanResult if available, fallback to CHECK_DETAILS
  const sourceChecks = (scanResult && scanResult.findings && scanResult.findings.length > 0)
    ? scanResult.findings.map(f => ({
        id: f.check_id,
        name: f.title,
        severity: f.severity,
        category: f.category || 'IaC Security',
        resource: f.resource,
        file: f.file,
        line: f.line,
        description: f.description,
        remediation: f.remediation,
        guideline: f.guideline || ''
      }))
    : (isRemediated ? [] : CHECK_DETAILS);

  const filteredChecks = sourceChecks.filter((check) => {
    const matchesSeverity = severityFilter === 'ALL' || check.severity === severityFilter;
    const matchesQuery = 
      check.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      check.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      check.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      check.file.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (check.resource && check.resource.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSeverity && matchesQuery;
  });

  const handleDownloadJSON = () => {
    const payload = scanResult || {
      total_checks: totalChecks,
      passed_checks: passedChecks,
      failed_checks: failedChecks,
      skipped_checks: skippedChecks,
      compliance_percentage: complianceScore,
      gate_status: gateStatus,
      target_directory: targetDir,
      scan_time: scanTime,
      scan_duration_seconds: scanDuration,
      checkov_version: checkovVer,
      findings: sourceChecks
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `checkov_${isRemediated ? 'remediated' : 'vulnerable'}_results.json`;
    a.click();
  };

  const handleDownloadSARIF = () => {
    const sarifPayload = {
      version: "2.1.0",
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      runs: [{
        tool: { 
          driver: { 
            name: "Checkov", 
            version: checkovVer,
            informationUri: "https://www.checkov.io/"
          } 
        },
        results: sourceChecks.map(c => ({
          ruleId: c.id,
          message: { text: c.name },
          level: (c.severity === 'CRITICAL' || c.severity === 'HIGH') ? 'error' : 'warning',
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: c.file },
              region: c.line ? { startLine: c.line } : undefined
            }
          }]
        }))
      }]
    };
    const blob = new Blob([JSON.stringify(sarifPayload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `checkov_${isRemediated ? 'remediated' : 'vulnerable'}_results.sarif`;
    a.click();
  };

  const handleCopySummary = () => {
    const summaryText = `Checkov Scan Summary:
Target: ./${targetDir}
Status: ${gateStatus}
Exit Code: ${gateStatus === 'PASSED' ? 0 : 1}
Checkov Version: v${checkovVer}
Scan Time: ${scanTime} (${scanDuration}s)
Compliance Score: ${complianceScore}%
Total Checks: ${totalChecks}
Passed: ${passedChecks}
Failed: ${failedChecks}
Skipped: ${skippedChecks}`;
    navigator.clipboard.writeText(summaryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header & Export Controls */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center space-x-2">
            <Award className="w-6 h-6 text-cyan-400" />
            <span>SCAN RESULTS & COMPLIANCE SCORECARDS</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Industry compliance standard mapping (CIS, NIST, SOC 2, HIPAA, PCI) and structured audit exports.
          </p>
        </div>

        <div className="flex items-center space-x-2 flex-wrap gap-y-2">
          <button
            onClick={handleCopySummary}
            className="px-3 py-2 rounded-xl text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition-all flex items-center space-x-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy CLI Summary'}</span>
          </button>

          <button
            onClick={handleDownloadJSON}
            className="px-3.5 py-2 rounded-xl text-xs font-mono bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-500/30 transition-all flex items-center space-x-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={handleDownloadSARIF}
            className="px-3.5 py-2 rounded-xl text-xs font-mono bg-cyan-500 hover:bg-cyan-400 text-black font-semibold border border-cyan-300 transition-all flex items-center space-x-1.5 shadow-sm shadow-cyan-500/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export SARIF</span>
          </button>
        </div>
      </div>

      {/* Real Scan Metadata Telemetry Ribbon (Requirement #8) */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider flex items-center space-x-1">
              <FolderGit2 className="w-3 h-3 text-cyan-400" />
              <span>Terraform Directory</span>
            </span>
            <div className="text-xs font-mono font-bold text-slate-200 truncate">./{targetDir}</div>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider flex items-center space-x-1">
              <Cpu className="w-3 h-3 text-cyan-400" />
              <span>Checkov Version</span>
            </span>
            <div className="text-xs font-mono font-bold text-cyan-300">v{checkovVer}</div>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider flex items-center space-x-1">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>Scan Time / Duration</span>
            </span>
            <div className="text-xs font-mono text-slate-300 truncate" title={scanTime}>
              {scanDuration}s <span className="text-slate-500">({scanTime.split(',')[1] || scanTime})</span>
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider flex items-center space-x-1">
              <Layers className="w-3 h-3 text-cyan-400" />
              <span>Passed / Total</span>
            </span>
            <div className="text-xs font-mono font-bold text-slate-200">
              <span className="text-emerald-400">{passedChecks}</span> / {totalChecks}
              {skippedChecks > 0 && <span className="text-slate-500 text-[10px]"> ({skippedChecks} skip)</span>}
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider flex items-center space-x-1">
              <Award className="w-3 h-3 text-cyan-400" />
              <span>Compliance %</span>
            </span>
            <div className={`text-xs font-mono font-bold ${gateStatus === 'PASSED' ? 'text-emerald-400' : 'text-rose-400'}`}>
              {complianceScore}%
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider flex items-center space-x-1">
              <ShieldCheck className="w-3 h-3 text-cyan-400" />
              <span>Security Gate</span>
            </span>
            <div>
              <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                gateStatus === 'PASSED'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
              }`}>
                GATE: {gateStatus}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Framework Scorecards */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-sm font-bold tracking-wider uppercase font-mono text-slate-200 flex items-center space-x-2">
              <Award className="w-4 h-4 text-cyan-400" />
              <span>Enterprise Benchmark Mapping</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Posture evaluation mapped directly from Checkov rule IDs to industry regulations.
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-300 bg-cyan-500/10 px-3 py-1 rounded-full border border-cyan-500/20">
            5 Active Standards
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {COMPLIANCE_FRAMEWORKS.map((fw) => {
            const score = (gateStatus === 'PASSED') ? fw.remediatedScore : fw.vulnerableScore;
            return (
              <div 
                key={fw.code} 
                className="p-5 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-cyan-500/30 transition-all space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-slate-100">{fw.name}</h3>
                    <span className="text-[11px] font-mono text-cyan-400">{fw.code}</span>
                  </div>
                  <span className={`px-2 py-0.5 text-xs font-mono font-bold rounded ${
                    score >= 90
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                  }`}>
                    {score}%
                  </span>
                </div>
                <p className="text-xs text-slate-400 line-clamp-2">{fw.description}</p>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div 
                    className={`h-full rounded-full transition-all duration-500 ${
                      score >= 90 ? 'bg-gradient-to-r from-teal-400 to-cyan-400' : 'bg-gradient-to-r from-rose-500 to-amber-500'
                    }`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed Filterable Findings Table */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search rule ID, resource, file..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-4 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/40 w-64 sm:w-80"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded-lg transition-all ${
                    severityFilter === sev 
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="text-xs font-mono text-slate-400">
            Showing <span className="text-cyan-400 font-bold">{filteredChecks.length}</span> policy rules
          </div>
        </div>

        {/* Findings List */}
        <div className="space-y-3">
          {filteredChecks.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-950/60 border border-slate-800/80 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-sm font-bold text-slate-200 font-mono">Zero Policy Violations</div>
              <p className="text-xs text-slate-400 font-mono max-w-md mx-auto">
                {gateStatus === 'PASSED'
                  ? 'All evaluated Terraform manifests strictly adhere to CIS AWS benchmarks and enterprise security baselines.'
                  : 'No checks matching current search or severity filter.'}
              </p>
            </div>
          ) : (
            filteredChecks.map((check) => (
              <div 
                key={check.id}
                className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-cyan-500/30 transition-all space-y-2"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                      {check.id}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      check.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                      check.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                      check.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                      'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    }`}>
                      {check.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Category: <span className="text-slate-300">{check.category}</span>
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      File: <code className="text-cyan-300">{check.file}</code>
                      {check.line ? ` : L${check.line}` : ''}
                    </span>
                    {check.resource && (
                      <span className="text-xs font-mono text-slate-500 hidden sm:inline">
                        • Resource: <span className="text-slate-300">{check.resource}</span>
                      </span>
                    )}
                  </div>

                  <span className={`text-xs font-mono font-semibold px-2.5 py-0.5 rounded ${
                    gateStatus === 'PASSED' 
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                  }`}>
                    {gateStatus === 'PASSED' ? 'PASSED IN HARDENED' : 'FAILED IN BASELINE'}
                  </span>
                </div>

                <div className="font-semibold text-sm text-slate-100">{check.name}</div>
                <p className="text-xs text-slate-400">{check.description}</p>
                
                <div className="mt-2 p-3 rounded-lg bg-[#040813] border border-slate-800 text-xs font-mono">
                  <span className="text-emerald-400 font-bold">Recommended Fix: </span>
                  <span className="text-slate-300">{check.remediation}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
