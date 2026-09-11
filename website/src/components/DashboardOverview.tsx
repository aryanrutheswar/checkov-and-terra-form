import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Eye, 
  Award, 
  ArrowRight,
  Sparkles
} from 'lucide-react';
import { SCAN_METRICS, COMPLIANCE_FRAMEWORKS, CHECK_DETAILS } from '../data/securityData';

interface DashboardOverviewProps {
  isRemediated: boolean;
  setIsRemediated: (val: boolean) => void;
  setActiveTab: (tab: string) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  isRemediated,
  setIsRemediated,
  setActiveTab
}) => {
  const metrics = isRemediated ? SCAN_METRICS.remediated : SCAN_METRICS.vulnerable;

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Top Banner Alert */}
      <div className={`p-6 rounded-2xl border transition-all ${
        isRemediated
          ? 'bg-gradient-to-r from-emerald-950/50 via-slate-900 to-indigo-950/30 border-emerald-500/30 glow-emerald'
          : 'bg-gradient-to-r from-rose-950/50 via-slate-900 to-amber-950/30 border-rose-500/40 glow-rose'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center space-x-3">
              {isRemediated ? (
                <span className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  <ShieldCheck className="w-6 h-6" />
                </span>
              ) : (
                <span className="p-2 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  <ShieldAlert className="w-6 h-6" />
                </span>
              )}
              <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                {isRemediated 
                  ? 'Hardened Production Security Posture' 
                  : 'Vulnerable Baseline Security Scan Report'}
              </h1>
            </div>
            <p className="text-sm text-slate-300">
              {isRemediated
                ? 'Infrastructure manifests in `terraform/remediated/` pass 100% of Checkov security rules and custom organizational policies with zero active vulnerabilities.'
                : 'Baseline infrastructure in `terraform/vulnerable/` contains 39 high-risk misconfigurations across S3, IAM, RDS PostgreSQL, and Security Groups.'}
            </p>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setIsRemediated(!isRemediated)}
              className={`px-5 py-2.5 rounded-xl font-semibold text-xs flex items-center space-x-2 transition-all shadow-lg ${
                isRemediated
                  ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/20'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20'
              }`}
            >
              <Sparkles className="w-4 h-4" />
              <span>Switch to {isRemediated ? 'Vulnerable Baseline' : 'Remediated Posture'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Compliance Score */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Compliance Rating</span>
            <Award className={`w-5 h-5 ${isRemediated ? 'text-emerald-400' : 'text-rose-400'}`} />
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className={`text-4xl font-extrabold tracking-tight ${isRemediated ? 'text-emerald-400' : 'text-rose-400'}`}>
              {metrics.complianceScore}%
            </span>
            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
              isRemediated ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
            }`}>
              {isRemediated ? 'Grade A+' : 'Grade F'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400 font-mono">
            {isRemediated ? 'Passes all 5 benchmark standards' : 'Critical security gaps detected'}
          </p>
        </div>

        {/* Passed Checks */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Passed Policy Checks</span>
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-4xl font-extrabold text-slate-100">{metrics.passed}</span>
            <span className="text-xs text-emerald-400 font-mono">/ {metrics.total} Total</span>
          </div>
          <p className="mt-2 text-xs text-slate-400 font-mono">Static & custom checks passing</p>
        </div>

        {/* Failed Checks */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Failed Policy Checks</span>
            <XCircle className={`w-5 h-5 ${metrics.failed > 0 ? 'text-rose-400' : 'text-slate-500'}`} />
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className={`text-4xl font-extrabold ${metrics.failed > 0 ? 'text-rose-400' : 'text-slate-100'}`}>
              {metrics.failed}
            </span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
              metrics.failed > 0 ? 'bg-rose-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'
            }`}>
              {metrics.failed > 0 ? 'Action Required' : 'Zero Failures'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400 font-mono">Blocks CI/CD deployment pipeline</p>
        </div>

        {/* Suppressed / Skipped */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Inline Suppressions</span>
            <Eye className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-4xl font-extrabold text-slate-100">{metrics.skipped}</span>
            <span className="text-xs text-indigo-400 font-mono"># checkov:skip</span>
          </div>
          <p className="mt-2 text-xs text-slate-400 font-mono">Documented security exemptions</p>
        </div>
      </div>

      {/* Compliance Benchmarks Matrix */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
              <Award className="w-5 h-5 text-indigo-400" />
              <span>Compliance Framework Readiness</span>
            </h2>
            <p className="text-xs text-slate-400">Automated mapping of Checkov policy controls to enterprise compliance standards.</p>
          </div>
          <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-3 py-1 rounded-full border border-indigo-500/20">
            5/5 Frameworks Mapped
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {COMPLIANCE_FRAMEWORKS.map((fw) => {
            const score = isRemediated ? fw.remediatedScore : fw.vulnerableScore;
            return (
              <div key={fw.code} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-indigo-500/30 transition-all space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-slate-200">{fw.name}</h3>
                    <span className="text-xs font-mono text-indigo-400">{fw.code}</span>
                  </div>
                  <span className={`px-2 py-1 text-xs font-bold rounded-lg ${
                    score === 100 
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                  }`}>
                    {score}%
                  </span>
                </div>
                <p className="text-xs text-slate-400 line-clamp-2">{fw.description}</p>
                {/* Progress Bar */}
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full rounded-full transition-all duration-500 ${
                      score === 100 ? 'bg-gradient-to-r from-emerald-500 to-indigo-500' : 'bg-gradient-to-r from-rose-500 to-amber-500'
                    }`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Vulnerabilities Breakdown List */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
              <AlertTriangle className={`w-5 h-5 ${isRemediated ? 'text-emerald-400' : 'text-rose-400'}`} />
              <span>
                {isRemediated ? 'Verified Security Controls & Skip Rationale' : 'Active Vulnerability Audit & Fixes'}
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              {isRemediated 
                ? 'All rules evaluated against remediated manifests in `terraform/remediated/`.' 
                : 'Failed Checkov rules detected in `terraform/vulnerable/`.'}
            </p>
          </div>

          <button
            onClick={() => setActiveTab('code-inspector')}
            className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 flex items-center space-x-1"
          >
            <span>Open HCL Code Inspector</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-3">
          {CHECK_DETAILS.map((check) => (
            <div 
              key={check.id}
              className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-indigo-500/30 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div className="space-y-1 max-w-3xl">
                <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                  <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                    {check.id}
                  </span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                    check.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                    check.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {check.severity}
                  </span>
                  <span className="text-xs font-medium text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                    {check.category}
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-200">{check.name}</h3>
                <p className="text-xs text-slate-400">{check.guideline}</p>
                <div className="flex items-center space-x-3 pt-1">
                  <span className="text-xs font-mono text-slate-400">File: {check.file}</span>
                  <span className="text-xs text-slate-500">•</span>
                  <span className="text-xs font-mono text-slate-400">Resource: {check.resource}</span>
                </div>
              </div>

              <div className="flex items-center space-x-3 self-start md:self-center">
                <span className={`px-3 py-1 rounded-lg text-xs font-bold flex items-center space-x-1.5 ${
                  isRemediated
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                }`}>
                  {isRemediated ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>PASSED</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3.5 h-3.5 text-rose-400" />
                      <span>FAILED</span>
                    </>
                  )}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
