import React from 'react';
import { 
  ShieldCheck, 
  Code2, 
  GitBranch, 
  Terminal, 
  FileText, 
  Radar 
} from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isRemediated: boolean;
  setIsRemediated: (val: boolean) => void;
  gateStatus?: 'BLOCKED' | 'PASSED';
  onRunScanClick?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isRemediated,
  setIsRemediated,
  gateStatus = 'BLOCKED',
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Radar },
    { id: 'scanner', label: 'IaC Scanner', icon: Terminal },
    { id: 'results', label: 'Scan Results', icon: ShieldCheck },
    { id: 'findings', label: 'Security Findings', icon: Code2 },
    { id: 'pipeline', label: 'CI/CD Pipeline', icon: GitBranch },
    { id: 'docs', label: 'Documentation', icon: FileText },
  ];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-cyan-500/20 bg-[#050811]/90 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Title */}
          <div 
            className="flex items-center space-x-3 cursor-pointer group" 
            onClick={() => setActiveTab('dashboard')}
          >
            <div className="relative p-2 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-700 text-black shadow-lg shadow-cyan-500/25 group-hover:shadow-cyan-400/50 transition-all">
              <ShieldCheck className="w-6 h-6 text-black font-extrabold" />
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
              </span>
            </div>
            <div>
              <span className="font-extrabold text-lg text-slate-100 tracking-wider font-mono text-glow-cyan">
                CYBER<span className="text-cyan-400">SENTINEL</span>
              </span>
              <p className="text-[11px] text-slate-400 font-mono">IaC Security Gate & Governance Platform</p>
            </div>
          </div>

          {/* Right Header Controls: Mode Selector & Gate Status */}
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setIsRemediated(!isRemediated)}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all ${
                isRemediated 
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20' 
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-400 hover:bg-rose-500/20'
              }`}
              title="Toggle between vulnerable baseline and remediated infrastructure code"
            >
              <span className={`w-2 h-2 rounded-full ${isRemediated ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400 animate-pulse'}`}></span>
              <span className="hidden sm:inline">Mode:</span>
              <span className="font-semibold">{isRemediated ? 'Remediated' : 'Vulnerable'}</span>
            </button>

            <span className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold tracking-wider uppercase border ${
              gateStatus === 'PASSED'
                ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/40 text-rose-300'
            }`}>
              Gate: {gateStatus}
            </span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 overflow-x-auto no-scrollbar border-t border-cyan-500/10 pt-1 pb-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-2 px-3.5 py-2 text-xs font-semibold rounded-lg whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
