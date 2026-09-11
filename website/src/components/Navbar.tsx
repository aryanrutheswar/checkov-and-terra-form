import React from 'react';
import { ShieldCheck, ShieldAlert, Code2, FileCode, GitBranch, Terminal, Play, Lock, Bot } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isRemediated: boolean;
  setIsRemediated: (val: boolean) => void;
  onToggleAiGuide: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isRemediated,
  setIsRemediated,
  onToggleAiGuide
}) => {
  const navItems = [
    { id: 'overview', label: 'Command Center', icon: ShieldCheck },
    { id: 'code-inspector', label: 'HCL Code Inspector', icon: Code2 },
    { id: 'custom-policies', label: 'Custom Policy Studio', icon: FileCode },
    { id: 'pipeline', label: 'Shift-Left CI/CD', icon: GitBranch },
    { id: 'sandbox', label: 'Live IaC Sandbox', icon: Play },
    { id: 'reports', label: 'CLI & Reports', icon: Terminal },
  ];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('overview')}>
            <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-600 via-indigo-500 to-emerald-500 text-white shadow-lg shadow-indigo-500/20">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg text-slate-100 tracking-tight">Checkov IaC Security</span>
                <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  v3.0 Suite
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">Terraform Security & Governance Engine</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* AI Guide Trigger Button */}
            <button
              onClick={onToggleAiGuide}
              className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-lg shadow-indigo-900/30 transition-all"
            >
              <Bot className="w-4 h-4 text-purple-200 animate-pulse" />
              <span>AI Guide Assistant</span>
            </button>

            {/* Infrastructure Posture Toggle Switch */}
            <div className="flex items-center space-x-2 bg-slate-900/90 p-1.5 rounded-xl border border-slate-800">
              <span className="text-xs font-medium text-slate-400 pl-2 hidden sm:inline">Infrastructure Mode:</span>
              <button
                onClick={() => setIsRemediated(false)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  !isRemediated
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 glow-rose'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                <span>Vulnerable</span>
              </button>
              <button
                onClick={() => setIsRemediated(true)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  isRemediated
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 glow-emerald'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Remediated</span>
              </button>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 overflow-x-auto no-scrollbar border-t border-slate-800/60 pt-1 pb-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-2 px-4 py-2 text-xs font-medium rounded-lg whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-indigo-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
