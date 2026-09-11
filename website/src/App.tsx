import { useState } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardOverview } from './components/DashboardOverview';
import { CodeInspector } from './components/CodeInspector';
import { CustomPolicyStudio } from './components/CustomPolicyStudio';
import { PipelineVisualizer } from './components/PipelineVisualizer';
import { InteractiveSandbox } from './components/InteractiveSandbox';
import { ReportsExplorer } from './components/ReportsExplorer';
import { AIGuideBot } from './components/AIGuideBot';
import { ShieldCheck, Bot } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [isRemediated, setIsRemediated] = useState(true);
  const [isAiOpen, setIsAiOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 bg-grid-pattern flex flex-col selection:bg-indigo-500/30 selection:text-indigo-200 relative">
      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isRemediated={isRemediated}
        setIsRemediated={setIsRemediated}
        onToggleAiGuide={() => setIsAiOpen(!isAiOpen)}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeTab === 'overview' && (
          <DashboardOverview
            isRemediated={isRemediated}
            setIsRemediated={setIsRemediated}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'code-inspector' && <CodeInspector />}

        {activeTab === 'custom-policies' && <CustomPolicyStudio />}

        {activeTab === 'pipeline' && <PipelineVisualizer />}

        {activeTab === 'sandbox' && <InteractiveSandbox />}

        {activeTab === 'reports' && <ReportsExplorer />}
      </main>

      {/* Floating Action Button for AI Guide (Bottom Right) */}
      <button
        onClick={() => setIsAiOpen(true)}
        className="fixed bottom-6 right-6 z-40 p-4 rounded-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-2xl shadow-indigo-500/40 hover:scale-105 transition-all flex items-center space-x-2 border border-indigo-400/30"
      >
        <Bot className="w-6 h-6 animate-pulse text-purple-200" />
        <span className="text-xs font-bold hidden md:inline">AI Guide Assistant</span>
      </button>

      {/* AI Assistant Drawer/Modal */}
      <AIGuideBot
        isOpen={isAiOpen}
        onClose={() => setIsAiOpen(false)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/80 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="font-semibold text-slate-300">Terraform Checkov Security Suite</span>
            <span>— Shift-Left Policy-as-Code Platform</span>
          </div>
          <div className="flex items-center space-x-4">
            <span className="font-mono text-slate-400">Environment: AWS / Terraform HCL</span>
            <span className="text-slate-600">•</span>
            <span className="font-mono text-slate-400">Checkov v3.2.0</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;

