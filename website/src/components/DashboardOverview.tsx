import React from 'react';
import { 
  Zap, 
  Sparkles 
} from 'lucide-react';
import { NormalizedScanResult, SystemHealth } from '../services/api';

interface DashboardOverviewProps {
  isRemediated: boolean;
  setIsRemediated: (val: boolean) => void;
  setActiveTab: (tab: string) => void;
  onRunScan: () => void;
  isScanning?: boolean;
  scanResult?: NormalizedScanResult | null;
  health?: SystemHealth | null;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  isRemediated,
  setIsRemediated,
  onRunScan,
  isScanning = false,
}) => {
  return (
    <div className="w-full flex-1 flex flex-col justify-center items-center animate-fadeIn py-1">
      {/* HERO SECTION: SECURE YOUR INFRASTRUCTURE (FULL SCREEN VIEW) */}
      <div className="relative w-full flex-1 min-h-[calc(100vh-8.5rem)] flex flex-col items-center justify-center overflow-hidden rounded-3xl border border-cyan-500/30 bg-gradient-to-b from-[#091224] via-[#060a17] to-[#040711] p-8 sm:p-14 lg:p-20 shadow-2xl shadow-cyan-950/40">
        {/* Futuristic glowing ambient background */}
        <div className="absolute top-1/4 right-1/4 -mt-20 w-[500px] h-[500px] bg-cyan-500/15 rounded-full blur-[120px] pointer-events-none" />
        <div className={`absolute bottom-1/4 left-1/4 -mb-20 w-[500px] h-[500px] ${isRemediated ? 'bg-emerald-500/15' : 'bg-rose-500/15'} rounded-full blur-[120px] pointer-events-none`} />

        <div className="relative z-10 max-w-5xl mx-auto text-center space-y-8 sm:space-y-10 my-auto">
          {/* Main Title */}
          <h1 className="text-4xl sm:text-6xl md:text-7xl lg:text-8xl font-black text-slate-100 tracking-tight font-mono uppercase leading-tight">
            SECURE YOUR <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500 text-glow-cyan">INFRASTRUCTURE</span>
          </h1>

          {/* Subtitle */}
          <p className="text-lg sm:text-2xl md:text-3xl text-slate-300 max-w-3xl mx-auto font-sans leading-relaxed font-light">
            Detect and remediate Infrastructure-as-Code vulnerabilities <span className="text-cyan-300 font-semibold underline decoration-cyan-500/40 underline-offset-8">before</span> they reach your live cloud environment.
          </p>

          {/* Main Action Button: [ RUN SECURITY SCAN ] */}
          <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-5">
            <button
              onClick={onRunScan}
              disabled={isScanning}
              className={`w-full sm:w-auto px-12 py-5 rounded-2xl font-mono text-base sm:text-xl font-bold uppercase tracking-wider flex items-center justify-center space-x-3 transition-all duration-300 shadow-2xl ${
                isScanning
                  ? 'bg-cyan-600/50 text-cyan-200 cursor-not-allowed border border-cyan-400/50'
                  : 'bg-gradient-to-r from-cyan-500 via-teal-400 to-cyan-400 hover:from-cyan-400 hover:to-teal-300 text-black shadow-cyan-500/40 hover:shadow-cyan-400/60 hover:scale-[1.03] active:scale-[0.98] border border-cyan-300'
              }`}
            >
              <Zap className={`w-6 h-6 text-black ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'EXECUTING STATIC SCAN...' : 'RUN SECURITY SCAN'}</span>
            </button>

            <button
              onClick={() => setIsRemediated(!isRemediated)}
              className="w-full sm:w-auto px-8 py-5 rounded-2xl font-mono text-sm sm:text-base font-semibold bg-slate-900/90 hover:bg-slate-800/90 text-slate-300 border border-slate-700/80 hover:border-cyan-500/40 transition-all flex items-center justify-center space-x-2.5 shadow-lg"
            >
              <Sparkles className="w-5 h-5 text-cyan-400" />
              <span>Toggle: {isRemediated ? 'Switch to Vulnerable' : 'Switch to Remediated'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
