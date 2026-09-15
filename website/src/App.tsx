import { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardOverview } from './components/DashboardOverview';
import { IacScanner } from './components/IacScanner';
import { ReportsExplorer } from './components/ReportsExplorer';
import { CodeInspector } from './components/CodeInspector';
import { PipelineVisualizer } from './components/PipelineVisualizer';
import { DocumentationView } from './components/DocumentationView';
import { 
  fetchHealth, 
  runScan, 
  NormalizedScanResult, 
  SystemHealth 
} from './services/api';
import { AlertCircle, RefreshCw } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isRemediated, setIsRemediated] = useState(false); // Default to vulnerable to demonstrate gate failure first!
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<NormalizedScanResult | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  // Execute scan for given target or custom code snippet
  const executeScan = useCallback(async (targetOverride?: string, customCode?: string) => {
    setIsScanning(true);
    setApiError(null);
    try {
      let result;
      if (customCode && customCode.trim()) {
        result = await runScan(undefined, customCode.trim());
      } else {
        const target = targetOverride || (isRemediated ? 'terraform/remediated' : 'terraform/vulnerable');
        result = await runScan(target);
      }
      setScanResult(result);
      // Refresh system health to reflect latest gate state
      fetchHealth().then(setHealth).catch(() => {});
      return result;
    } catch (err: any) {
      console.warn('Scan API call failed:', err);
      setApiError(err?.message || 'Failed to connect to backend scanner');
      throw err;
    } finally {
      setIsScanning(false);
    }
  }, [isRemediated]);

  // Initial load: fetch health and run baseline scan
  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch((err) => {
        console.warn('Backend not currently reachable:', err);
      });

    // Run initial scan on baseline (vulnerable suite)
    executeScan('terraform/vulnerable').catch(() => {});
  }, []);

  // Posture switcher: toggle vulnerable vs remediated suite
  const handleTogglePosture = (newIsRemediated: boolean) => {
    setIsRemediated(newIsRemediated);
    const target = newIsRemediated ? 'terraform/remediated' : 'terraform/vulnerable';
    executeScan(target).catch(() => {});
  };

  // Handler for RUN SECURITY SCAN button
  const handleRunSecurityScan = async () => {
    setActiveTab('scanner');
    const target = isRemediated ? 'terraform/remediated' : 'terraform/vulnerable';
    await executeScan(target).catch(() => {});
  };

  const gateStatus = scanResult?.gate_status || (isRemediated ? 'PASSED' : 'BLOCKED');

  return (
    <div className="min-h-screen bg-[#050811] text-slate-100 bg-cyber-grid flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200 relative">
      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isRemediated={isRemediated}
        setIsRemediated={handleTogglePosture}
        gateStatus={gateStatus}
      />

      {/* Optional Backend Connection Notice (Non-disruptive) */}
      {apiError && (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-4 w-full">
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>Notice: {apiError}. (Ensure backend is running: <code>python -m uvicorn backend.main:app --port 8000</code>)</span>
            </div>
            <button
              onClick={() => executeScan()}
              className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 text-xs flex items-center space-x-1"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Retry</span>
            </button>
          </div>
        </div>
      )}

      {/* Main Content Viewport */}
      <main className={`flex-1 w-full mx-auto ${
        activeTab === 'dashboard'
          ? 'w-full max-w-[1800px] px-4 sm:px-6 lg:px-8 py-3 flex flex-col justify-center'
          : 'max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-8'
      }`}>
        {activeTab === 'dashboard' && (
          <DashboardOverview
            isRemediated={isRemediated}
            setIsRemediated={handleTogglePosture}
            setActiveTab={setActiveTab}
            onRunScan={handleRunSecurityScan}
            isScanning={isScanning}
            scanResult={scanResult}
            health={health}
          />
        )}

        {activeTab === 'scanner' && (
          <IacScanner
            isRemediated={isRemediated}
            setIsRemediated={handleTogglePosture}
            setActiveTab={setActiveTab}
            onRunScan={executeScan}
            isScanning={isScanning}
            scanResult={scanResult}
          />
        )}

        {activeTab === 'results' && (
          <ReportsExplorer
            isRemediated={isRemediated}
            scanResult={scanResult}
          />
        )}

        {activeTab === 'findings' && (
          <CodeInspector
            scanResult={scanResult}
            isRemediated={isRemediated}
          />
        )}

        {activeTab === 'pipeline' && (
          <PipelineVisualizer />
        )}

        {activeTab === 'docs' && (
          <DocumentationView />
        )}
      </main>
    </div>
  );
}

export default App;
