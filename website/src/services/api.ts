export interface Finding {
  check_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  file: string;
  line: number | null;
  line_range?: [number, number] | null;
  resource: string;
  remediation: string;
  status: string;
  guideline?: string;
  code_snippet?: string | null;
  category?: string;
}

export interface NormalizedScanResult {
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  skipped_checks: number;
  compliance_percentage: number;
  gate_status: 'BLOCKED' | 'PASSED';
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  target_directory: string;
  scan_time: string;
  scan_duration_seconds: number;
  checkov_version: string;
  findings: Finding[];
  exit_code?: number;
  block_policy?: string[];
}

export interface SystemHealth {
  status: string;
  terraform: {
    detected: boolean;
    hcl_files_count: number;
    vulnerable_suite: boolean;
    remediated_suite: boolean;
  };
  checkov: {
    installed: boolean;
    version: string;
    engine: string;
  };
  github_actions: {
    detected: boolean;
    workflows_count: number;
    workflow_files: string[];
  };
  deployment_gate: {
    status: string;
    policy: string[];
  };
  timestamp: string;
}

export interface SecurityConfig {
  block_on: string[];
  warn_on: string[];
  allowed_directories: string[];
  default_target: string;
}

const API_BASE = '/api';

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed with status: ${res.status}`);
  }
  return res.json();
}

export async function fetchConfig(): Promise<SecurityConfig> {
  const res = await fetch(`${API_BASE}/config`);
  if (!res.ok) {
    throw new Error(`Config fetch failed with status: ${res.status}`);
  }
  return res.json();
}

export async function runScan(target?: string, customCode?: string): Promise<NormalizedScanResult> {
  const payload: { target?: string; custom_code?: string } = {};
  if (customCode && customCode.trim()) {
    payload.custom_code = customCode.trim();
  } else if (target) {
    payload.target = target;
  }

  const res = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan failed with status: ${res.status}`);
  }
  return res.json();
}

export async function fetchLatestResults(): Promise<NormalizedScanResult> {
  const res = await fetch(`${API_BASE}/results`);
  if (!res.ok) {
    throw new Error(`Failed to load results with status: ${res.status}`);
  }
  return res.json();
}
