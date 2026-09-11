# Implementation Plan - Advanced Features for Terraform Checkov Security Suite

Add top-tier DevSecOps features to the **Terraform Checkov Security Suite**, including an AI Auto-Remediation Patch Generator, Compliance Scorecard Exporter, Attack Vector & Threat Model Visualizer, and Multi-Framework Scan Engine.

## Proposed Changes

---

### Frontend Web Platform (`website/src/`)

#### [MODIFY] [CodeInspector.tsx](file:///d:/projects/devops%20project/terraform-checkov-security-suite/website/src/components/CodeInspector.tsx)
- Add **AI Auto-Remediation Patch Mode** alongside Split/Vulnerable/Remediated views.
- Render dynamic git diff patch blocks highlighting exact lines added (`+`) and removed (`-`) to fix Checkov rule violations.
- Add **"Apply Patch Simulator"** and **"Copy Unified Patch"** actions.

#### [MODIFY] [DashboardOverview.tsx](file:///d:/projects/devops%20project/terraform-checkov-security-suite/website/src/components/DashboardOverview.tsx)
- Add interactive **Compliance Framework Scorecard** cards for CIS AWS 1.4, NIST 800-53, SOC 2, HIPAA, and PCI-DSS.
- Add live posture score toggles between baseline (vulnerable) and hardened states.

#### [MODIFY] [PipelineVisualizer.tsx](file:///d:/projects/devops%20project/terraform-checkov-security-suite/website/src/components/PipelineVisualizer.tsx)
- Add a **Threat Vector & Blast Radius Visualizer** sub-view.
- Render interactive node attack chains (e.g. `Public Internet` ➔ `Port 22 Ingress` ➔ `Wildcard IAM Role` ➔ `Exposed S3 Bucket`).
- Show exploitation likelihood, blast radius metrics, and mitigation checkpoints.

#### [MODIFY] [ReportsExplorer.tsx](file:///d:/projects/devops%20project/terraform-checkov-security-suite/website/src/components/ReportsExplorer.tsx)
- Add **Executive PDF Audit Report Generator** feature.
- Include printable compliance breakdown, policy metrics summary, and export capability.

---

### Automation Scripts (`scripts/`)

#### [MODIFY] [run_scans.ps1](file:///d:/projects/devops%20project/terraform-checkov-security-suite/scripts/run_scans.ps1)
#### [MODIFY] [run_scans.sh](file:///d:/projects/devops%20project/terraform-checkov-security-suite/scripts/run_scans.sh)
- Add parameters to support `--framework` selection (`terraform`, `dockerfile`, `kubernetes`, `all`).
- Add `--export-format` parameter (`cli`, `sarif`, `json`) and colored terminal logging for multi-framework execution.

---

## Verification Plan

### Manual Verification
1. Open [`http://localhost:5173/`](http://localhost:5173/) in browser.
2. Test **Code Inspector**'s new **AI Remediation Patch** view mode and verify git diff generation.
3. Test **Dashboard Overview** compliance framework cards and score toggling.
4. Test **Pipeline Visualizer** attack chain node visualization.
5. Run updated `.\scripts\run_scans.ps1 -Target "all"` in PowerShell to verify multi-framework scanning flags.
