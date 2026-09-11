# Infrastructure as Code (IaC) Security with Terraform and Checkov

A complete, production-grade reference architecture and practical testing suite for securing Terraform infrastructure using **Checkov** static analysis, custom policy-as-code engines, pre-commit shift-left hooks, and automated CI/CD security gates.

---

## 📑 Table of Contents
1. [Executive Overview & Threat Landscape](#1-executive-overview--threat-landscape)
2. [Checkov Architecture & Scanning Model](#2-checkov-architecture--scanning-model)
3. [Repository Structure](#3-repository-structure)
4. [Vulnerable vs. Hardened Manifest Breakdown](#4-vulnerable-vs-hardened-manifest-breakdown)
5. [Custom Policy Development (YAML & Python)](#5-custom-policy-development-yaml--python)
6. [Managing Suppressions & Technical Debt](#6-managing-suppressions--technical-debt)
7. [Shift-Left CI/CD Pipeline Integration](#7-shift-left-cicd-pipeline-integration)
8. [Hands-On CLI Execution & Testing Guide](#8-hands-on-cli-execution--testing-guide)
9. [Scanning Terraform Plans vs. Raw HCL](#9-scanning-terraform-plans-vs-raw-hcl)
10. [Summary of Production Best Practices](#10-summary-of-production-best-practices)

---

## 1. Executive Overview & Threat Landscape

### The Shift-Left Paradigm
Traditional cloud security operates reactively via runtime Cloud Security Posture Management (CSPM), alerting security operations teams *after* insecure infrastructure is deployed. 

**Infrastructure as Code (IaC) Security** shifts detection leftward directly into developer workflows (IDE, Git hooks, Pull Requests, CI/CD). By catching misconfigurations before `terraform apply`, organizations:
- **Prevent Zero-Day Misconfigurations**: Insecure cloud resources are never provisioned in AWS/Azure/GCP.
- **Drastically Lower Remediation Cost**: Fixing a line of Terraform in a Pull Request costs negligible time compared to migrating production data or investigating a breach.
- **Enforce Compliance as Code**: Ensure automated adherence to **CIS Benchmarks**, **NIST 800-53**, **SOC 2**, **HIPAA**, and **PCI-DSS**.

```
  +-------------+      +-------------------+      +------------------+      +--------------------+
  | Developer   | ---> | Pre-Commit Hook   | ---> | Pull Request /   | ---> | terraform apply    |
  | IDE Tooling |      | Checkov Static    |      | CI/CD SARIF Gate |      | Secure Deployment  |
  +-------------+      +-------------------+      +------------------+      +--------------------+
         ^                       ^                          ^                          |
         |                       |                          |                          v
         +-----------------------+--------------------------+----------------   Cloud Environment
                                 Shift-Left Security Boundary                    (Hardened Posture)
```

---

## 2. Checkov Architecture & Scanning Model

Checkov (developed by Bridgecrew / Palo Alto Networks) is an open-source static code analysis tool for Infrastructure as Code.

### Core Capabilities:
- **Graph-Based Evaluation**: Checkov builds an Abstract Syntax Tree (AST) and directed acyclic graph (DAG) of the entire Terraform module, allowing cross-resource evaluations (e.g., verifying if a Security Group attached to an EC2 instance allows ingress from `0.0.0.0/0`).
- **Multi-Framework Support**: Scans Terraform (HCL & JSON plans), CloudFormation, ARM Templates, Bicep, Helm charts, Kubernetes YAML, Dockerfiles, and OpenAPI.
- **Built-in Rule Engine**: Over 1,000+ out-of-the-box policies mapped directly to industry compliance standards.
- **Extensible Policy-as-Code**: Custom rules can be written declaratively in **YAML** or procedurally in **Python**.
- **Rich Output Formats**: CLI tables, JSON, JUnit XML, CycloneDX/SPDX SBOMs, and **SARIF** (for native GitHub Security integration).

---

## 3. Repository Structure

```tree
terraform-checkov-security-suite/
├── .checkov.yml                                 # Global production Checkov configuration
├── .pre-commit-config.yaml                      # Shift-left local git hook definitions
├── .github/workflows/
│   └── checkov-iac-scan.yml                     # GitHub Actions CI/CD workflow with SARIF reporting
├── .gitlab-ci.yml                               # GitLab CI/CD pipeline template
├── custom_policies/
│   ├── yaml/
│   │   ├── s3_mandatory_tagging.yaml            # Declarative tag enforcement rule
│   │   └── rds_backup_retention.yaml            # Automated backup SLA enforcement rule
│   └── python/
│       ├── IAMNoWildcardAdministratorAccess.py  # Python check for wildcard IAM policies
│       └── S3BucketCustomKMSRequired.py         # Python check for Customer-Managed KMS Keys
├── terraform/
│   ├── vulnerable/                              # Deliberately flawed Terraform manifests
│   │   ├── main.tf
│   │   ├── s3.tf
│   │   ├── security_groups.tf
│   │   ├── iam.tf
│   │   ├── rds.tf
│   │   └── outputs.tf
│   └── remediated/                              # Production-hardened Terraform manifests
│       ├── main.tf
│       ├── s3.tf
│       ├── security_groups.tf
│       ├── iam.tf
│       ├── rds.tf
│       └── outputs.tf
└── scripts/
    ├── run_scans.ps1                            # PowerShell execution helper
    └── run_scans.sh                             # Bash execution helper
```

---

## 4. Vulnerable vs. Hardened Manifest Breakdown

| Resource Area | Vulnerable Anti-Pattern (Found in `terraform/vulnerable/`) | Remediated Best Practice (Found in `terraform/remediated/`) | Checkov Rule ID |
| :--- | :--- | :--- | :--- |
| **S3 Storage** | Public ACL (`public-read`), unencrypted storage, disabled versioning, missing access logs. | Dedicated logging bucket, KMS SSE with Bucket Key, 4-tier Public Access Block, TLS 1.2+ enforce policy. | `CKV_AWS_18`, `CKV_AWS_21`, `CKV_AWS_53-56`, `CKV_AWS_145` |
| **Network Security** | Ingress `0.0.0.0/0` on Port 22 (SSH) & Port 3389 (RDP), missing descriptions. | Multi-tier security groups (ALB -> App -> RDS), HTTPS 443 only, strict internal SG referencing. | `CKV_AWS_24`, `CKV_AWS_25`, `CKV_AWS_260`, `CKV_AWS_277` |
| **IAM Security** | Blanket `Action: "*"` on `Resource: "*"`, wildcard principal trust, static long-lived API keys. | Granular least-privilege action/resource scoping, service-specific trust policies, GitHub Actions OIDC integration. | `CKV_AWS_1`, `CKV_AWS_60`, `CKV_AWS_62`, `CKV_AWS_273` |
| **RDS Database** | `publicly_accessible = true`, storage unencrypted, `backup_retention = 0`, hardcoded plaintext passwords. | Private DB Subnet Group, KMS encrypted, 14-day backup retention, dynamic password in Secrets Manager, IAM Auth enabled. | `CKV_AWS_16`, `CKV_AWS_17`, `CKV_AWS_118`, `CKV_AWS_133`, `CKV_AWS_161` |
| **Key Management** | Default shared AWS managed keys without customer rotation control. | Customer Managed Key (CMK) with annual automated key rotation (`enable_key_rotation = true`). | `CKV_AWS_7` |

---

## 5. Custom Policy Development (YAML & Python)

Checkov allows authoring proprietary security and governance rules tailored to organizational standards.

### A. Declarative YAML Policy Example (`custom_policies/yaml/s3_mandatory_tagging.yaml`)
YAML policies are ideal for attribute existence, regex checks, and simple logic combinations.

```yaml
metadata:
  name: "Ensure all S3 buckets have required organizational tags (Environment, Project)"
  id: "CUSTOM_AWS_001"
  category: "GENERAL_SECURITY"
  guideline: "All S3 buckets must be tagged with Environment (dev, stage, production) and Project name."
  severity: "MEDIUM"

scope:
  provider: "aws"

definition:
  and:
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.Environment"
      operator: "within"
      value:
        - "dev"
        - "stage"
        - "production"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.Project"
      operator: "exists"
```

### B. Procedural Python Policy Example (`custom_policies/python/IAMNoWildcardAdministratorAccess.py`)
Python policies provide complete AST parsing capability, ideal for complex logic, multi-statement JSON inspections, or relationship traversing.

```python
import json
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class IAMNoWildcardAdministratorAccess(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM policy documents do not allow wildcard administrator access"
        id = "CUSTOM_AWS_003"
        supported_resources = ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf.keys():
            try:
                policy_raw = conf["policy"][0]
                policy_doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str): actions = [actions]
                        if isinstance(resources, str): resources = [resources]
                        
                        if ("*" in actions or "*:*" in actions) and "*" in resources:
                            return CheckResult.FAILED
                return CheckResult.PASSED
            except Exception:
                return CheckResult.UNKNOWN
        return CheckResult.PASSED

check = IAMNoWildcardAdministratorAccess()
```

---

## 6. Managing Suppressions & Technical Debt

When a policy check is not applicable or an explicit business exemption is approved, Checkov supports granular inline annotations and external baseline files.

### 1. Inline HCL Suppression
Always document the reason directly in code:

```hcl
resource "aws_s3_bucket" "public_static_assets" {
  bucket = "company-public-marketing-assets"

  # checkov:skip=CKV_AWS_20:Public read ACL required for public CDN origin distribution
  # checkov:skip=CKV_AWS_53:Public access block purposefully disabled for public asset bucket
}
```

### 2. Baseline Configuration (`.checkov.baseline`)
For legacy codebases with hundreds of existing violations, capture a baseline snapshot so new scans only fail on *new* violations:

```bash
# Generate baseline file
checkov -d ./terraform --create-baseline

# Run subsequent scans against the baseline
checkov -d ./terraform --baseline .checkov.baseline
```

---

## 7. Shift-Left CI/CD Pipeline Integration

### GitHub Actions Workflow with SARIF Security Tab Integration
The included [checkov-iac-scan.yml](file:///d:/projects/terraform-checkov-security-suite/.github/workflows/checkov-iac-scan.yml) uploads scan results directly to GitHub Advanced Security:

```yaml
- name: Execute Checkov Security Scan
  run: |
    checkov \
      --directory ./terraform/remediated \
      --external-checks-dir ./custom_policies/yaml \
      --external-checks-dir ./custom_policies/python \
      --framework terraform \
      --output sarif \
      --output-file-path ./reports \
      --hard-fail-on HIGH

- name: Publish SARIF to GitHub Code Scanning Tab
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ./reports/results_sarif.sarif
    category: checkov-iac-scan
```

### Local Git Pre-Commit Hook
Run security checks before commits are finalized:
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

## 8. Hands-On CLI Execution & Testing Guide

### Prerequisites
Install Python 3.9+ and Checkov:
```bash
pip install checkov
```

### Step 1: Scan the Vulnerable Manifests
Observe how Checkov flags critical vulnerabilities (unencrypted storage, public S3, wildcard IAM):
```bash
checkov -d ./terraform/vulnerable --framework terraform
```

### Step 2: Scan with Custom Policies Included
```bash
checkov \
  -d ./terraform/vulnerable \
  --external-checks-dir ./custom_policies/yaml \
  --external-checks-dir ./custom_policies/python \
  --framework terraform
```

### Step 3: Scan the Remediated Hardened Manifests
Verify that the hardened infrastructure passes all security controls and custom rules:
```bash
checkov \
  -d ./terraform/remediated \
  --external-checks-dir ./custom_policies/yaml \
  --external-checks-dir ./custom_policies/python \
  --framework terraform
```

### Step 4: Run via Helper Scripts
- **PowerShell (Windows)**:
  ```powershell
  .\scripts\run_scans.ps1 -Target "all" -Severity "HIGH"
  ```
- **Bash (Linux / macOS)**:
  ```bash
  chmod +x ./scripts/run_scans.sh
  ./scripts/run_scans.sh all HIGH
  ```

---

## 9. Scanning Terraform Plans vs. Raw HCL

Scanning raw `.tf` files evaluates static definitions. However, scanning compiled **Terraform Execution Plans (`tfplan.json`)** evaluates dynamic variables, module outputs, and exact resolved states.

### Workflow for Plan Scanning:
```bash
cd ./terraform/remediated

# 1. Initialize terraform
terraform init

# 2. Generate execution plan
terraform plan -out=tfplan.binary

# 3. Convert plan to JSON
terraform show -json tfplan.binary > tfplan.json

# 4. Scan the plan with Checkov
checkov -f tfplan.json --framework terraform_plan
```

---

## 10. Summary of Production Best Practices

1. **Automate in CI/CD**: Treat security warnings as blocking gates on pull requests for `HIGH` and `CRITICAL` findings.
2. **Standardize Custom Policies**: Enforce organizational naming conventions, backup retention, and tagging at build time.
3. **Use Scoped Suppressions**: Never globally disable rules in `.checkov.yml`; enforce inline comments with explicit business justification.
4. **Scan Both Plan and Code**: Scan raw HCL on pull requests for fast feedback, and scan `tfplan.json` prior to deployment for exact variable resolution.
5. **Continuous Baseline Maintenance**: Periodically burn down baseline debt on legacy modules.
