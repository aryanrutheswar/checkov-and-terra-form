# 🎓 College Presentation & Viva Defense Guide
## Terraform + Checkov IaC Security Suite

---

## 📌 1. Project Overview & Elevator Pitch

> *"This project builds an automated **DevSecOps Infrastructure-as-Code (IaC) security gate** using **Terraform**, **Checkov**, and **GitHub Actions**. By embedding static analysis directly into CI/CD pipelines, we shift security leftward—preventing cloud misconfigurations (such as public S3 buckets, exposed SSH ports, and wildcard IAM privileges) before any infrastructure can ever be provisioned in the cloud."*

---

## 🏗️ 2. Core Architecture & Workflow

```text
               DEVELOPER WORKSPACE
                        │
                        ▼ (git commit / git push)
              GITHUB REPOSITORY (PR / Main)
                        │
                        ▼ (triggers workflow)
            GITHUB ACTIONS CI/CD PIPELINE
                        │
       ┌────────────────┴────────────────┐
       │ STAGE 1: Checkov Security Gate  │
       │ (Static Analysis & AST Graph)   │
       └────────────────┬────────────────┘
                        │
               Does IaC meet policy?
              /                       \
        [ VIOLATIONS ]              [ ZERO VIOLATIONS ]
             /                             \
            ▼                               ▼
 🛑 PIPELINE HALTED             ✅ SECURITY GATE PASSED
 • Exit code: 1                 • Exit code: 0
 • SARIF uploaded to Security   • Step summary posted
 • Downstream jobs SKIPPED      • Stage 2 UNLOCKED
 • Deployment BLOCKED                       │
                                            ▼
                                ┌───────────────────────────────┐
                                │ STAGE 2: Terraform Validation │
                                │  • terraform fmt -check       │
                                │  • terraform init             │
                                │  • terraform validate         │
                                │  • terraform plan             │
                                └───────────────┬───────────────┘
                                                │
                                                ▼
                                    🚀 APPROVED FOR DEPLOYMENT
```

---

## ⚡ 3. The 2-Minute Live Demo Script

Use this exact sequence during your live presentation or viva demonstration:

### Step 1: Explain the Concept (15 seconds)
> *"Traditional security alerts teams after infrastructure is deployed into AWS. In this project, we implement Shift-Left security: the CI/CD pipeline acts as an automated gatekeeper. If Terraform manifests violate security benchmarks, the pipeline fails and blocks deployment."*

### Step 2: Demonstrate the Security Gate Blocking Insecure Code (45 seconds)
Run in PowerShell:
```powershell
.\scripts\run_scans.ps1 -Target "vulnerable"
```
*(Or run the all-in-one walkthrough: `powershell -ExecutionPolicy Bypass -File .\scripts\demo_walkthrough.ps1`)*

**What to point out on screen:**
1. Checkov flags **39 policy violations** (Red text).
2. Point out specific flaws:
   - S3 bucket has `acl = "public-read"` (`CKV_AWS_20`).
   - Security group opens Port 22 (SSH) to `0.0.0.0/0` (`CKV_AWS_24`).
   - IAM role grants wildcard `*` administrator rights (`CKV_AWS_1`, `CKV_AWS_62`).
   - RDS database has hardcoded password and `publicly_accessible = true` (`CKV_AWS_16`, `CKV_AWS_17`).
3. Point to the terminal exit line:
   ```text
   [VIOLATIONS DETECTED] Target 'vulnerable' identified policy violations (Exit code: 1).
   [SECURITY GATE FAILED] Halting pipeline execution due to high/critical violations.
   ```
4. Emphasize: *"Notice exit code 1. In GitHub Actions, this halts the pipeline immediately and stops `terraform plan` from executing."*

### Step 3: Demonstrate Remediated Architecture Unlocking Deployment (45 seconds)
Run in PowerShell:
```powershell
.\scripts\run_scans.ps1 -Target "remediated"
```

**What to point out on screen:**
1. Checkov evaluates all 112 checks.
2. Result shows: **0 failed checks!**
   ```text
   [PASSED] Target 'remediated' passed security policy checks with 0 critical/high violations.
   ```
3. Exit code is **0**.
4. Emphasize: *"Because Checkov passed with 0 violations, GitHub Actions unlocks Stage 2: executing `terraform fmt`, `terraform init`, `terraform validate`, and generating the speculative execution plan."*

### Step 4: Show GitHub Actions Security Tab & Dashboard (15 seconds)
1. Show `.github/workflows/checkov-iac-scan.yml`: Highlight `needs: [security-gate]`.
2. Show the web dashboard: Displays visual pass/fail scorecards and interactive blast radius graph.

---

## 📊 4. Insecure Anti-Patterns vs. Remediated Best Practices

| Resource | Insecure Anti-Pattern (`terraform/vulnerable/`) | Remediated Best Practice (`terraform/remediated/`) | Checkov Rule ID |
| :--- | :--- | :--- | :--- |
| **S3 Storage** | `acl = "public-read"`, unencrypted, versioning disabled. | Customer KMS key encryption, 4-tier Public Access Block, access logging. | `CKV_AWS_18`, `CKV_AWS_21`, `CKV_AWS_53-56` |
| **Security Groups** | Port 22 (SSH) and Port 3389 (RDP) open to `0.0.0.0/0`. | Multi-tier security groups, HTTPS 443 only, strict internal SG referencing. | `CKV_AWS_24`, `CKV_AWS_25`, `CKV_AWS_260` |
| **IAM Security** | Blanket `Action: "*"` on `Resource: "*"`, wildcard principal trust. | Granular least-privilege scoping, condition keys, service-specific trust policies. | `CKV_AWS_1`, `CKV_AWS_60`, `CKV_AWS_62` |
| **RDS Database** | `publicly_accessible = true`, unencrypted storage, 0 backup retention. | Private DB subnet group, KMS encryption, 14-day backup retention, IAM Auth enabled. | `CKV_AWS_16`, `CKV_AWS_17`, `CKV_AWS_118` |
| **Custom Rules** | Missing tags, backup retention under 7 days. | Custom YAML & Python rules enforce enterprise governance. | `CUSTOM_AWS_001`, `CUSTOM_AWS_002` |

---

## 🎯 5. Top 10 Viva / Presentation Questions & Answers

### Q1: What is Infrastructure-as-Code (IaC) Security?
> **Answer:** IaC Security is the practice of scanning declarative code templates (like Terraform HCL) for misconfigurations, security vulnerabilities, and compliance violations *before* resources are provisioned in live cloud environments.

### Q2: How does Checkov evaluate Terraform files without deploying them to AWS?
> **Answer:** Checkov uses an **Abstract Syntax Tree (AST)** and builds a directed acyclic graph (DAG) of all Terraform blocks. It statically analyzes relationships between resources—for example, tracing whether a security group attached to an EC2 instance permits unrestricted ingress.

### Q3: Why is static analysis better than runtime cloud security (CSPM)?
> **Answer:** Runtime CSPM detects vulnerabilities *after* exposure (e.g. data breach or internet exposure). Static analysis shifts security leftward, stopping flaws at the pull request stage where remediation takes seconds and costs zero incident-response budget.

### Q4: How does the CI/CD Security Gate work in GitHub Actions?
> **Answer:** The workflow has two jobs:
> 1. `security-gate`: Runs Checkov with `--hard-fail-on HIGH`. If any High or Critical check fails, it exits with code 1.
> 2. `terraform-validate-and-plan`: Has `needs: [security-gate]`. Because of this explicit dependency, GitHub Actions automatically halts and skips this job whenever Stage 1 fails.

### Q5: What is SARIF and why do we export it?
> **Answer:** SARIF stands for **Static Analysis Results Interchange Format** (an OASIS JSON standard). When Checkov exports SARIF, the `github/codeql-action/upload-sarif` action integrates scan results directly into the **GitHub Security -> Code Scanning Alerts** dashboard with clickable code annotations.

### Q6: What is the difference between soft-fail and hard-fail?
> **Answer:** 
> - `--soft-fail`: Checkov reports violations for auditing, but always returns exit code 0 so the build never stops.
> - `--hard-fail-on HIGH`: Checkov returns exit code 1 if any violation is High or Critical severity, deliberately failing the CI/CD job to block deployment.

### Q7: What if an engineer has a valid reason to bypass a check? How are exceptions handled?
> **Answer:** Checkov supports inline suppressions using HCL comments (e.g., `#checkov:skip=CKV_AWS_18: "Access logs bucket does not need self-logging"`). Suppressions must include a mandatory rationale and can be tracked in audit logs.

### Q8: Can organizations write their own custom security rules in Checkov?
> **Answer:** Yes. Checkov supports two custom policy types:
> - **YAML policies** for simple declarative checks (e.g., ensuring mandatory tags like `Environment` and `Project`).
> - **Python policies** for complex multi-resource graph queries (e.g., parsing IAM JSON policies for wildcard permissions). Both are included in our `custom_policies/` directory.

### Q9: Does running `terraform validate` and `terraform plan` in this project cost cloud money?
> **Answer:** No. We configured AWS provider bypass settings (`skip_credentials_validation = true`, `skip_requesting_account_id = true`, `skip_metadata_api_check = true`) along with mock environment variables. The validation and planning execute 100% offline at zero cloud cost.

### Q10: How does this project scale to enterprise production?
> **Answer:** In production:
> 1. Pre-commit hooks run Checkov locally on developer laptops.
> 2. Branch protection rules prevent merging PRs unless the Checkov security gate passes.
> 3. Verified plans are automatically applied through pipeline OIDC role assumption without long-lived static AWS keys.
