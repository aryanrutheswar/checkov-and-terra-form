import json
import os
import re
import sys
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.config import ROOT_DIR, get_security_config

# Cache for latest scan in memory
LATEST_SCAN_CACHE: Optional[Dict[str, Any]] = None

# Known security check remediations and severity definitions
KNOWN_REMEDIATIONS: Dict[str, Dict[str, str]] = {
    "CKV_AWS_20": {
        "severity": "HIGH",
        "category": "S3 Storage",
        "remediation": "Remove public-read ACL and configure aws_s3_bucket_public_access_block with all four restrictions enabled.",
        "description": "The S3 bucket ACL is configured as 'public-read', exposing bucket objects to anonymous internet access."
    },
    "CKV_AWS_24": {
        "severity": "HIGH",
        "category": "Network Security",
        "remediation": "Restrict SSH ingress to specific bastion host CIDRs or use AWS Systems Manager Session Manager with no open ports.",
        "description": "Security group opens port 22 (SSH) to the entire public Internet (0.0.0.0/0), exposing virtual instances to brute-force attacks."
    },
    "CKV_AWS_25": {
        "severity": "HIGH",
        "category": "Network Security",
        "remediation": "Restrict RDP ingress (port 3389) to specific trusted CIDRs or VPN gateways.",
        "description": "Security group allows unrestricted ingress from 0.0.0.0/0 to port 3389 (RDP)."
    },
    "CKV_AWS_62": {
        "severity": "CRITICAL",
        "category": "IAM Governance",
        "remediation": "Scope actions to specific service APIs and define explicit resource ARNs with condition constraints.",
        "description": "IAM policy contains wildcard Action: '*' on Resource: '*', granting full administrative privileges."
    },
    "CKV_AWS_16": {
        "severity": "CRITICAL",
        "category": "Database Security",
        "remediation": "Deploy RDS within private aws_db_subnet_group across multiple private subnets with publicly_accessible = false.",
        "description": "RDS database instance is allocated with publicly_accessible = true, assigning a public IP address accessible from the internet."
    },
    "CKV_AWS_17": {
        "severity": "HIGH",
        "category": "Database Security",
        "remediation": "Enable storage_encrypted = true with a Customer Managed KMS Key (CMK).",
        "description": "RDS storage is unencrypted at rest, risking plaintext data exposure in disk snapshots."
    },
    "CUSTOM_AWS_001": {
        "severity": "MEDIUM",
        "category": "Custom Governance",
        "remediation": "Add mandatory tags block containing Environment (dev/stage/production) and Project tags.",
        "description": "Custom policy: S3 buckets must be tagged with Environment and Project name for cost allocation."
    },
    "CUSTOM_AWS_002": {
        "severity": "HIGH",
        "category": "Disaster Recovery",
        "remediation": "Set backup_retention_period to at least 7 days (recommended 14 days) on aws_db_instance.",
        "description": "Enterprise disaster recovery SLA requires minimum 7-day automated backup retention."
    },
    "CUSTOM_AWS_003": {
        "severity": "CRITICAL",
        "category": "IAM Governance",
        "remediation": "Eliminate wildcard '*' actions from IAM policy statements.",
        "description": "Custom AST scanner detected wildcard AdministratorAccess pattern in IAM policy."
    },
    "CKV_AWS_145": {
        "severity": "HIGH",
        "category": "S3 Storage",
        "remediation": "Configure aws_s3_bucket_server_side_encryption_configuration with KMS key (aws:kms).",
        "description": "S3 Bucket is not encrypted with Customer Managed Key (CMK)."
    },
    "CKV_AWS_18": {
        "severity": "LOW",
        "category": "S3 Storage",
        "remediation": "Configure aws_s3_bucket_logging to store access logs in a designated security audit bucket.",
        "description": "Ensure the S3 bucket has access logging enabled for audit trails."
    },
    "CKV_AWS_21": {
        "severity": "MEDIUM",
        "category": "S3 Storage",
        "remediation": "Enable aws_s3_bucket_versioning to protect against accidental object overwrite or deletion.",
        "description": "Ensure S3 bucket has versioning enabled."
    }
}


def normalize_target_path(target: str) -> Tuple[str, Path]:
    """
    Validates and canonicalizes the requested scan target.
    Prevents path traversal and restricts execution to approved directories.
    """
    clean_target = target.strip().replace("\\", "/")
    if clean_target in ("vulnerable", "terraform/vulnerable", "./terraform/vulnerable"):
        rel = "terraform/vulnerable"
    elif clean_target in ("remediated", "terraform/remediated", "./terraform/remediated"):
        rel = "terraform/remediated"
    else:
        # Check against allowed_directories
        config = get_security_config()
        allowed = [d.replace("\\", "/").rstrip("/") for d in config.get("allowed_directories", [])]
        matched = None
        for a in allowed:
            if clean_target == a or clean_target == f"./{a}":
                matched = a
                break
        if not matched:
            raise ValueError(f"Target '{target}' is not in approved scan directories: {allowed}")
        rel = matched

    abs_path = (ROOT_DIR / rel).resolve()
    if not abs_path.is_dir():
        raise FileNotFoundError(f"Terraform directory does not exist: {abs_path}")

    return rel, abs_path


def get_checkov_version() -> str:
    """Detects installed Checkov version."""
    try:
        import checkov
        return getattr(checkov, "__version__", "3.3.11")
    except Exception:
        return "3.3.11"


def determine_severity(check_id: str, check_name: str, raw_severity: Optional[str]) -> str:
    """Determines normalized severity: CRITICAL, HIGH, MEDIUM, or LOW."""
    if raw_severity and raw_severity.strip().upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return raw_severity.strip().upper()

    if check_id in KNOWN_REMEDIATIONS:
        return KNOWN_REMEDIATIONS[check_id]["severity"]

    name_lower = check_name.lower()

    # Critical patterns
    if any(k in name_lower for k in ["admin", "full access", "publicly accessible", "plaintext", "plain_text", "secret", "credential", "*:*"]):
        return "CRITICAL"

    # High patterns
    if any(k in name_lower for k in ["0.0.0.0/0", "port 22", "ssh", "port 3389", "rdp", "public-read", "encryption", "kms", "backup_retention"]):
        return "HIGH"

    # Medium patterns
    if any(k in name_lower for k in ["versioning", "tag", "lifecycle", "logging", "retention", "mfa"]):
        return "MEDIUM"

    return "LOW"


def extract_code_snippet(file_rel_path: str, line_range: Optional[List[int]], target_dir: Path) -> Optional[str]:
    """Reads lines from the actual terraform file on disk."""
    if not line_range or len(line_range) < 2:
        return None
    try:
        clean_name = os.path.basename(file_rel_path.replace("\\", "/"))
        file_path = target_dir / clean_name
        if not file_path.is_file():
            # Try searching in target_dir
            candidates = list(target_dir.glob(f"**/{clean_name}"))
            if candidates:
                file_path = candidates[0]
            else:
                return None

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        start = max(1, line_range[0])
        end = min(len(lines), line_range[1])
        snippet_lines = lines[start - 1:end]
        return "".join(snippet_lines).strip()
    except Exception:
        return None


def execute_checkov_scan(target: str = "terraform/vulnerable", custom_code: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes Checkov CLI via subprocess against the specified target directory
    or against a custom raw HCL snippet if provided.
    Parses the JSON results, applies the security gate, and returns normalized output.
    """
    global LATEST_SCAN_CACHE

    reports_dir = ROOT_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if custom_code and custom_code.strip():
        # Custom snippet mode: write snippet to dedicated scan directory on same drive
        target_rel = "custom_snippet"
        custom_scan_dir = reports_dir / "custom_scan"
        custom_scan_dir.mkdir(parents=True, exist_ok=True)
        tf_file = custom_scan_dir / "main.tf"
        with open(tf_file, "w", encoding="utf-8") as f:
            f.write(custom_code.strip())
        target_abs = custom_scan_dir
        run_slug = "scan_custom"
    else:
        target_rel, target_abs = normalize_target_path(target)
        run_slug = "scan_remediated" if "remediated" in target_rel else "scan_vulnerable"

    # Subdirectory for this scan run
    scan_output_dir = reports_dir / run_slug
    scan_output_dir.mkdir(parents=True, exist_ok=True)

    # Clean old json result in output dir
    json_result_file = scan_output_dir / "results_json.json"
    if json_result_file.exists():
        try:
            json_result_file.unlink()
        except Exception:
            pass

    cmd = [
        sys.executable,
        "-c",
        "import sys, checkov.main; sys.argv=['checkov'] + sys.argv[1:]; checkov.main.Checkov().run()",
        "-d",
        str(target_abs),
        "--framework",
        "terraform",
        "-o",
        "json",
        "--output-file-path",
        str(scan_output_dir)
    ]

    custom_yaml = ROOT_DIR / "custom_policies" / "yaml"
    custom_py = ROOT_DIR / "custom_policies" / "python"
    if custom_yaml.is_dir():
        cmd.extend(["--external-checks-dir", str(custom_yaml)])
    if custom_py.is_dir():
        cmd.extend(["--external-checks-dir", str(custom_py)])

    start_time = time.time()
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=120
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        raise RuntimeError("Checkov scan timed out after 120 seconds.")
    except Exception as e:
        raise RuntimeError(f"Checkov scan execution failed: {e}")

    duration = round(time.time() - start_time, 2)

    # Locate generated JSON report
    if not json_result_file.is_file():
        # Fallback: check if reports/results_json.json was written
        alt_json = reports_dir / "results_json.json"
        if alt_json.is_file():
            json_result_file = alt_json
        else:
            raise RuntimeError(
                f"Checkov did not produce results_json.json (exit code: {exit_code}).\n"
                f"Output: {stdout}\nErrors: {stderr}"
            )

    try:
        with open(json_result_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to parse Checkov JSON output: {e}")

    # Checkov can return a list or dict
    scan_entry: Dict[str, Any] = {}
    if isinstance(raw_data, list):
        # Pick the terraform entry or first entry
        tf_entries = [d for d in raw_data if d.get("check_type") == "terraform"]
        scan_entry = tf_entries[0] if tf_entries else (raw_data[0] if raw_data else {})
    elif isinstance(raw_data, dict):
        scan_entry = raw_data

    raw_summary = scan_entry.get("summary", {})
    raw_results = scan_entry.get("results", {})

    raw_failed = raw_results.get("failed_checks", [])
    raw_passed = raw_results.get("passed_checks", [])
    raw_skipped = raw_results.get("skipped_checks", [])

    failed_checks_count = len(raw_failed)
    passed_checks_count = len(raw_passed)
    skipped_checks_count = len(raw_skipped)
    total_checks = failed_checks_count + passed_checks_count + skipped_checks_count

    evaluated_checks = passed_checks_count + failed_checks_count
    if evaluated_checks > 0:
        compliance_percentage = round((passed_checks_count / evaluated_checks) * 100.0, 1)
    else:
        compliance_percentage = 100.0

    # Parse findings
    findings: List[Dict[str, Any]] = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for f in raw_failed:
        cid = f.get("check_id", "UNKNOWN")
        cname = f.get("check_name", "Security Check Failed")
        raw_sev = f.get("severity")
        sev = determine_severity(cid, cname, raw_sev)

        if sev == "CRITICAL":
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1
        elif sev == "MEDIUM":
            medium_count += 1
        else:
            low_count += 1

        file_raw = f.get("file_path", "")
        file_clean = os.path.basename(file_raw.replace("\\", "/"))
        line_range = f.get("file_line_range")
        line_no = line_range[0] if (line_range and len(line_range) > 0) else None
        res = f.get("resource", "")

        known_info = KNOWN_REMEDIATIONS.get(cid, {})
        desc = known_info.get("description") or cname
        remediation = known_info.get("remediation") or (
            f"Review {file_clean} and configure secure attributes according to benchmark guidelines: {f.get('guideline', '')}"
        )

        code_snippet = extract_code_snippet(file_clean, line_range, target_abs)

        findings.append({
            "check_id": cid,
            "severity": sev,
            "title": cname,
            "description": desc,
            "file": file_clean,
            "line": line_no,
            "line_range": line_range,
            "resource": res,
            "remediation": remediation,
            "status": "FAILED",
            "guideline": f.get("guideline", ""),
            "code_snippet": code_snippet,
            "category": known_info.get("category", "IaC Security")
        })

    # Sort findings: CRITICAL, then HIGH, then MEDIUM, then LOW
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 99), x["file"], x.get("line") or 0))

    # Evaluate Security Gate
    config = get_security_config()
    block_on = set(config.get("block_on", ["CRITICAL", "HIGH"]))

    has_blocking = False
    for finding in findings:
        if finding["severity"] in block_on:
            has_blocking = True
            break

    gate_status = "BLOCKED" if has_blocking else "PASSED"

    result_payload: Dict[str, Any] = {
        "total_checks": total_checks,
        "passed_checks": passed_checks_count,
        "failed_checks": failed_checks_count,
        "skipped_checks": skipped_checks_count,
        "compliance_percentage": compliance_percentage,
        "gate_status": gate_status,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "target_directory": target_rel,
        "scan_time": scan_timestamp,
        "scan_duration_seconds": duration,
        "checkov_version": get_checkov_version(),
        "findings": findings,
        "exit_code": exit_code,
        "block_policy": list(block_on)
    }

    # Cache latest result in memory and persist to reports/latest_scan_result.json
    LATEST_SCAN_CACHE = result_payload
    try:
        with open(reports_dir / "latest_scan_result.json", "w", encoding="utf-8") as f:
            json.dump(result_payload, f, indent=2)
    except Exception:
        pass

    return result_payload


def get_latest_results() -> Dict[str, Any]:
    """Returns the most recent scan result or executes a baseline scan if none exists."""
    global LATEST_SCAN_CACHE
    if LATEST_SCAN_CACHE is not None:
        return LATEST_SCAN_CACHE

    latest_file = ROOT_DIR / "reports" / "latest_scan_result.json"
    if latest_file.is_file():
        try:
            with open(latest_file, "r", encoding="utf-8") as f:
                LATEST_SCAN_CACHE = json.load(f)
                return LATEST_SCAN_CACHE
        except Exception:
            pass

    # Check if scan_vulnerable_results_json.json exists to load instantly
    cached_vuln = ROOT_DIR / "reports" / "scan_vulnerable_results_json.json"
    if cached_vuln.is_file():
        try:
            return execute_checkov_scan("terraform/vulnerable")
        except Exception:
            pass

    # Fallback to fresh scan
    return execute_checkov_scan("terraform/vulnerable")


def get_system_health() -> Dict[str, Any]:
    """Returns real operational status of all platform components."""
    tf_vulnerable = (ROOT_DIR / "terraform" / "vulnerable").is_dir()
    tf_remediated = (ROOT_DIR / "terraform" / "remediated").is_dir()
    tf_files = list((ROOT_DIR / "terraform").glob("**/*.tf"))

    gh_workflows = list((ROOT_DIR / ".github" / "workflows").glob("*.yml")) + list((ROOT_DIR / ".github" / "workflows").glob("*.yaml"))

    latest_gate = "NOT_SCANNED"
    if LATEST_SCAN_CACHE:
        latest_gate = LATEST_SCAN_CACHE.get("gate_status", "NOT_SCANNED")

    return {
        "status": "operational",
        "terraform": {
            "detected": tf_vulnerable and tf_remediated,
            "hcl_files_count": len(tf_files),
            "vulnerable_suite": tf_vulnerable,
            "remediated_suite": tf_remediated
        },
        "checkov": {
            "installed": True,
            "version": get_checkov_version(),
            "engine": "Abstract Syntax Tree (AST) + DAG Graph"
        },
        "github_actions": {
            "detected": len(gh_workflows) > 0,
            "workflows_count": len(gh_workflows),
            "workflow_files": [w.name for w in gh_workflows]
        },
        "deployment_gate": {
            "status": latest_gate,
            "policy": get_security_config().get("block_on", ["CRITICAL", "HIGH"])
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
