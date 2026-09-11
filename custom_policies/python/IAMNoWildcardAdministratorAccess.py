import ast
import json
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class IAMNoWildcardAdministratorAccess(BaseResourceCheck):
    """
    Custom Checkov Python Policy:
    Ensures IAM Policies do not grant wildcard Action ('*') across all Resources ('*').
    """
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
                policy_doc = None

                if isinstance(policy_raw, dict):
                    policy_doc = policy_raw
                elif isinstance(policy_raw, str):
                    clean_str = policy_raw.strip()
                    if clean_str.startswith("${jsonencode(") and clean_str.endswith(")}"):
                        clean_str = clean_str[clean_str.find("(") + 1 : clean_str.rfind(")")].strip()
                    elif clean_str.startswith("jsonencode(") and clean_str.endswith(")"):
                        clean_str = clean_str[clean_str.find("(") + 1 : clean_str.rfind(")")].strip()

                    try:
                        policy_doc = json.loads(clean_str)
                    except Exception:
                        try:
                            policy_doc = ast.literal_eval(clean_str)
                        except Exception:
                            policy_doc = None

                if not isinstance(policy_doc, dict):
                    return CheckResult.PASSED

                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                elif not isinstance(statements, list):
                    return CheckResult.PASSED

                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue

                    effect = stmt.get("Effect", "")
                    if isinstance(effect, list):
                        effect = effect[0] if effect else ""

                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    elif isinstance(actions, list):
                        actions = [a[0] if isinstance(a, list) else a for a in actions]

                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    elif isinstance(resources, list):
                        resources = [r[0] if isinstance(r, list) else r for r in resources]

                    if effect == "Allow":
                        if ("*" in actions or "*:*" in actions) and "*" in resources:
                            return CheckResult.FAILED

                return CheckResult.PASSED
            except Exception:
                return CheckResult.UNKNOWN
        return CheckResult.PASSED


check = IAMNoWildcardAdministratorAccess()
