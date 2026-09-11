from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class S3BucketCustomKMSRequired(BaseResourceCheck):
    """
    Custom Checkov Python Policy:
    Ensures S3 bucket server side encryption configuration specifies a Customer Managed KMS Key
    rather than default aws/s3 or missing key.
    """
    def __init__(self):
        name = "Ensure S3 server side encryption uses Customer Managed Key (CMK) ARN"
        id = "CUSTOM_AWS_004"
        supported_resources = ["aws_s3_bucket_server_side_encryption_configuration"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        rules = conf.get("rule", [])
        if not rules:
            return CheckResult.FAILED

        if isinstance(rules, dict):
            rules = [rules]

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            apply_sse = rule.get("apply_server_side_encryption_by_default", [])
            if not apply_sse:
                return CheckResult.FAILED

            sse_config = apply_sse[0] if isinstance(apply_sse, list) and apply_sse else apply_sse
            if not isinstance(sse_config, dict):
                return CheckResult.FAILED

            sse_algo_val = sse_config.get("sse_algorithm", [""])
            sse_algorithm = sse_algo_val[0] if isinstance(sse_algo_val, list) and sse_algo_val else (sse_algo_val if isinstance(sse_algo_val, str) else "")

            kms_key_val = sse_config.get("kms_master_key_id", [""])
            kms_key = kms_key_val[0] if isinstance(kms_key_val, list) and kms_key_val else (kms_key_val if isinstance(kms_key_val, str) else "")

            if sse_algorithm == "aws:kms" and kms_key:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED

        return CheckResult.PASSED


check = S3BucketCustomKMSRequired()
