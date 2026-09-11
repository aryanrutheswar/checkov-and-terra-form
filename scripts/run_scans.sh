#!/usr/bin/env bash
# ==============================================================================
# Checkov Security Scan Runner (Bash)
# Usage:
#   ./scripts/run_scans.sh vulnerable
#   ./scripts/run_scans.sh remediated HIGH terraform
# ==============================================================================

set -eo pipefail

TARGET=${1:-"remediated"}
SEVERITY=${2:-"HIGH"}
FRAMEWORK=${3:-"terraform"}

echo "=========================================================="
echo "  IaC Security Scanner: Checkov Multi-Framework Suite"
echo "=========================================================="

if command -v checkov &> /dev/null; then
    RUNNER="checkov"
elif command -v python3 &> /dev/null; then
    RUNNER="python3 -m checkov.main"
elif command -v python &> /dev/null; then
    RUNNER="python -m checkov.main"
else
    echo "Checkov is not installed or not in PATH."
    echo "Please install it: pip install checkov"
    exit 1
fi

mkdir -p ./reports

if [ "$TARGET" = "all" ]; then
    TARGETS=("vulnerable" "remediated")
else
    TARGETS=("$TARGET")
fi

for t in "${TARGETS[@]}"; do
    echo ""
    echo ">>> Scanning target suite: ./terraform/$t (Framework: $FRAMEWORK)"
    $RUNNER \
        -d "./terraform/$t" \
        --external-checks-dir ./custom_policies/yaml \
        --external-checks-dir ./custom_policies/python \
        --framework "$FRAMEWORK" \
        --output cli \
        --output json \
        --output sarif \
        --output-file-path "./reports/scan_$t" \
        --hard-fail-on "$SEVERITY" || true
done

echo ""
echo "Security scans completed. Reports written to ./reports/"

