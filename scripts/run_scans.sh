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
    RUNNER=(checkov)
elif command -v python3 &> /dev/null; then
    RUNNER=(python3 -c "import sys; from checkov.main import Checkov; sys.argv=['checkov'] + sys.argv[1:]; sys.exit(Checkov().run())")
elif command -v python &> /dev/null; then
    RUNNER=(python -c "import sys; from checkov.main import Checkov; sys.argv=['checkov'] + sys.argv[1:]; sys.exit(Checkov().run())")
else
    echo "Checkov or Python was not found in PATH."
    echo "Please install it: pip install checkov"
    exit 1
fi

mkdir -p ./reports

if [ "$TARGET" = "all" ]; then
    TARGETS=("vulnerable" "remediated")
else
    TARGETS=("$TARGET")
fi

OVERALL_EXIT=0

for t in "${TARGETS[@]}"; do
    echo ""
    echo ">>> Scanning target suite: ./terraform/$t (Framework: $FRAMEWORK)"
    set +e
    "${RUNNER[@]}" \
        -d "./terraform/$t" \
        --external-checks-dir ./custom_policies/yaml \
        --external-checks-dir ./custom_policies/python \
        --framework "$FRAMEWORK" \
        --output cli \
        --output json \
        --output sarif \
        --output-file-path "./reports" \
        --hard-fail-on "$SEVERITY"
    SCAN_EXIT=$?
    set -e

    if [ -f "./reports/results_json.json" ]; then
        cp "./reports/results_json.json" "./reports/scan_${t}_results_json.json" 2>/dev/null || true
    fi

    if [ $SCAN_EXIT -eq 0 ]; then
        echo -e "\n[PASSED] Target '$t' passed security policy checks with 0 critical/high violations."
    else
        echo -e "\n[VIOLATIONS DETECTED] Target '$t' identified policy violations (Exit code: $SCAN_EXIT)."
        OVERALL_EXIT=$SCAN_EXIT
    fi
done

echo ""
echo "Security scans completed. Reports written to ./reports/"

if [ $OVERALL_EXIT -ne 0 ]; then
    echo -e "\n[SECURITY GATE FAILED] Halting execution due to detected policy violations."
    exit $OVERALL_EXIT
fi
