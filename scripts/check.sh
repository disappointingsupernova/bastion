#!/usr/bin/env bash
# scripts/check.sh — Full local quality gate: mirrors CI exactly.
#
# Runs in order:
#   1. ruff lint
#   2. ruff format check
#   3. mypy type check
#   4. bandit security scan
#   5. pytest (verbose, with coverage)
#
# Exits non-zero if any step fails.
# Usage: bash scripts/check.sh [--fast]
#   --fast  skips bandit and coverage report (useful during rapid iteration)

set -euo pipefail

FAST=false
for arg in "$@"; do
    [[ "$arg" == "--fast" ]] && FAST=true
done

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

header()  { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════${RESET}"; \
            echo -e "${CYAN}${BOLD}  $1${RESET}"; \
            echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"; }
pass()    { echo -e "${GREEN}${BOLD}  ✓ $1${RESET}"; }
fail()    { echo -e "${RED}${BOLD}  ✗ $1${RESET}"; }
info()    { echo -e "${YELLOW}  → $1${RESET}"; }

# ── Result tracking ───────────────────────────────────────────────────────────
declare -A RESULTS
FAILED=0

run_step() {
    local name="$1"
    shift
    header "$name"
    if "$@"; then
        RESULTS["$name"]="PASS"
        pass "$name passed"
    else
        RESULTS["$name"]="FAIL"
        fail "$name FAILED"
        FAILED=1
    fi
}

# ── Environment check ─────────────────────────────────────────────────────────
header "Environment"
info "Python: $(python --version 2>&1)"
info "Working directory: $(pwd)"

# Ensure required env vars are set for tests
export SECRET_KEY="${SECRET_KEY:-test-secret-key-not-for-production-use-only-32chars}"
export DB_URL="${DB_URL:-sqlite+aiosqlite:///./test.db}"
export ENVIRONMENT="${ENVIRONMENT:-development}"
info "SECRET_KEY: [set]"
info "DB_URL: $DB_URL"
info "ENVIRONMENT: $ENVIRONMENT"

# ── 1. Ruff lint ──────────────────────────────────────────────────────────────
run_step "Ruff lint" \
    ruff check . --output-format=full

# ── 2. Ruff format check ──────────────────────────────────────────────────────
run_step "Ruff format" \
    ruff format --check .

# ── 3. mypy type check ────────────────────────────────────────────────────────
run_step "mypy" \
    mypy bastion bastion_api bastion_admin cli workers \
        --ignore-missing-imports \
        --no-error-summary

# ── 4. Bandit security scan ───────────────────────────────────────────────────
if [[ "$FAST" == "false" ]]; then
    run_step "Bandit" \
        bandit -r bastion bastion_api bastion_admin cli workers \
            -c pyproject.toml \
            --severity-level medium \
            --confidence-level medium \
            -q
else
    info "Bandit skipped (--fast)"
    RESULTS["Bandit"]="SKIP"
fi

# ── 5. pytest ─────────────────────────────────────────────────────────────────
if [[ "$FAST" == "false" ]]; then
    PYTEST_ARGS=(
        tests/
        --verbose
        --tb=short
        --cov=bastion
        --cov=bastion_api
        --cov=bastion_admin
        --cov-report=term-missing
        --cov-report=html:htmlcov
        --cov-fail-under=0
        -p no:warnings
    )
else
    PYTEST_ARGS=(
        tests/
        --verbose
        --tb=short
        -p no:warnings
    )
fi

run_step "pytest" \
    pytest "${PYTEST_ARGS[@]}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Quality Gate Summary${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"

for step in "Ruff lint" "Ruff format" "mypy" "Bandit" "pytest"; do
    result="${RESULTS[$step]:-SKIP}"
    if [[ "$result" == "PASS" ]]; then
        echo -e "  ${GREEN}✓${RESET} $step"
    elif [[ "$result" == "FAIL" ]]; then
        echo -e "  ${RED}✗${RESET} $step"
    else
        echo -e "  ${YELLOW}–${RESET} $step (skipped)"
    fi
done

echo ""
if [[ "$FAILED" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  All checks passed.${RESET}"
    if [[ "$FAST" == "false" ]]; then
        echo -e "${YELLOW}  Coverage report: htmlcov/index.html${RESET}"
    fi
    exit 0
else
    echo -e "${RED}${BOLD}  One or more checks failed. See output above.${RESET}"
    exit 1
fi
