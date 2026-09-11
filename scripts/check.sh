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
# Usage:
#   bash scripts/check.sh           # full gate
#   bash scripts/check.sh --fast    # skip bandit and coverage
#
# Works in three environments:
#   - Native Linux / macOS venv  (.venv/bin/python)
#   - WSL with a Linux venv      (.venv/bin/python)
#   - WSL with a Windows venv    (.venv/Scripts/python.exe)
#     In the last case paths are converted with wslpath before being
#     passed to Windows executables.

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

header() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
    echo -e "${CYAN}${BOLD}  $1${RESET}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
}
pass()  { echo -e "${GREEN}${BOLD}  ✓ $1${RESET}"; }
fail()  { echo -e "${RED}${BOLD}  ✗ $1${RESET}"; }
info()  { echo -e "${YELLOW}  → $1${RESET}"; }

# ── Locate the virtual environment ───────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

VENV_PYTHON=""
for candidate in \
    "$REPO_ROOT/.venv/bin/python" \
    "$REPO_ROOT/.venv/Scripts/python" \
    "$REPO_ROOT/.venv/Scripts/python.exe" \
    "$REPO_ROOT/venv/bin/python" \
    "$REPO_ROOT/venv/Scripts/python" \
    "$REPO_ROOT/venv/Scripts/python.exe"; do
    if [[ -x "$candidate" ]]; then
        VENV_PYTHON="$candidate"
        break
    fi
done

if [[ -z "$VENV_PYTHON" ]]; then
    if command -v python3 &>/dev/null; then
        VENV_PYTHON="python3"
    elif command -v python &>/dev/null; then
        VENV_PYTHON="python"
    else
        echo -e "${RED}${BOLD}ERROR: No Python interpreter found.${RESET}"
        echo "Create a virtual environment first:"
        echo "  python3 -m venv .venv && source .venv/bin/activate"
        echo "  pip install -e '.[dev]'"
        exit 1
    fi
fi

PYTHON="$VENV_PYTHON"

# ── Detect whether the Python is a Windows .exe running under WSL ────────────
# If so, paths passed to it must be Windows paths (C:\...) not WSL paths (/mnt/c/...).
IS_WIN_EXE=false
if [[ "$PYTHON" == *.exe ]]; then
    IS_WIN_EXE=true
fi

# Convert a path for use by the Python interpreter.
# On a Windows .exe under WSL, convert /mnt/c/... → C:\...
# Otherwise return the path unchanged.
to_py_path() {
    if [[ "$IS_WIN_EXE" == "true" ]] && command -v wslpath &>/dev/null; then
        wslpath -w "$1"
    else
        echo "$1"
    fi
}

REPO_PY="$(to_py_path "$REPO_ROOT")"

# ── Helper: run a module via the venv Python ──────────────────────────────────
py() { "$PYTHON" -m "$@"; }

# ── Ensure dev dependencies are installed ────────────────────────────────────
header "Environment"
info "Python: $($PYTHON --version 2>&1)"
info "Interpreter: $PYTHON"
info "Working directory: $REPO_ROOT"
if [[ "$IS_WIN_EXE" == "true" ]]; then
    info "Mode: Windows .exe Python under WSL (paths converted via wslpath)"
fi

IS_VENV=false
if [[ "$PYTHON" == *".venv"* ]] || [[ "$PYTHON" == *"/venv/"* ]]; then
    IS_VENV=true
fi

if [[ "$IS_VENV" == "true" ]]; then
    if ! "$PYTHON" -m ruff --version &>/dev/null || \
       ! "$PYTHON" -m mypy --version &>/dev/null || \
       ! "$PYTHON" -m pytest --version &>/dev/null; then
        info "Dev dependencies not fully installed — running: pip install -e '.[dev]'"
        "$PYTHON" -m pip install -e "$(to_py_path "$REPO_ROOT")[dev]" -q
    fi
    if ! "$PYTHON" -m bandit --version &>/dev/null 2>&1; then
        info "Installing bandit..."
        "$PYTHON" -m pip install bandit -q
    fi
else
    for tool in ruff mypy pytest; do
        if ! "$PYTHON" -m "$tool" --version &>/dev/null 2>&1; then
            echo -e "${RED}${BOLD}ERROR: '$tool' not found.${RESET}"
            echo "Activate your virtual environment first:"
            echo "  source .venv/Scripts/activate   # Windows/WSL venv"
            echo "  source .venv/bin/activate       # Linux venv"
            exit 1
        fi
    done
fi

info "ruff:   $($PYTHON -m ruff --version 2>&1)"
info "mypy:   $($PYTHON -m mypy --version 2>&1)"
info "pytest: $($PYTHON -m pytest --version 2>&1)"

# ── Environment variables for tests ──────────────────────────────────────────
export SECRET_KEY="${SECRET_KEY:-test-secret-key-not-for-production-use-only-32chars}"
export DB_URL="${DB_URL:-sqlite+aiosqlite:///./test.db}"
export ENVIRONMENT="${ENVIRONMENT:-development}"
info "SECRET_KEY: [set]"
info "DB_URL: $DB_URL"
info "ENVIRONMENT: $ENVIRONMENT"

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

# ── 1. Ruff lint ──────────────────────────────────────────────────────────────
run_step "Ruff lint" \
    py ruff check "$REPO_PY" --output-format=full

# ── 2. Ruff format check ──────────────────────────────────────────────────────
run_step "Ruff format" \
    py ruff format --check "$REPO_PY"

# ── 3. mypy type check ────────────────────────────────────────────────────────
# mypy resolves module names relative to cwd — always use the WSL path here,
# never the Windows path, because bash's cd only understands POSIX paths.
run_step "mypy" bash -c "
    cd '$REPO_ROOT' && \
    '$PYTHON' -m mypy bastion bastion_api bastion_admin cli workers \
        --ignore-missing-imports \
        --no-error-summary
"

# ── 4. Bandit security scan ───────────────────────────────────────────────────
if [[ "$FAST" == "false" ]]; then
    PYPROJECT_PY="$(to_py_path "$REPO_ROOT/pyproject.toml")"
    run_step "Bandit" \
        py bandit \
            -r "$(to_py_path "$REPO_ROOT/bastion")" \
               "$(to_py_path "$REPO_ROOT/bastion_api")" \
               "$(to_py_path "$REPO_ROOT/bastion_admin")" \
               "$(to_py_path "$REPO_ROOT/cli")" \
               "$(to_py_path "$REPO_ROOT/workers")" \
            -c "$PYPROJECT_PY" \
            --severity-level medium \
            --confidence-level medium \
            -q
else
    info "Bandit skipped (--fast)"
    RESULTS["Bandit"]="SKIP"
fi

# ── 5. pytest ─────────────────────────────────────────────────────────────────
# pytest must run with cwd = repo root so relative imports resolve correctly.
cd "$REPO_ROOT"

if [[ "$FAST" == "false" ]]; then
    PYTEST_ARGS=(
        "$(to_py_path "$REPO_ROOT/tests")"
        --verbose
        --tb=short
        --cov=bastion
        --cov=bastion_api
        --cov=bastion_admin
        --cov-report=term-missing
        --cov-report="html:$(to_py_path "$REPO_ROOT/htmlcov")"
        -p no:warnings
    )
else
    PYTEST_ARGS=(
        "$(to_py_path "$REPO_ROOT/tests")"
        --verbose
        --tb=short
        -p no:warnings
    )
fi

run_step "pytest" \
    py pytest "${PYTEST_ARGS[@]}"

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
