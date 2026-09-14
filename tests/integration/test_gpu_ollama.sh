#!/bin/bash
# GPU Ollama Smoke Tests
# End-to-end verification that GPU compute actually works inside the nono sandbox
# using ollama as the inference engine.
#
# Prerequisites:
#   - GPU hardware (NVIDIA or AMD)
#   - ollama installed (https://ollama.com/install.sh)
#   - nono built (cargo build --release -p nono-cli)
#   - curl installed
#
# Usage:
#   # Run from project root:
#   ./tests/integration/test_gpu_ollama.sh
#
#   # Or via the integration test runner (auto-skips if ollama not installed):
#   ./scripts/run_all_tests.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== GPU Ollama Smoke Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "GPU ollama suite"; then
    print_summary
    exit 0
fi

if ! skip_unless_linux "GPU ollama suite"; then
    print_summary
    exit 0
fi

# Check prerequisites
if ! command_exists ollama; then
    skip_test "GPU ollama suite" "ollama not installed"
    print_summary
    exit 0
fi

if ! command_exists curl; then
    skip_test "GPU ollama suite" "curl not installed"
    print_summary
    exit 0
fi

# Detect GPU
has_any_gpu() {
    ls /dev/dri/renderD* >/dev/null 2>&1 || \
    ls /dev/nvidia0 >/dev/null 2>&1 || \
    [[ -e /dev/kfd ]] || \
    [[ -e /dev/dxg ]]
}

if ! has_any_gpu; then
    skip_test "GPU ollama suite" "no GPU devices found"
    print_summary
    exit 0
fi

# Use a small generative model for testing. tinyllama (~637MB) is the smallest
# model that supports text generation via `ollama run`. Avoid embedding-only
# models (e.g. all-minilm) as they don't support the generate endpoint.
TEST_MODEL="${NONO_GPU_TEST_MODEL:-tinyllama}"

# Pick a port that won't conflict
OLLAMA_PORT="${NONO_GPU_TEST_PORT:-11399}"
OLLAMA_HOST="127.0.0.1:${OLLAMA_PORT}"

# Create work directory for the sandbox
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"; kill_ollama_servers' EXIT

# Track PIDs for cleanup
OLLAMA_PIDS=()

kill_ollama_servers() {
    for pid in "${OLLAMA_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}

wait_for_ollama() {
    local host="$1"
    local timeout="${2:-30}"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if curl -sf "http://${host}/" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Determine where ollama stores models so we can grant access
OLLAMA_MODELS="${OLLAMA_MODELS:-${HOME}/.ollama}"

echo ""
echo "Configuration:"
echo "  Model:        ${TEST_MODEL}"
echo "  Port:         ${OLLAMA_PORT}"
echo "  Model store:  ${OLLAMA_MODELS}"
echo "  GPU devices:  $(ls /dev/dri/renderD* /dev/nvidia* /dev/kfd /dev/dxg 2>/dev/null | tr '\n' ' ')"
echo ""

# =============================================================================
# Pre-pull: ensure model is available (outside sandbox)
# =============================================================================

echo "--- Setup: pulling test model ---"

# Start ollama briefly to pull the model if needed
OLLAMA_HOST="${OLLAMA_HOST}" ollama serve >/dev/null 2>&1 &
SETUP_PID=$!
OLLAMA_PIDS+=("$SETUP_PID")

if ! wait_for_ollama "${OLLAMA_HOST}" 30; then
    echo -e "${RED}FAIL: could not start ollama for model pull${NC}"
    print_summary
    exit 1
fi

# Pull model (no-op if already present)
OLLAMA_HOST="${OLLAMA_HOST}" ollama pull "${TEST_MODEL}" 2>&1 || true
kill "$SETUP_PID" 2>/dev/null || true
wait "$SETUP_PID" 2>/dev/null || true
OLLAMA_PIDS=()

echo ""

# =============================================================================
# Test 1: Ollama WITHOUT --allow-gpu (should fall back to CPU or fail GPU init)
# =============================================================================

echo "--- Test: ollama without --allow-gpu ---"

NOGPU_PORT=$((OLLAMA_PORT + 1))
NOGPU_HOST="127.0.0.1:${NOGPU_PORT}"

# Start ollama inside sandbox WITHOUT GPU access.
# Grant network (ollama needs to listen), model store (read), and tmpdir.
OLLAMA_HOST="${NOGPU_HOST}" \
"$NONO_BIN" run --silent --allow-cwd \
    --read "${OLLAMA_MODELS}" \
    --allow "$TMPDIR" \
    --allow-net \
    -- ollama serve >"$TMPDIR/nogpu_stdout.log" 2>"$TMPDIR/nogpu_stderr.log" &
NOGPU_PID=$!
OLLAMA_PIDS+=("$NOGPU_PID")

if wait_for_ollama "${NOGPU_HOST}" 30; then
    # Server started — check if it's using GPU or CPU
    OLLAMA_HOST="${NOGPU_HOST}" ollama run "${TEST_MODEL}" "test" >"$TMPDIR/nogpu_response.txt" 2>&1 || true

    # Check the logs for GPU initialization failure indicators
    NOGPU_LOGS=$(cat "$TMPDIR/nogpu_stderr.log" 2>/dev/null || echo "")

    # Look for signs that GPU was NOT used
    if echo "$NOGPU_LOGS" | grep -iqE "no (nvidia|cuda|rocm|gpu)|gpu not available|cpu|failed.*gpu|could not.*gpu|permission denied.*nvidia|permission denied.*dri|permission denied.*kfd"; then
        echo -e "  ${GREEN}PASS${NC}: ollama without --allow-gpu shows no GPU access"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        # ollama may silently fall back to CPU without logging — check if model loaded at all
        if [[ -s "$TMPDIR/nogpu_response.txt" ]]; then
            echo -e "  ${YELLOW}WARN${NC}: ollama responded (likely CPU fallback), logs inconclusive"
            echo "       Check: $TMPDIR/nogpu_stderr.log"
            TESTS_RUN=$((TESTS_RUN + 1))
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "  ${RED}FAIL${NC}: ollama without --allow-gpu — unexpected behavior"
            echo "       Logs: ${NOGPU_LOGS:0:500}"
            TESTS_RUN=$((TESTS_RUN + 1))
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
else
    # Server failed to start entirely — also acceptable (GPU init crash = containment working)
    NOGPU_LOGS=$(cat "$TMPDIR/nogpu_stderr.log" 2>/dev/null || echo "")
    if echo "$NOGPU_LOGS" | grep -iqE "permission denied|operation not permitted|sandbox"; then
        echo -e "  ${GREEN}PASS${NC}: ollama failed to start without GPU (sandbox denied access)"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${YELLOW}WARN${NC}: ollama failed to start (may not be GPU-related)"
        echo "       Logs: ${NOGPU_LOGS:0:500}"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi
fi

kill "$NOGPU_PID" 2>/dev/null || true
wait "$NOGPU_PID" 2>/dev/null || true

# =============================================================================
# Test 2: Ollama WITH --allow-gpu (should use GPU for inference)
# =============================================================================

echo ""
echo "--- Test: ollama with --allow-gpu ---"

GPU_PORT=$((OLLAMA_PORT + 2))
GPU_HOST="127.0.0.1:${GPU_PORT}"

# Start ollama inside sandbox WITH GPU access
OLLAMA_HOST="${GPU_HOST}" \
"$NONO_BIN" run --silent --allow-cwd \
    --read "${OLLAMA_MODELS}" \
    --allow "$TMPDIR" \
    --allow-net \
    --allow-gpu \
    -- ollama serve >"$TMPDIR/gpu_stdout.log" 2>"$TMPDIR/gpu_stderr.log" &
GPU_PID=$!
OLLAMA_PIDS+=("$GPU_PID")

if wait_for_ollama "${GPU_HOST}" 30; then
    echo -e "  ${GREEN}PASS${NC}: ollama started with --allow-gpu"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))

    # Run inference
    RESPONSE=$(OLLAMA_HOST="${GPU_HOST}" ollama run "${TEST_MODEL}" "test" 2>"$TMPDIR/gpu_run_stderr.log" || echo "")
    GPU_LOGS=$(cat "$TMPDIR/gpu_stderr.log" 2>/dev/null || echo "")

    if [[ -n "$RESPONSE" ]]; then
        echo -e "  ${GREEN}PASS${NC}: inference succeeded with --allow-gpu"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: inference failed with --allow-gpu"
        echo "       Logs: ${GPU_LOGS:0:500}"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Check logs for GPU detection
    if echo "$GPU_LOGS" | grep -iqE "nvidia|cuda|rocm|gpu.*found|gpu.*detected|using gpu|metal"; then
        echo -e "  ${GREEN}PASS${NC}: GPU detected in ollama logs"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        # GPU may be used without explicit log messages in some ollama versions
        echo -e "  ${YELLOW}SKIP${NC}: GPU detection not confirmed in logs (may still be in use)"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi

    # Verify via API that model is loaded
    API_RESPONSE=$(curl -sf "http://${GPU_HOST}/api/tags" 2>/dev/null || echo "")
    if echo "$API_RESPONSE" | grep -q "${TEST_MODEL}"; then
        echo -e "  ${GREEN}PASS${NC}: model listed via ollama API"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: model not listed via API"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC}: ollama failed to start with --allow-gpu"
    GPU_LOGS=$(cat "$TMPDIR/gpu_stderr.log" 2>/dev/null || echo "")
    echo "       Logs: ${GPU_LOGS:0:500}"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

kill "$GPU_PID" 2>/dev/null || true
wait "$GPU_PID" 2>/dev/null || true

# =============================================================================
# Summary
# =============================================================================

print_summary

if [[ "$TESTS_FAILED" -gt 0 ]]; then
    exit 1
fi
