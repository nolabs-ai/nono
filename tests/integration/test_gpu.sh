#!/bin/bash
# GPU Access Control Tests
# Tests that nono correctly enforces GPU device access via --allow-gpu.
#
# These tests require GPU hardware and are automatically skipped on machines
# without GPU devices. Run on a GPU-equipped instance (e.g., AWS p4d/g5, GCP a2/g2).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== GPU Access Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "GPU access suite"; then
    print_summary
    exit 0
fi

if ! command_exists python3; then
    skip_test "GPU access suite" "python3 not installed"
    print_summary
    exit 0
fi

# Detect GPU devices
has_render_nodes() {
    ls /dev/dri/renderD* >/dev/null 2>&1
}

has_nvidia_devices() {
    ls /dev/nvidia0 >/dev/null 2>&1
}

has_kfd_device() {
    [[ -e /dev/kfd ]]
}

has_dxg_device() {
    [[ -e /dev/dxg ]]
}

has_any_gpu() {
    has_render_nodes || has_nvidia_devices || has_kfd_device || has_dxg_device
}

if ! has_any_gpu; then
    skip_test "GPU access suite" "no GPU devices found (/dev/dri/renderD*, /dev/nvidia*, /dev/kfd, /dev/dxg)"
    print_summary
    exit 0
fi

if ! skip_unless_linux "GPU access suite"; then
    print_summary
    exit 0
fi

# Create a minimal test directory for --allow
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Detected GPU devices:"
ls -la /dev/dri/renderD* 2>/dev/null || true
ls -la /dev/nvidia* 2>/dev/null || true
ls -la /dev/kfd 2>/dev/null || true
echo ""

# =============================================================================
# DRM Render Node Tests
# =============================================================================

if has_render_nodes; then
    RENDER_NODE=$(ls /dev/dri/renderD* 2>/dev/null | head -1)

    # Check if the user can actually open the render node (requires 'render' group).
    # If not, skip these tests — the failure would be Unix permissions, not sandbox.
    if ! python3 -c "import os; fd = os.open('${RENDER_NODE}', os.O_RDWR); os.close(fd)" 2>/dev/null; then
        skip_test "DRM render node tests" "no permission on ${RENDER_NODE} (user not in 'render' group?)"
    else

    echo "--- DRM Render Node Tests (${RENDER_NODE}) ---"

    # Without --allow-gpu: opening a render node should fail with permission denied
    expect_failure "render node denied without --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
        python3 -c "
import os, sys, errno
try:
    fd = os.open('${RENDER_NODE}', os.O_RDWR)
    os.close(fd)
    print('ERROR: opened render node without --allow-gpu', file=sys.stderr)
    sys.exit(0)  # should not reach here
except PermissionError:
    sys.exit(1)  # expected: sandbox denied access
"

    # With --allow-gpu: opening a render node should succeed
    expect_success "render node allowed with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        python3 -c "
import os, sys
fd = os.open('${RENDER_NODE}', os.O_RDWR)
os.close(fd)
print('OK: opened render node successfully')
"

    # With --allow-gpu: verify we can actually ioctl the device (not just open it)
    expect_success "render node ioctl works with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        python3 -c "
import os, sys, fcntl, struct
fd = os.open('${RENDER_NODE}', os.O_RDWR)
# DRM_IOCTL_VERSION = 0xc0406400 on 64-bit Linux
# This is a safe read-only ioctl that returns driver version info
try:
    # Try DRM version ioctl - may fail on some drivers but open+ioctl proves access
    buf = bytearray(4 * 5 + 3 * 8)  # drm_version struct (padded)
    fcntl.ioctl(fd, 0xc0406400, buf, True)
    print('OK: DRM_IOCTL_VERSION succeeded')
except OSError as e:
    # ENOTTY/EINVAL is ok - means ioctl reached the driver but format was wrong
    # The point is it wasn't EACCES (sandbox didn't block it)
    if e.errno in (25, 22):  # ENOTTY, EINVAL
        print(f'OK: ioctl reached driver (errno={e.errno}, expected for raw call)')
    else:
        print(f'ERROR: unexpected ioctl error: {e}', file=sys.stderr)
        sys.exit(1)
finally:
    os.close(fd)
"
    fi # end of render group permission check
else
    skip_test "render node tests" "no /dev/dri/renderD* found"
fi

# =============================================================================
# NVIDIA Device Tests
# =============================================================================

if has_nvidia_devices; then
    echo ""
    echo "--- NVIDIA Device Tests ---"

    # Count NVIDIA GPU devices
    NVIDIA_COUNT=$(ls /dev/nvidia[0-9]* 2>/dev/null | wc -l)
    echo "Found ${NVIDIA_COUNT} NVIDIA GPU device(s)"

    # Without --allow-gpu: opening nvidia0 should fail
    expect_failure "nvidia0 denied without --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
        python3 -c "
import os, sys
try:
    fd = os.open('/dev/nvidia0', os.O_RDWR)
    os.close(fd)
    sys.exit(0)
except PermissionError:
    sys.exit(1)
"

    # Without --allow-gpu: nvidiactl should also be denied
    expect_failure "nvidiactl denied without --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
        python3 -c "
import os, sys
try:
    fd = os.open('/dev/nvidiactl', os.O_RDWR)
    os.close(fd)
    sys.exit(0)
except PermissionError:
    sys.exit(1)
"

    # With --allow-gpu: should be able to open all NVIDIA devices
    expect_success "all NVIDIA devices accessible with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        python3 -c "
import os, sys, glob
devices = glob.glob('/dev/nvidia[0-9]*') + ['/dev/nvidiactl']
if os.path.exists('/dev/nvidia-uvm'):
    devices.append('/dev/nvidia-uvm')
opened = 0
for dev in devices:
    try:
        fd = os.open(dev, os.O_RDWR)
        os.close(fd)
        opened += 1
    except Exception as e:
        print(f'WARN: could not open {dev}: {e}', file=sys.stderr)
print(f'OK: opened {opened}/{len(devices)} NVIDIA devices')
if opened == 0:
    sys.exit(1)
"

    # Multi-GPU: verify all GPU devices are accessible (not just nvidia0)
    if [[ "$NVIDIA_COUNT" -gt 1 ]]; then
        expect_success "multi-GPU: all nvidia[0-N] devices accessible" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
            python3 -c "
import os, sys, glob
gpu_devs = sorted(glob.glob('/dev/nvidia[0-9]*'))
for dev in gpu_devs:
    fd = os.open(dev, os.O_RDWR)
    os.close(fd)
print(f'OK: opened all {len(gpu_devs)} GPU devices: {gpu_devs}')
"
    else
        skip_test "multi-GPU access" "only 1 NVIDIA GPU present"
    fi

    # NVIDIA MIG: test nvidia-caps if present
    if [[ -d /dev/nvidia-caps ]]; then
        expect_success "nvidia-caps accessible with --allow-gpu" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
            python3 -c "
import os, sys, glob
caps = glob.glob('/dev/nvidia-caps/*')
for cap in caps:
    fd = os.open(cap, os.O_RDWR)
    os.close(fd)
print(f'OK: opened {len(caps)} nvidia-caps devices')
"
    else
        skip_test "nvidia-caps (MIG) access" "no /dev/nvidia-caps/ found"
    fi

    # NVIDIA procfs grants — regression tests for the --allow-gpu CUDA-init
    # fix. These paths are only granted when NVIDIA devices are present; the
    # probes live inside has_nvidia_devices to match the scope of the grant.
    echo ""
    echo "--- NVIDIA procfs Grant Tests ---"

    # /proc/self/task/<tid>/comm write — CUDA Error 304 root cause.
    expect_failure "/proc/self/task/<tid>/comm write denied without --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
        python3 -c "
import os, sys
tid = os.gettid() if hasattr(os, 'gettid') else os.getpid()
try:
    with open(f'/proc/self/task/{tid}/comm', 'wb') as f:
        f.write(b'probe\n')
    sys.exit(0)  # should not reach here
except PermissionError:
    sys.exit(1)  # expected: sandbox denied the write
"
    expect_success "/proc/self/task/<tid>/comm write allowed with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        python3 -c "
import os
tid = os.gettid() if hasattr(os, 'gettid') else os.getpid()
with open(f'/proc/self/task/{tid}/comm', 'wb') as f:
    f.write(b'probe\n')
print('OK: wrote thread comm under --allow-gpu')
"

    # Issue #924 regression: grandchild process (different PID from the
    # direct child) must also be able to write to its own
    # /proc/<pid>/task/<tid>/comm. Without the widening of
    # /proc/self/task → /proc inside widen_procfs_self_to_proc(), this
    # write would be denied because the Landlock rule is bound to the
    # direct child's PID inode, surfacing as CUDA Error 304.
    expect_success "grandchild /proc/self/task/<tid>/comm write allowed with --allow-gpu (#924)" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        sh -c "python3 -c \"
import os
tid = os.gettid() if hasattr(os, 'gettid') else os.getpid()
with open(f'/proc/self/task/{tid}/comm', 'wb') as f:
    f.write(b'probe\n')
print(f'OK: grandchild (pid={os.getpid()}) wrote thread comm')
\""

    # /proc/driver/nvidia — CUDA UVM init read. Only test if the driver is
    # loaded (the grant itself skips the path when it doesn't exist).
    if [[ -d /proc/driver/nvidia ]]; then
        expect_failure "/proc/driver/nvidia read denied without --allow-gpu" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
            ls /proc/driver/nvidia
        expect_success "/proc/driver/nvidia read allowed with --allow-gpu" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
            ls /proc/driver/nvidia
    else
        skip_test "/proc/driver/nvidia read probe" "/proc/driver/nvidia not present (driver not loaded?)"
    fi

    # Least-privilege regression guard: --allow-gpu must NOT grant the
    # parent /proc/driver directory (would expose metadata about unrelated
    # kernel drivers). Listing /proc/driver should still fail.
    #
    # Caveat: `ls` exercises Landlock's READ_DIR access, which is distinct
    # from READ_FILE under the current ABI. A future ABI that splits or
    # renames these bits could change what this probe observes. The assertion
    # remains valid for today's ABI; revisit if the kernel evolves its
    # filesystem access vocabulary.
    expect_failure "/proc/driver parent read denied even with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        ls /proc/driver
else
    skip_test "NVIDIA device tests" "no /dev/nvidia0 found"
fi

# =============================================================================
# AMD KFD Tests
# =============================================================================

if has_kfd_device; then
    echo ""
    echo "--- AMD KFD Tests ---"

    expect_failure "kfd denied without --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
        python3 -c "
import os, sys
try:
    fd = os.open('/dev/kfd', os.O_RDWR)
    os.close(fd)
    sys.exit(0)
except PermissionError:
    sys.exit(1)
"

    expect_success "kfd allowed with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        python3 -c "
import os, sys
fd = os.open('/dev/kfd', os.O_RDWR)
os.close(fd)
print('OK: opened /dev/kfd')
"
else
    skip_test "AMD KFD tests" "no /dev/kfd found"
fi

# =============================================================================
# Read-only Path Tests (Vulkan ICD, sysfs)
# =============================================================================

echo ""
echo "--- Read-only GPU Path Tests ---"

for dir in /usr/share/vulkan /etc/vulkan /sys/class/drm; do
    if [[ -d "$dir" ]]; then
        expect_success "${dir} readable with --allow-gpu" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
            ls "$dir"
    else
        skip_test "${dir} readable" "directory does not exist"
    fi
done

# =============================================================================
# WSL2 GPU Tests (/dev/dxg passthrough)
# =============================================================================

if has_dxg_device; then
    echo ""
    echo "--- WSL2 GPU Tests (/dev/dxg) ---"

    # /dev/dxg read/write should be denied without --allow-gpu
    # (metadata via ls may succeed — Landlock allows stat on denied paths)
    expect_failure "/dev/dxg read denied without --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" -- \
        cat /dev/dxg

    # /dev/dxg should be accessible with --allow-gpu
    expect_success "/dev/dxg accessible with --allow-gpu" \
        "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
        ls -la /dev/dxg

    # /usr/lib/wsl/lib should be readable with --allow-gpu
    if [[ -d /usr/lib/wsl/lib ]]; then
        expect_success "/usr/lib/wsl/lib readable with --allow-gpu" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
            ls /usr/lib/wsl/lib
    else
        skip_test "/usr/lib/wsl/lib readable" "directory does not exist"
    fi

    # nvidia-smi should work inside sandbox with --allow-gpu
    if command_exists nvidia-smi; then
        expect_success "nvidia-smi works inside sandbox with --allow-gpu" \
            "$NONO_BIN" run --silent --allow-cwd --allow "$TMPDIR" --allow-gpu -- \
            nvidia-smi
    else
        skip_test "nvidia-smi inside sandbox" "nvidia-smi not installed"
    fi
fi

# =============================================================================
# Summary
# =============================================================================

print_summary

if [[ "$TESTS_FAILED" -gt 0 ]]; then
    exit 1
fi
