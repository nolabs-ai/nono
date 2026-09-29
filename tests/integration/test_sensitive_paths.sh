#!/bin/bash
# shellcheck disable=SC2088 # User-facing test descriptions intentionally use ~ notation.
# Sensitive Path Protection Tests
# Verifies that credential and secret paths are blocked by default

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}Sensitive Path Protection Tests${NC}"

verify_nono_binary
if ! require_working_sandbox "sensitive path suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Testing sensitive path protection..."
echo "(These tests verify paths are blocked even with broad grants)"
echo ""

# SSH Keys

echo "SSH Keys"

if [[ -d ~/.ssh ]]; then
    expect_failure "~/.ssh directory blocked with ~ grant" \
        "$NONO_BIN" run --allow ~ -- ls ~/.ssh/

    if [[ -f ~/.ssh/id_rsa ]]; then
        expect_failure "~/.ssh/id_rsa blocked" \
            "$NONO_BIN" run --allow ~ -- cat ~/.ssh/id_rsa
    elif [[ -f ~/.ssh/id_ed25519 ]]; then
        expect_failure "~/.ssh/id_ed25519 blocked" \
            "$NONO_BIN" run --allow ~ -- cat ~/.ssh/id_ed25519
    else
        skip_test "SSH private key test" "no id_rsa or id_ed25519 found"
    fi
else
    skip_test "SSH directory tests" "~/.ssh not found"
fi

# Cloud Credentials

echo ""
echo "Cloud Credentials"

if [[ -d ~/.aws ]]; then
    expect_failure "~/.aws directory blocked" \
        "$NONO_BIN" run --allow ~ -- ls ~/.aws/

    if [[ -f ~/.aws/credentials ]]; then
        expect_failure "~/.aws/credentials blocked" \
            "$NONO_BIN" run --allow ~ -- cat ~/.aws/credentials
    fi
else
    skip_test "AWS credentials test" "~/.aws not found"
fi

if [[ -d ~/.kube ]]; then
    expect_failure "~/.kube directory blocked" \
        "$NONO_BIN" run --allow ~ -- ls ~/.kube/

    if [[ -f ~/.kube/config ]]; then
        expect_failure "~/.kube/config blocked" \
            "$NONO_BIN" run --allow ~ -- cat ~/.kube/config
    fi
else
    skip_test "Kubernetes config test" "~/.kube not found"
fi

if [[ -d ~/.docker ]]; then
    expect_failure "~/.docker directory blocked" \
        "$NONO_BIN" run --allow ~ -- ls ~/.docker/
else
    skip_test "Docker config test" "~/.docker not found"
fi

if [[ -d ~/.azure ]]; then
    expect_failure "~/.azure directory blocked" \
        "$NONO_BIN" run --allow ~ -- ls ~/.azure/
else
    skip_test "Azure credentials test" "~/.azure not found"
fi

if [[ -d ~/.gcloud ]] || [[ -d ~/.config/gcloud ]]; then
    if [[ -d ~/.gcloud ]]; then
        expect_failure "~/.gcloud directory blocked" \
            "$NONO_BIN" run --allow ~ -- ls ~/.gcloud/
    fi
    if [[ -d ~/.config/gcloud ]]; then
        expect_failure "~/.config/gcloud directory blocked" \
            "$NONO_BIN" run --allow ~ -- ls ~/.config/gcloud/
    fi
else
    skip_test "GCP credentials test" "~/.gcloud not found"
fi

# Shell Configurations

echo ""
echo "Shell Configurations"

if [[ -f ~/.zshrc ]]; then
    expect_failure "~/.zshrc blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.zshrc
else
    skip_test "zshrc test" "~/.zshrc not found"
fi

if [[ -f ~/.bashrc ]]; then
    expect_failure "~/.bashrc blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.bashrc
else
    skip_test "bashrc test" "~/.bashrc not found"
fi

if [[ -f ~/.bash_profile ]]; then
    expect_failure "~/.bash_profile blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.bash_profile
else
    skip_test "bash_profile test" "~/.bash_profile not found"
fi

if [[ -f ~/.profile ]]; then
    expect_failure "~/.profile blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.profile
else
    skip_test "profile test" "~/.profile not found"
fi

if [[ -f ~/.env ]]; then
    expect_failure "~/.env blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.env
else
    skip_test "env file test" "~/.env not found"
fi

if [[ -f ~/.envrc ]]; then
    expect_failure "~/.envrc blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.envrc
else
    skip_test "envrc test" "~/.envrc not found"
fi

# Password Managers & GPG

echo ""
echo "Password Managers & GPG"

if [[ -d ~/.gnupg ]]; then
    expect_failure "~/.gnupg directory blocked" \
        "$NONO_BIN" run --allow ~ -- ls ~/.gnupg/
else
    skip_test "GnuPG test" "~/.gnupg not found"
fi

if [[ -d ~/.password-store ]]; then
    expect_failure "~/.password-store directory blocked" \
        "$NONO_BIN" run --allow ~ -- ls ~/.password-store/
else
    skip_test "password-store test" "~/.password-store not found"
fi

# History Files

echo ""
echo "History Files"

if [[ -f ~/.zsh_history ]]; then
    expect_failure "~/.zsh_history blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.zsh_history
else
    skip_test "zsh_history test" "~/.zsh_history not found"
fi

if [[ -f ~/.bash_history ]]; then
    expect_failure "~/.bash_history blocked" \
        "$NONO_BIN" run --allow ~ -- cat ~/.bash_history
else
    skip_test "bash_history test" "~/.bash_history not found"
fi

# macOS Specific

echo ""
echo "macOS Specific"

if is_macos; then
    if [[ -d ~/Library/Keychains ]]; then
        expect_failure "~/Library/Keychains blocked" \
            "$NONO_BIN" run --allow ~ -- ls ~/Library/Keychains/
    else
        skip_test "Keychain test" "~/Library/Keychains not found"
    fi

    if [[ -d ~/Library/Messages ]]; then
        expect_failure "~/Library/Messages blocked" \
            "$NONO_BIN" run --allow ~ -- ls ~/Library/Messages/
    else
        skip_test "Messages test" "~/Library/Messages not found"
    fi

    if [[ -d "$HOME/Library/Application Support/Google/Chrome" ]]; then
        expect_failure "Chrome profile blocked" \
            "$NONO_BIN" run --allow ~ -- ls "$HOME/Library/Application Support/Google/Chrome/"
    else
        skip_test "Chrome profile test" "Chrome not found"
    fi
else
    skip_test "macOS Keychain test" "not macOS"
    skip_test "macOS Messages test" "not macOS"
    skip_test "Chrome profile test" "not macOS"
fi

# Explicit Grant Override

echo ""
echo "Explicit Grant Override"

# Sensitive paths remain denied even if explicitly granted by CLI flags.
# Note: These tests use --allow /tmp which triggers Landlock EBADFD on Linux CI containers.
if is_linux; then
    skip_test "explicit --read-file ~/.zshrc stays denied" "Landlock EBADFD with /tmp in CI containers"
    skip_test "explicit --read ~/.ssh stays denied" "Landlock EBADFD with /tmp in CI containers"
else
    if [[ -f ~/.zshrc ]]; then
        expect_failure "explicit --read-file ~/.zshrc stays denied" \
            "$NONO_BIN" run --read-file ~/.zshrc --allow /tmp -- cat ~/.zshrc
    else
        skip_test "explicit --read-file ~/.zshrc stays denied" "~/.zshrc not found"
    fi

    if [[ -d ~/.ssh ]]; then
        expect_failure "explicit --read ~/.ssh stays denied" \
            "$NONO_BIN" run --read ~/.ssh --allow /tmp -- ls ~/.ssh/
    fi
fi

# Internal State Protection

echo ""
echo "Internal State Protection"

expect_output_contains "--allow ~ is rejected when it overlaps protected nono state" \
    "overlaps protected nono state root" \
    "$NONO_BIN" run --allow ~ -- true

expect_output_contains "explicit ~/.nono subtree grant is rejected" \
    "overlaps protected nono state root" \
    "$NONO_BIN" run --allow "$HOME/.nono/rollbacks" -- true

# Path Collision Bypass Prevention (Security Regression Tests)

echo ""
echo "Path Collision Bypass Prevention"
echo "(These tests verify the fix for string-based starts_with vulnerability)"
echo ""

# Create collision directories that could bypass sensitive path protection
# if the comparison used string starts_with() instead of path component comparison.
COLLISION_DIR_SSH="$TMPDIR/.sshfoo"
COLLISION_DIR_AWS="$TMPDIR/.awsbackup"
mkdir -p "$COLLISION_DIR_SSH" "$COLLISION_DIR_AWS"
echo "not-a-key" > "$COLLISION_DIR_SSH/fake"
echo "not-creds" > "$COLLISION_DIR_AWS/fake"

# Test 1: Granting ~/.sshfoo must NOT bypass ~/.ssh protection
# The vulnerable code would match "/home/user/.sshfoo".starts_with("/home/user/.ssh")
if [[ -d ~/.ssh ]]; then
    expect_failure "~/.sshfoo grant does NOT bypass ~/.ssh protection" \
        "$NONO_BIN" run --read "$COLLISION_DIR_SSH" --allow "$TMPDIR" -- ls ~/.ssh/

    if [[ -f ~/.ssh/id_rsa ]] || [[ -f ~/.ssh/id_ed25519 ]]; then
        if [[ -f ~/.ssh/id_rsa ]]; then
            KEY_FILE=~/.ssh/id_rsa
        else
            KEY_FILE=~/.ssh/id_ed25519
        fi
        expect_failure "~/.sshfoo grant does NOT allow reading SSH keys" \
            "$NONO_BIN" run --read "$COLLISION_DIR_SSH" --allow "$TMPDIR" -- cat "$KEY_FILE"
    fi
else
    skip_test "SSH collision bypass test" "~/.ssh not found"
fi

# Test 2: Granting ~/.awsbackup must NOT bypass ~/.aws protection
if [[ -d ~/.aws ]]; then
    expect_failure "~/.awsbackup grant does NOT bypass ~/.aws protection" \
        "$NONO_BIN" run --read "$COLLISION_DIR_AWS" --allow "$TMPDIR" -- ls ~/.aws/

    if [[ -f ~/.aws/credentials ]]; then
        expect_failure "~/.awsbackup grant does NOT allow reading AWS creds" \
            "$NONO_BIN" run --read "$COLLISION_DIR_AWS" --allow "$TMPDIR" -- cat ~/.aws/credentials
    fi
else
    skip_test "AWS collision bypass test" "~/.aws not found"
fi

# Test 3: Verify the collision directories themselves ARE accessible (grants work)
expect_success "collision directory itself is readable when granted" \
    "$NONO_BIN" run --read "$COLLISION_DIR_SSH" --allow "$TMPDIR" -- cat "$COLLISION_DIR_SSH/fake"

# Summary

print_summary
