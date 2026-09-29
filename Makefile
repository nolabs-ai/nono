# nono - Makefile for library and CLI
#
# Usage:
#   make              Build everything
#   make test         Run all tests
#   make check        Run clippy and format check
#   make release      Build release binaries

.PHONY: all build build-lib build-cli build-ffi build-arm64 test test-workspace test-lib test-cli test-ffi test-doc test-one test-repeat test-spiffe check clippy fmt clean install audit help

# Keep Rust panic locations available in both local and CI test output. A
# caller can still override this (for example, RUST_BACKTRACE=full make test).
RUST_BACKTRACE ?= 1

# Default target
all: build

# Build targets
build: build-lib build-cli

build-lib:
	cargo build -p nono

build-cli:
	cargo build -p nono-cli

build-ffi:
	cargo build -p nono-ffi

build-release:
	cargo build --release

build-release-lib:
	cargo build --release -p nono

build-release-cli:
	cargo build --release -p nono-cli

# Cross-compilation: Linux ARM64 (aarch64-unknown-linux-gnu)
# Uses `cross` which handles both native (ARM64) and cross-compilation (e.g. x86_64).
# If `cross` fails with "may not be able to run on this system",
# install from git: cargo install cross --git https://github.com/cross-rs/cross
build-arm64:
	@cross build --release --target aarch64-unknown-linux-gnu -p nono-cli

# Test targets
#
# Match the regular Rust CI coverage. The former package-by-package aggregate
# omitted nono-proxy and any future workspace members.
test: test-workspace

test-workspace:
	RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test --workspace --no-fail-fast

test-lib:
	RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test -p nono --no-fail-fast

test-cli:
	RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test -p nono-cli --no-fail-fast

test-ffi:
	RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test -p nono-ffi --no-fail-fast

test-doc:
	RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test --doc --workspace --no-fail-fast

# Run one exact test with live process output. Usage:
#   make test-one TEST=approval_runtime::tests::platform_poll_loop_gives_up_at_the_configured_timeout
test-one:
	@test -n "$(TEST)" || { echo "Usage: make test-one TEST=<exact-test-name>" >&2; exit 2; }
	RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test --workspace --no-fail-fast "$(TEST)" -- --exact --nocapture --test-threads=1

# Repeat one exact test serially to reproduce intermittent failures. Usage:
#   make test-repeat TEST=<exact-test-name> COUNT=100
COUNT ?= 20
test-repeat:
	@test -n "$(TEST)" || { echo "Usage: make test-repeat TEST=<exact-test-name> [COUNT=<iterations>]" >&2; exit 2; }
	@set -eu; \
	i=1; \
	while [ "$$i" -le "$(COUNT)" ]; do \
		echo "==> $$i/$(COUNT): $(TEST)"; \
		RUST_BACKTRACE=$(RUST_BACKTRACE) cargo test --workspace --no-fail-fast "$(TEST)" -- --exact --nocapture --test-threads=1; \
		i=$$((i + 1)); \
	done

test-spiffe:
	bash scripts/spire-test.sh

# Check targets (lint + format)
check: clippy fmt-check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used

clippy-fix:
	cargo clippy --fix --allow-dirty

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# Clean
clean:
	cargo clean

# Install CLI to ~/.cargo/bin
install:
	cargo install --path crates/nono-cli

# Run the CLI (for quick testing)
run:
	cargo run -p nono-cli -- --help

run-setup:
	cargo run -p nono-cli -- setup --check-only

run-dry:
	cargo run -p nono-cli -- run --allow-cwd --dry-run -- echo "test"

# Development helpers
watch:
	cargo watch -x 'build -p nono-cli'

watch-test:
	cargo watch -x 'test'

# Documentation
doc:
	cargo doc --no-deps --open

doc-lib:
	cargo doc -p nono --no-deps --open

# Security audit
audit:
	cargo audit

# Lint: forbid legacy #594 schema tokens in docs and rustdoc outside the
# allowlist (see scripts/lint-docs.sh).
.PHONY: lint-docs
lint-docs:
	bash scripts/lint-docs.sh

# CI simulation (what CI would run)
ci: check test test-doc audit lint-docs
	@echo "CI checks passed"

# Help
help:
	@echo "nono Makefile targets:"
	@echo ""
	@echo "Build:"
	@echo "  make build          Build library and CLI (debug)"
	@echo "  make build-lib      Build library only"
	@echo "  make build-cli      Build CLI only"
	@echo "  make build-ffi      Build C FFI bindings"
	@echo "  make build-release  Build release binaries"
	@echo "  make build-arm64    Build CLI for Linux ARM64 (cargo on Linux ARM64; cross elsewhere)"
	@echo ""
	@echo "Test:"
	@echo "  make test           Run all tests"
	@echo "  make test-workspace Run all workspace Rust tests"
	@echo "  make test-lib       Run library tests only"
	@echo "  make test-cli       Run CLI tests only"
	@echo "  make test-ffi       Run C FFI tests only"
	@echo "  make test-doc       Run doc tests only"
	@echo "  make test-one TEST=<name>             Run one exact Rust test with live output"
	@echo "  make test-repeat TEST=<name> COUNT=N  Repeat one exact Rust test serially"
	@echo "  make test-spiffe    Run SPIFFE/SPIRE integration tests (downloads SPIRE if needed)"
	@echo ""
	@echo "Check:"
	@echo "  make check          Run clippy and format check"
	@echo "  make clippy         Run clippy linter"
	@echo "  make fmt            Format code"
	@echo "  make fmt-check      Check formatting"
	@echo ""
	@echo "Security:"
	@echo "  make audit          Run cargo audit for vulnerabilities"
	@echo ""
	@echo "Lint:"
	@echo "  make lint-docs      Forbid legacy #594 schema tokens in docs"
	@echo ""
	@echo "Other:"
	@echo "  make install        Install CLI to ~/.cargo/bin"
	@echo "  make clean          Clean build artifacts"
	@echo "  make doc            Generate and open documentation"
	@echo "  make ci             Simulate CI checks"
	@echo "  make help           Show this help"
