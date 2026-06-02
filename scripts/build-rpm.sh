#!/usr/bin/env bash
# Build an RPM for an already-built nono CLI binary.
# Usage: scripts/build-rpm.sh <version> <target> [binary]

set -euo pipefail

usage() {
    echo "Usage: $0 <version> <target> [binary]" >&2
    echo "Targets: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 2
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "Error: rpmbuild is required to build RPM packages" >&2
    exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"
PACKAGE_NAME="nono-cli"
VERSION="${1#v}"
TARGET="$2"
BINARY="${3:-${ROOT}/target/${TARGET}/release/nono}"

case "${TARGET}" in
    x86_64-unknown-linux-gnu)
        RPM_ARCH="x86_64"
        ;;
    aarch64-unknown-linux-gnu)
        RPM_ARCH="aarch64"
        ;;
    *)
        echo "Error: unsupported RPM target: ${TARGET}" >&2
        usage
        exit 1
        ;;
esac

if [[ ! -f "${BINARY}" ]]; then
    echo "Error: binary not found: ${BINARY}" >&2
    exit 1
fi

RPM_VERSION="${VERSION}"
RPM_RELEASE="1%{?dist}"
if [[ "${VERSION}" == *-* ]]; then
    RPM_VERSION="${VERSION%%-*}"
    RPM_PRERELEASE="${VERSION#*-}"
    RPM_PRERELEASE="${RPM_PRERELEASE//[^[:alnum:].]/.}"
    RPM_RELEASE="0.${RPM_PRERELEASE}%{?dist}"
fi

WORKDIR="${ROOT}/target/rpm/${TARGET}"
SOURCES_DIR="${WORKDIR}/SOURCES"
SPECS_DIR="${WORKDIR}/SPECS"
SOURCE_PARENT="${WORKDIR}/source"
SOURCE_ROOT="${SOURCE_PARENT}/${PACKAGE_NAME}-${RPM_VERSION}"
SPEC_FILE="${SPECS_DIR}/${PACKAGE_NAME}.spec"

rm -rf "${WORKDIR}"
mkdir -p "${SOURCES_DIR}" "${SPECS_DIR}" "${SOURCE_ROOT}"

install -m 0755 "${BINARY}" "${SOURCE_ROOT}/nono"
install -m 0644 "${ROOT}/README.md" "${SOURCE_ROOT}/README.md"
install -m 0644 "${ROOT}/LICENSE" "${SOURCE_ROOT}/LICENSE"

tar -C "${SOURCE_PARENT}" -czf "${SOURCES_DIR}/${PACKAGE_NAME}-${RPM_VERSION}.tar.gz" "${PACKAGE_NAME}-${RPM_VERSION}"

cat > "${SPEC_FILE}" <<EOF
Name:           ${PACKAGE_NAME}
Version:        ${RPM_VERSION}
Release:        ${RPM_RELEASE}
Summary:        CLI for nono capability-based sandbox

License:        Apache-2.0
URL:            https://github.com/always-further/nono
Source0:        %{name}-%{version}.tar.gz

# This spec has no changelog; avoid distro macros trying to derive
# SOURCE_DATE_EPOCH from one.
%global source_date_epoch_from_changelog 0

# The release binary is already built by Cargo. Avoid host strip/debug steps,
# which can fail when packaging cross-compiled Linux binaries.
%global debug_package %{nil}
%global __brp_strip /bin/true
%global __brp_strip_lto /bin/true
%global __brp_strip_comment_note /bin/true
%global __brp_strip_static_archive /bin/true

%description
nono is a capability-based sandboxing system for running untrusted AI agents
with OS-enforced isolation.

%prep
%setup -q

%build

%install
install -Dm0755 nono %{buildroot}/usr/bin/nono

%files
/usr/bin/nono
%doc README.md
%license LICENSE
EOF

rpmbuild \
    --target "${RPM_ARCH}" \
    --define "_topdir ${WORKDIR}" \
    --define "dist %{nil}" \
    -bb "${SPEC_FILE}"

find "${WORKDIR}/RPMS" -name '*.rpm' -print
