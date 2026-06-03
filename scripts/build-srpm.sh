#!/usr/bin/env bash
# Build a source RPM suitable for Fedora COPR.
# Usage: scripts/build-srpm.sh [version]

set -euo pipefail

usage() {
    echo "Usage: $0 [version]" >&2
}

if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi

for tool in cargo git rpmbuild tar; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Error: ${tool} is required to build the source RPM" >&2
        exit 1
    fi
done

ROOT="$(git rev-parse --show-toplevel)"
if ! git -C "${ROOT}" diff-index --quiet HEAD --; then
    echo "Warning: You have uncommitted changes. 'git archive' will only package committed changes from HEAD." >&2
fi
PACKAGE_NAME="nono-cli"
VERSION="${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${ROOT}/crates/nono-cli/Cargo.toml" | head -n 1)}"
VERSION="${VERSION#v}"

if [[ -z "${VERSION}" ]]; then
    echo "Error: could not determine nono-cli version" >&2
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

WORKDIR="${ROOT}/target/rpm/copr"
SOURCES_DIR="${WORKDIR}/SOURCES"
SPECS_DIR="${WORKDIR}/SPECS"
SOURCE_PARENT="${WORKDIR}/source"
SOURCE_NAME="nono-${RPM_VERSION}"
SOURCE_ROOT="${SOURCE_PARENT}/${SOURCE_NAME}"
SPEC_TEMPLATE="${ROOT}/packaging/rpm/${PACKAGE_NAME}.spec.in"
SPEC_FILE="${SPECS_DIR}/${PACKAGE_NAME}.spec"

if [[ ! -f "${SPEC_TEMPLATE}" ]]; then
    echo "Error: spec template not found: ${SPEC_TEMPLATE}" >&2
    exit 1
fi

rm -rf "${WORKDIR}"
mkdir -p "${SOURCES_DIR}" "${SPECS_DIR}" "${SOURCE_PARENT}"

git -C "${ROOT}" archive --format=tar --prefix="${SOURCE_NAME}/" HEAD | tar -C "${SOURCE_PARENT}" -xf -

mkdir -p "${SOURCE_ROOT}/.cargo"
(
    cd "${SOURCE_ROOT}"
    cargo vendor --quiet --locked --versioned-dirs vendor >> .cargo/config.toml
)

sed \
    -e "s|@RPM_VERSION@|${RPM_VERSION}|g" \
    -e "s|@RPM_RELEASE@|${RPM_RELEASE}|g" \
    "${SPEC_TEMPLATE}" > "${SPEC_FILE}"

tar -C "${SOURCE_PARENT}" -czf "${SOURCES_DIR}/${SOURCE_NAME}.tar.gz" "${SOURCE_NAME}"

rpmbuild \
    --define "_topdir ${WORKDIR}" \
    --define "dist %{nil}" \
    -bs "${SPEC_FILE}"

find "${WORKDIR}/SRPMS" -name '*.src.rpm' -print
