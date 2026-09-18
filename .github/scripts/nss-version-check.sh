#!/bin/sh
# Check the system NSS against the minimum version nss-rs requires, so that CI
# can skip a platform whose NSS is too old instead of failing on it. Writes the
# reason as a job summary fragment to ./nss-skipped.md, which is also the
# caller's signal to skip; in a VM, the host publishes it after the run.
# POSIX sh, because this also runs on the BSDs and on Alpine.
# Usage: nss-version-check.sh <min-version> <label>
set -eu

MIN_VERSION=${1:?a minimum NSS version is required}
LABEL=${2:?a platform label is required}

if ! pkg-config --exists nss; then
  echo "::warning::No nss.pc on $LABEL, cannot check the NSS version"
  exit 0
fi

if pkg-config --atleast-version="$MIN_VERSION" nss; then
  exit 0
fi

REASON="Skipping $LABEL: system NSS $(pkg-config --modversion nss) is older than the required $MIN_VERSION"
echo "::warning::$REASON"
echo "### $REASON" > nss-skipped.md
