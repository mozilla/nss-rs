#!/bin/sh
# Skip, don't fail, a platform whose system NSS is too old for nss-rs; a missing
# nss.pc is a broken install, so that fails. Usage: <min-version> <label>
set -eu

MIN_VERSION=${1:?a minimum NSS version is required}
LABEL=${2:?a platform label is required}

# Match build.rs: the pkg-config crate honours $PKG_CONFIG, else pkgconf.
if [ -z "${PKG_CONFIG:-}" ]; then
  if command -v pkg-config > /dev/null 2>&1; then
    PKG_CONFIG=pkg-config
  elif command -v pkgconf > /dev/null 2>&1; then
    PKG_CONFIG=pkgconf
  else
    echo "::error::No pkg-config on $LABEL; the NSS package install is broken"
    exit 1
  fi
fi

if ! "$PKG_CONFIG" --exists nss; then
  echo "::error::No nss.pc on $LABEL; the NSS package install is broken"
  exit 1
fi

if "$PKG_CONFIG" --atleast-version="$MIN_VERSION" nss; then
  exit 0
fi

REASON="Skipping $LABEL: system NSS $("$PKG_CONFIG" --modversion nss) is older than the required $MIN_VERSION"
echo "::warning::$REASON"
echo "### $REASON" > nss-skipped.md

# A VM shares no environment with the runner; its host reads nss-skipped.md.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat nss-skipped.md >> "$GITHUB_STEP_SUMMARY"; fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "skip=true" >> "$GITHUB_OUTPUT"; fi
