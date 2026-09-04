#!/usr/bin/env bash
# Build the NSS checkout at $NSS_DIR, then build and test nss-rs against it.
# Expects the environment mozilla/actions/nss sets up with 'deps-only'. Also the
# `git bisect run` predicate, so it runs from an arbitrary cwd and must not let
# one revision's artifacts decide the next revision's verdict.
set -o pipefail

: "${NSS_DIR:?set by mozilla/actions/nss}"
: "${NSS_BUILD_FLAGS:?set by mozilla/actions/nss}"
: "${NSS_RS_DIR:?must point at the nss-rs checkout}"

# build.rs reads $NSS_DIR/../dist, so a stale tree would mask a failed build.
rm -rf "${NSS_DIR}/../dist"
[ "${SCCACHE_CC:-}" ] && [ "${SCCACHE_CXX:-}" ] && export CC="$SCCACHE_CC" CXX="$SCCACHE_CXX"
# Conditional, because an empty CFLAGS on Windows would override MSVC defaults.
[ -n "${NSS_BUILD_CFLAGS:-}" ] && export CFLAGS="$NSS_BUILD_CFLAGS"
# shellcheck disable=SC2086
"$NSS_DIR/build.sh" $NSS_BUILD_FLAGS || exit 1

cd "$NSS_RS_DIR" || exit 1
# Nothing tells cargo that dist changed, so force the bindings to regenerate.
cargo clean -p nss-rs
cargo test --locked
