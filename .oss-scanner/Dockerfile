# Image for https://github.com/anthropics/oss-scanner. Everything the scanner may need must be fetched and built here;
# the scan itself runs offline.
FROM rust:1-trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev gyp ninja-build python-is-python3 jq \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy \
    && rustup toolchain install nightly --profile minimal --component rustfmt

COPY . /src
WORKDIR /src
# Image layers keep whole-second mtimes only; match that so cargo's prebuilt fingerprints stay fresh.
RUN find /src -exec touch -h -d "@$(date +%s)" {} +

# Build NSS from the release tarball pinned in Cargo.toml, so build.rs never needs to fetch it.
ENV NSS_DIR=/nss \
    NSS_TARGET=Release \
    NSS_PREBUILT=1 \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib
RUN set -eux; \
    eval "$(cargo metadata --locked --format-version=1 --no-deps -q \
        | jq -r '.packages[] | select(.name=="nss-rs") | .metadata.nss \
                 | "NSS_VERSION=" + .["min-version"], "NSS_SHA256=" + .sha256')"; \
    NSS_TAG=$(echo "$NSS_VERSION" | tr '.' '_'); \
    RELEASE_DIR="https://ftp.mozilla.org/pub/security/nss/releases/NSS_${NSS_TAG}_RTM/src"; \
    FILENAME=$(curl -fsSL "$RELEASE_DIR/SHA256SUMS" | grep -F "$NSS_SHA256 " | awk '{print $2}' | sed 's/^\*//'); \
    case "$FILENAME" in \
      nss-*-with-nspr-*.tar.gz) ;; \
      *) echo "No with-nspr artifact in NSS_${NSS_TAG}_RTM matches sha256 $NSS_SHA256" >&2; exit 1 ;; \
    esac; \
    curl -fL -o /tmp/nss.tar.gz "$RELEASE_DIR/$FILENAME"; \
    echo "$NSS_SHA256  /tmp/nss.tar.gz" | sha256sum -c; \
    tar xzf /tmp/nss.tar.gz --strip-components=1 -C /; \
    rm /tmp/nss.tar.gz; \
    "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 -Ddisable_ckbi=1 -Ddisable_fips=1 -o

# Fetch every dependency and prebuild the tests with and without blapi, because the agent has only 2 CPUs.
ENV CARGO_NET_OFFLINE=true
RUN CARGO_NET_OFFLINE=false cargo fetch --locked \
    && cargo build --locked --workspace --all-targets \
    && cargo test --locked --workspace --no-run \
    && cargo test --locked --workspace --features blapi --no-run

# Check the image works, but don't fail the build on test failures.
# blapi unit tests can crash when run in parallel, so run them single-threaded.
RUN { cargo test --locked --workspace && cargo test --locked --workspace --features blapi -- --test-threads=1; } \
    || echo "WARNING: cargo test reported failures"
