# Threat model

## What this project does and where untrusted input enters

`nss-rs` is the Rust API to NSS used by Firefox. It provides TLS 1.3 for QUIC (used by neqo, and so for all HTTP/3
traffic in Firefox), ECH, HPKE, AEAD and header protection, HKDF, HMAC, signatures and EC, and wraps the NSS C API
through bindgen bindings and `unsafe` FFI. The `blapi` feature calls freebl directly for record protection, bypassing
the PKCS#11 session layer.

Data from the peer is untrusted, including before the handshake has authenticated it. It enters through:

- `agentio.rs` and `agent.rs`: handshake records passed into NSS, and the callbacks NSS makes back into Rust
  (certificate authentication, alerts, secrets, ECH status).
- `ext.rs`: TLS extension data handed to `ExtensionHandler`s.
- `cert.rs`: the peer's certificate chain, stapled OCSP responses and SCTs.
- `ech.rs` and `hpke.rs`: ECH configs from DNS and `retry_configs` from the server, HPKE public keys and ciphertexts.
- `aead/` and `hp/`: ciphertexts, tags and samples from the network, with and without `blapi`.
- `selfencrypt.rs`: tokens that the application issued but that are returned by the peer (e.g. QUIC Retry and
  NEW_TOKEN).
- `replay.rs`: anti-replay checks for 0-RTT.

The application calling the API (neqo, Firefox) is trusted; data from the peer is not.

## Components that matter most / least

- Most important: client-side code paths, and every `unsafe` block and FFI call, including pointer, length and
  lifetime handling across the boundary to NSS and the `blapi` path in `freebl/` and `aead/recprot_blapi.rs`.
- In scope but lower priority: server-side code paths (Firefox does not ship a QUIC server).
- Out of scope: `test-fixture`, `benches`, and anything that needs the `bench`, `disable-encryption`,
  `disable-random` or `gecko` features.
- NSS itself: in scope only where `nss-rs` misuses it, or where a bug in it is reachable through `nss-rs` with
  peer-controlled data. NSS is scanned separately.

## How to exercise it

- `cargo test --locked --workspace` runs the test suite; `--features blapi` adds the freebl path (run it with
  `-- --test-threads=1`). Both are prebuilt in this image, against NSS built from the release pinned in
  `Cargo.toml`.
- `test-fixture` initialises NSS with the test certificate database in `test-fixture/db`; `tests/handshake.rs` and
  `tests/common/` drive client/server handshakes, which are the easiest way to write a reproducer as a Rust test.

## How you rate severity

### Critical or high

Memory corruption that a peer controls and that may lead to code execution is critical; so is a bypass of record
protection or peer authentication.

- Memory safety issues reachable with peer-controlled data, including use-after-free, double free or out-of-bounds
  access across the FFI boundary.
- Breaking a TLS or QUIC security property: accepting an unauthenticated certificate, misreporting the authentication
  or ECH outcome to the application, leaking the inner ClientHello, using or exposing keys or secrets that should have
  been discarded or zeroized, accepting a forged AEAD tag or `selfencrypt` token, or accepting replayed 0-RTT data.
- Results that differ between the `blapi` and the PKCS#11 path for the same input.
- A peer-reachable `debug_assert!` that guards memory safety or one of the properties above. Tests enable debug
  assertions; Firefox release builds do not.

### Low

These should still be reported:

- Denial of service: panics, aborts, infinite loops, and peer-driven unbounded memory or CPU use. A panic without
  memory corruption is a denial of service, not a memory-safety issue (Mozilla rates these sec-low, see
  https://wiki.mozilla.org/Security_Severity_Ratings/Client).
- Peer-reachable `debug_assert!` failures without the consequences above.
- Unsoundness that requires the application to misuse the API.
- Leaks of NSS objects or memory.

Issues only reachable in server code rate one level lower than the same issue in client code.

## Reports

- Include a reproducer, preferably a Rust test using `test-fixture`, and the exact commit.
- Proposed patches should be minimal, follow the existing code style, be formatted with `cargo +nightly fmt` and pass
  `cargo clippy --locked --all-targets -- -D warnings`.
