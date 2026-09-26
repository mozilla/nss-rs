// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmarks for complete TLS 1.3 handshakes between an in-memory client and server.

#![expect(clippy::unwrap_used, reason = "This is benchmark code.")]
#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use nss_rs::{
    AuthenticationStatus, Client, Server, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
    TLS_GRP_EC_SECP256R1, TLS_GRP_EC_X25519, constants::Group,
};
use test_fixture::{fixture_init, now};

/// Key exchange groups, with names used in benchmark IDs so that reports are readable.
const GROUPS: [(&str, Group); 2] = [
    ("x25519", TLS_GRP_EC_X25519),
    ("secp256r1", TLS_GRP_EC_SECP256R1),
];

fn setup(group: Group) -> (Client, Server) {
    let mut client = Client::new("server.example", true).unwrap();
    client.set_groups(&[group]).unwrap();
    let mut server = Server::new(&["key"]).unwrap();
    server.set_groups(&[group]).unwrap();
    (client, server)
}

/// Drive a full 1-RTT handshake to completion, returning the number of bytes exchanged.
fn handshake(client: &mut Client, server: &mut Server) -> usize {
    let now = now();
    let ch = client.handshake(now, &[]).unwrap();
    let sh = server.handshake(now, &ch).unwrap();
    let empty = client.handshake(now, &sh).unwrap();
    debug_assert!(empty.is_empty());
    client.authenticated(AuthenticationStatus::Ok);
    let fin = client.handshake(now, &[]).unwrap();
    let done = server.handshake(now, &fin).unwrap();
    debug_assert!(client.state().is_connected());
    debug_assert!(server.state().is_connected());
    ch.len() + sh.len() + fin.len() + done.len()
}

fn handshakes(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    for (name, grp) in GROUPS {
        // Full handshake, including creation of the client and server agents.
        group.bench_function(BenchmarkId::new("full", name), |b| {
            b.iter(|| {
                let (mut client, mut server) = setup(black_box(grp));
                handshake(&mut client, &mut server)
            });
        });

        // Handshake only, with agent creation excluded from the measurement.
        group.bench_function(BenchmarkId::new("handshake_only", name), |b| {
            b.iter_batched_ref(
                || setup(grp),
                |(client, server)| handshake(client, server),
                BatchSize::SmallInput,
            );
        });
    }

    // Client and server agent creation.
    group.bench_function("agent_setup", |b| {
        b.iter(|| setup(black_box(TLS_GRP_EC_X25519)));
    });

    // Handshake with a restricted cipher suite.
    for (name, suite) in [
        ("aes128gcm", TLS_AES_128_GCM_SHA256),
        ("chacha20poly1305", TLS_CHACHA20_POLY1305_SHA256),
    ] {
        group.bench_function(BenchmarkId::new("cipher_suite", name), |b| {
            b.iter_batched_ref(
                || {
                    let (mut client, server) = setup(TLS_GRP_EC_X25519);
                    client.set_ciphers(&[suite]).unwrap();
                    (client, server)
                },
                |(client, server)| handshake(client, server),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = { fixture_init(); Criterion::default() };
    targets = handshakes
}
criterion_main!(benches);
