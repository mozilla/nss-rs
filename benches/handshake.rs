// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmarks for complete TLS 1.3 handshakes between an in-memory client and server.

#![expect(clippy::unwrap_used, reason = "This is benchmark code.")]

use divan::{Bencher, black_box};
use nss_rs::{
    AuthenticationStatus, Client, Server, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
    TLS_GRP_EC_SECP256R1, TLS_GRP_EC_X25519, constants::Group,
};
use test_fixture::{fixture_init, now};

fn main() {
    fixture_init();
    divan::main();
}

/// Key exchange group names, used as benchmark arguments so that reports are readable.
const GROUPS: [&str; 2] = ["x25519", "secp256r1"];

fn group(name: &str) -> Group {
    match name {
        "x25519" => TLS_GRP_EC_X25519,
        "secp256r1" => TLS_GRP_EC_SECP256R1,
        _ => unreachable!("unknown group {name}"),
    }
}

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

/// Full handshake, including creation of the client and server agents.
#[divan::bench(args = GROUPS)]
fn full(bencher: Bencher, name: &str) {
    let group = group(name);
    bencher.bench_local(|| {
        let (mut client, mut server) = setup(black_box(group));
        handshake(&mut client, &mut server)
    });
}

/// Handshake only, with agent creation excluded from the measurement.
#[divan::bench(args = GROUPS)]
fn handshake_only(bencher: Bencher, name: &str) {
    let group = group(name);
    bencher
        .with_inputs(|| setup(group))
        .bench_local_values(|(mut client, mut server)| {
            handshake(&mut client, &mut server);
            (client, server)
        });
}

/// Client and server agent creation.
#[divan::bench]
fn agent_setup() -> (Client, Server) {
    setup(TLS_GRP_EC_X25519)
}

/// Handshake with a restricted cipher suite.
#[divan::bench(args = ["aes128gcm", "chacha20poly1305"])]
fn cipher_suite(bencher: Bencher, name: &str) {
    let suite = match name {
        "aes128gcm" => TLS_AES_128_GCM_SHA256,
        "chacha20poly1305" => TLS_CHACHA20_POLY1305_SHA256,
        _ => unreachable!("unknown cipher {name}"),
    };
    bencher
        .with_inputs(|| {
            let (mut client, server) = setup(TLS_GRP_EC_X25519);
            client.set_ciphers(&[suite]).unwrap();
            (client, server)
        })
        .bench_local_values(|(mut client, mut server)| {
            handshake(&mut client, &mut server);
            (client, server)
        });
}
