// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmarks for the code the `blapi` feature switches from PKCS#11 to freebl.
//! Group names carry the backend so both builds can be reported side by side.

#![expect(clippy::unwrap_used, reason = "This is benchmark code.")]
#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

mod common;

use std::hint::black_box;

use common::{CIPHERS, DATA, SIZES, secret};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use nss_rs::{
    Mode, RecordProtection, RecordProtectionOps as _,
    constants::{TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3},
    hp,
    selfencrypt::SelfEncrypt,
};
use test_fixture::fixture_init;

const BACKEND: &str = if cfg!(feature = "blapi") {
    "blapi"
} else {
    "pkcs11"
};

const AAD: &[u8] = b"associated data";

fn aead(c: &mut Criterion) {
    let secret = secret();
    let rp = |cipher, mode| {
        RecordProtection::new(TLS_VERSION_1_3, cipher, &secret, "quic ", mode).unwrap()
    };
    let mut group = c.benchmark_group(format!("aead/{BACKEND}"));
    for (name, cipher) in CIPHERS {
        group.bench_function(BenchmarkId::new("new", name), |b| {
            b.iter(|| rp(black_box(cipher), Mode::Encrypt));
        });

        let (enc, dec) = (rp(cipher, Mode::Encrypt), rp(cipher, Mode::Decrypt));
        for size in SIZES {
            let pt = vec![0x5a; size];
            let mut ct = vec![0; size + enc.expansion()];
            enc.encrypt(0, AAD, &pt, &mut ct).unwrap();
            let mut out = vec![0; ct.len()];

            group.bench_function(BenchmarkId::new(format!("encrypt/{name}"), size), |b| {
                b.iter(|| enc.encrypt(0, AAD, black_box(&pt), &mut out).unwrap().len());
            });
            group.bench_function(BenchmarkId::new(format!("decrypt/{name}"), size), |b| {
                b.iter(|| dec.decrypt(0, AAD, black_box(&ct), &mut out).unwrap().len());
            });

            // The in-place variants are what QUIC packet protection uses.
            let mut buf = vec![0x5a; size + enc.expansion()];
            group.bench_function(
                BenchmarkId::new(format!("encrypt_in_place/{name}"), size),
                |b| {
                    b.iter(|| enc.encrypt_in_place(0, AAD, black_box(&mut buf)).unwrap());
                },
            );
            group.bench_function(
                BenchmarkId::new(format!("decrypt_in_place/{name}"), size),
                |b| {
                    b.iter_batched_ref(
                        || ct.clone(),
                        |buf| dec.decrypt_in_place(0, AAD, black_box(buf)).unwrap(),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
    group.finish();
}

/// QUIC Retry integrity tag: AES-128-GCM over an empty plaintext.
fn retry(c: &mut Criterion) {
    let secret = secret();
    let rp = |mode| {
        RecordProtection::new(
            TLS_VERSION_1_3,
            TLS_AES_128_GCM_SHA256,
            &secret,
            "quic ",
            mode,
        )
        .unwrap()
    };
    let (enc, dec) = (rp(Mode::Encrypt), rp(Mode::Decrypt));
    // Retry pseudo-packet: ODCID, long header, CIDs and a token.
    let aad = [0x5a; 96];
    let mut tag = vec![0; enc.expansion()];
    enc.encrypt(0, &aad, &[], &mut tag).unwrap();
    let mut out = vec![0; enc.expansion()];

    let mut group = c.benchmark_group(format!("retry/{BACKEND}"));
    group.bench_function("tag", |b| {
        b.iter(|| {
            enc.encrypt(0, black_box(&aad), &[], &mut out)
                .unwrap()
                .len()
        });
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            dec.decrypt(0, black_box(&aad), &tag, &mut out)
                .unwrap()
                .len()
        });
    });
    group.finish();
}

fn header_protection(c: &mut Criterion) {
    let secret = secret();
    let key = |cipher| hp::Key::extract(TLS_VERSION_1_3, cipher, &secret, "hp").unwrap();
    let mut group = c.benchmark_group(format!("header_protection/{BACKEND}"));
    for (name, cipher) in CIPHERS {
        group.bench_function(BenchmarkId::new("extract", name), |b| {
            b.iter(|| key(black_box(cipher)));
        });

        let key = key(cipher);
        group.bench_function(BenchmarkId::new("mask", name), |b| {
            b.iter(|| key.mask(black_box(&[0x5a; hp::Key::SAMPLE_SIZE])).unwrap());
        });
    }
    group.finish();
}

fn self_encrypt(c: &mut Criterion) {
    let se = SelfEncrypt::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256).unwrap();
    let sealed = se.seal(AAD, DATA).unwrap();
    let mut group = c.benchmark_group(format!("self_encrypt/{BACKEND}"));
    group.bench_function("seal", |b| {
        b.iter(|| se.seal(AAD, black_box(DATA)).unwrap());
    });
    group.bench_function("open", |b| {
        b.iter(|| se.open(AAD, black_box(&sealed)).unwrap());
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = { fixture_init(); Criterion::default() };
    targets = aead, header_protection, retry, self_encrypt
}
criterion_main!(benches);
