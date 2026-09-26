// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmarks for the symmetric and asymmetric cryptographic primitives.

#![expect(clippy::unwrap_used, reason = "This is benchmark code.")]
#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use nss_rs::{
    Mode, RecordProtection, RecordProtectionOps as _, SymKey,
    constants::{
        Cipher, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
        TLS_VERSION_1_3,
    },
    ec::{EcCurve, ecdh, ecdh_keygen, sign_ecdsa, sign_eddsa, verify_ecdsa, verify_eddsa},
    hash::{HashAlgorithm, hash},
    hkdf,
    hmac::HmacAlgorithm,
    hp,
    selfencrypt::SelfEncrypt,
};
use test_fixture::fixture_init;

/// Cipher suites, with names used in benchmark IDs so that reports are readable.
const CIPHERS: [(&str, Cipher); 3] = [
    ("aes128gcm", TLS_AES_128_GCM_SHA256),
    ("aes256gcm", TLS_AES_256_GCM_SHA384),
    ("chacha20poly1305", TLS_CHACHA20_POLY1305_SHA256),
];

/// Payload sizes: a small QUIC packet, a typical MTU-sized packet and a
/// maximum-size TLS record.
const SIZES: [usize; 3] = [64, 1200, 16384];

const AAD: &[u8] = &[
    0xc1, 0xff, 0x00, 0x00, 0x12, 0x05, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00, 0x40,
    0x74, 0x00, 0x01,
];

const SECRET: &[u8] = &[
    0x47, 0xb2, 0xea, 0xea, 0x6c, 0x26, 0x6e, 0x32, 0xc0, 0x69, 0x7a, 0x9e, 0x2a, 0x89, 0x8b, 0xdf,
    0x5c, 0x4f, 0xb3, 0xe5, 0xac, 0x34, 0xf0, 0xe5, 0x49, 0xbf, 0x2c, 0x58, 0x58, 0x1a, 0x38, 0x11,
];

fn secret() -> SymKey {
    hkdf::import_key(TLS_VERSION_1_3, SECRET).unwrap()
}

fn record_protection(cipher: Cipher, mode: Mode) -> RecordProtection {
    RecordProtection::new(TLS_VERSION_1_3, cipher, &secret(), "quic ", mode).unwrap()
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    for (name, cipher) in CIPHERS {
        group.bench_function(BenchmarkId::new("new", name), |b| {
            let secret = secret();
            b.iter(|| {
                RecordProtection::new(
                    TLS_VERSION_1_3,
                    black_box(cipher),
                    &secret,
                    "quic ",
                    Mode::Encrypt,
                )
                .unwrap()
            });
        });

        for size in SIZES {
            let enc = record_protection(cipher, Mode::Encrypt);
            let pt = payload(size);
            group.bench_function(BenchmarkId::new(format!("encrypt/{name}"), size), |b| {
                let mut out = vec![0; size + enc.expansion()];
                b.iter(|| {
                    let ct = enc
                        .encrypt(black_box(1), black_box(AAD), black_box(&pt), &mut out)
                        .unwrap();
                    black_box(ct.len());
                });
            });

            let dec = record_protection(cipher, Mode::Decrypt);
            let mut ct = vec![0; size + enc.expansion()];
            let ct_len = enc.encrypt(1, AAD, &pt, &mut ct).unwrap().len();
            ct.truncate(ct_len);
            group.bench_function(BenchmarkId::new(format!("decrypt/{name}"), size), |b| {
                let mut out = vec![0; ct_len];
                b.iter(|| {
                    let pt = dec
                        .decrypt(black_box(1), black_box(AAD), black_box(&ct), &mut out)
                        .unwrap();
                    black_box(pt.len());
                });
            });
        }
    }
    group.finish();
}

fn make_hp(cipher: Cipher) -> hp::Key {
    let ikm = hkdf::import_key(TLS_VERSION_1_3, &[0; 16]).unwrap();
    let prk = hkdf::extract(TLS_VERSION_1_3, cipher, None, &ikm).unwrap();
    hp::Key::extract(TLS_VERSION_1_3, cipher, &prk, "hp").unwrap()
}

fn header_protection(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_protection");
    for (name, cipher) in CIPHERS {
        group.bench_function(BenchmarkId::new("extract", name), |b| {
            b.iter(|| make_hp(black_box(cipher)));
        });

        let key = make_hp(cipher);
        let sample = [0x5a; hp::Key::SAMPLE_SIZE];
        group.bench_function(BenchmarkId::new("mask", name), |b| {
            b.iter(|| key.mask(black_box(&sample)).unwrap());
        });
    }
    group.finish();
}

fn key_schedule(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_schedule");
    for (name, cipher) in CIPHERS {
        let ikm = secret();
        let salt = secret();
        group.bench_function(BenchmarkId::new("extract", name), |b| {
            b.iter(|| {
                hkdf::extract(TLS_VERSION_1_3, black_box(cipher), Some(&salt), &ikm).unwrap()
            });
        });

        let prk = hkdf::extract(TLS_VERSION_1_3, cipher, None, &secret()).unwrap();
        group.bench_function(BenchmarkId::new("expand_label", name), |b| {
            b.iter(|| {
                hkdf::expand_label(
                    TLS_VERSION_1_3,
                    black_box(cipher),
                    &prk,
                    &[],
                    "tls13 c hs traffic",
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

fn digest(c: &mut Criterion) {
    const HASHES: [(&str, HashAlgorithm); 3] = [
        ("sha256", HashAlgorithm::SHA2_256),
        ("sha384", HashAlgorithm::SHA2_384),
        ("sha512", HashAlgorithm::SHA2_512),
    ];

    let mut group = c.benchmark_group("digest");
    for size in SIZES {
        let data = payload(size);
        for (name, alg) in &HASHES {
            group.bench_function(BenchmarkId::new(*name, size), |b| {
                b.iter(|| hash(black_box(alg), black_box(&data)).unwrap());
            });
        }

        let alg = HmacAlgorithm::HMAC_SHA2_256;
        let key = alg.import_key(SECRET).unwrap();
        group.bench_function(BenchmarkId::new("hmac_sha256", size), |b| {
            b.iter(|| alg.hmac(&key, black_box(&data)).unwrap());
        });
    }
    group.finish();
}

fn self_encrypt(c: &mut Criterion) {
    const PLAINTEXT: &[u8] = b"a resumption token or other opaque server state";

    let mut group = c.benchmark_group("self_encrypt");
    let se = SelfEncrypt::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256).unwrap();
    group.bench_function("seal", |b| {
        b.iter(|| se.seal(black_box(AAD), black_box(PLAINTEXT)).unwrap());
    });

    let sealed = se.seal(AAD, PLAINTEXT).unwrap();
    group.bench_function("open", |b| {
        b.iter(|| se.open(black_box(AAD), black_box(&sealed)).unwrap());
    });
    group.finish();
}

fn ec(c: &mut Criterion) {
    const ECDH_CURVES: [(&str, EcCurve); 3] = [
        ("x25519", EcCurve::X25519),
        ("p256", EcCurve::P256),
        ("p384", EcCurve::P384),
    ];
    const MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

    let mut group = c.benchmark_group("ec");
    for (name, curve) in &ECDH_CURVES {
        group.bench_function(BenchmarkId::new("keygen", name), |b| {
            b.iter(|| ecdh_keygen(black_box(curve)).unwrap());
        });

        let a = ecdh_keygen(curve).unwrap();
        let peer = ecdh_keygen(curve).unwrap();
        group.bench_function(BenchmarkId::new("ecdh", name), |b| {
            b.iter(|| ecdh(&a.private, black_box(&peer.public)).unwrap());
        });
    }

    let kp = ecdh_keygen(&EcCurve::P256).unwrap();
    let sig = sign_ecdsa(&kp.private, MESSAGE).unwrap();
    group.bench_function("sign_p256", |b| {
        b.iter(|| sign_ecdsa(&kp.private, black_box(MESSAGE)).unwrap());
    });
    group.bench_function("verify_p256", |b| {
        b.iter(|| {
            assert!(verify_ecdsa(&kp.public, black_box(MESSAGE), black_box(&sig)).unwrap());
        });
    });

    let kp = ecdh_keygen(&EcCurve::Ed25519).unwrap();
    let sig = sign_eddsa(&kp.private, MESSAGE).unwrap();
    group.bench_function("sign_ed25519", |b| {
        b.iter(|| sign_eddsa(&kp.private, black_box(MESSAGE)).unwrap());
    });
    group.bench_function("verify_ed25519", |b| {
        b.iter(|| {
            assert!(verify_eddsa(&kp.public, black_box(MESSAGE), black_box(&sig)).unwrap());
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = { fixture_init(); Criterion::default() };
    targets = aead, header_protection, key_schedule, digest, self_encrypt, ec
}
criterion_main!(benches);
