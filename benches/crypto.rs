// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmarks for the symmetric and asymmetric cryptographic primitives.

#![expect(clippy::unwrap_used, reason = "This is benchmark code.")]
#![expect(
    clippy::wildcard_imports,
    reason = "Benchmark groups share the parent scope."
)]

use divan::{Bencher, black_box};
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

fn main() {
    fixture_init();
    divan::main();
}

/// Cipher suite names, used as benchmark arguments so that reports are readable.
const CIPHERS: [&str; 3] = ["aes128gcm", "aes256gcm", "chacha20poly1305"];

fn cipher(name: &str) -> Cipher {
    match name {
        "aes128gcm" => TLS_AES_128_GCM_SHA256,
        "aes256gcm" => TLS_AES_256_GCM_SHA384,
        "chacha20poly1305" => TLS_CHACHA20_POLY1305_SHA256,
        _ => unreachable!("unknown cipher {name}"),
    }
}

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

mod aead {
    use super::*;

    #[divan::bench(args = CIPHERS)]
    fn new(name: &str) -> RecordProtection {
        let secret = secret();
        RecordProtection::new(
            TLS_VERSION_1_3,
            cipher(black_box(name)),
            &secret,
            "quic ",
            Mode::Encrypt,
        )
        .unwrap()
    }

    #[divan::bench(args = CIPHERS, consts = SIZES)]
    fn encrypt<const N: usize>(bencher: Bencher, name: &str) {
        let enc = record_protection(cipher(name), Mode::Encrypt);
        let pt = payload(N);
        let mut out = vec![0; N + enc.expansion()];
        bencher.bench_local(|| {
            let ct = enc
                .encrypt(black_box(1), black_box(AAD), black_box(&pt), &mut out)
                .unwrap();
            black_box(ct.len());
        });
    }

    #[divan::bench(args = CIPHERS, consts = SIZES)]
    fn decrypt<const N: usize>(bencher: Bencher, name: &str) {
        let enc = record_protection(cipher(name), Mode::Encrypt);
        let dec = record_protection(cipher(name), Mode::Decrypt);
        let pt = payload(N);
        let mut ct = vec![0; N + enc.expansion()];
        let ct_len = enc.encrypt(1, AAD, &pt, &mut ct).unwrap().len();
        ct.truncate(ct_len);
        let mut out = vec![0; ct_len];
        bencher.bench_local(|| {
            let pt = dec
                .decrypt(black_box(1), black_box(AAD), black_box(&ct), &mut out)
                .unwrap();
            black_box(pt.len());
        });
    }
}

mod header_protection {
    use super::*;

    fn make_hp(cipher: Cipher) -> hp::Key {
        let ikm = hkdf::import_key(TLS_VERSION_1_3, &[0; 16]).unwrap();
        let prk = hkdf::extract(TLS_VERSION_1_3, cipher, None, &ikm).unwrap();
        hp::Key::extract(TLS_VERSION_1_3, cipher, &prk, "hp").unwrap()
    }

    #[divan::bench(args = CIPHERS)]
    fn extract(name: &str) -> hp::Key {
        make_hp(cipher(black_box(name)))
    }

    #[divan::bench(args = CIPHERS)]
    fn mask(bencher: Bencher, name: &str) {
        let key = make_hp(cipher(name));
        let sample = [0x5a; hp::Key::SAMPLE_SIZE];
        bencher.bench_local(|| key.mask(black_box(&sample)).unwrap());
    }
}

mod key_schedule {
    use super::*;

    #[divan::bench(args = CIPHERS)]
    fn extract(bencher: Bencher, name: &str) {
        let cipher = cipher(name);
        let ikm = secret();
        let salt = secret();
        bencher.bench_local(|| {
            hkdf::extract(TLS_VERSION_1_3, black_box(cipher), Some(&salt), &ikm).unwrap()
        });
    }

    #[divan::bench(args = CIPHERS)]
    fn expand_label(bencher: Bencher, name: &str) {
        let cipher = cipher(name);
        let prk = hkdf::extract(TLS_VERSION_1_3, cipher, None, &secret()).unwrap();
        bencher.bench_local(|| {
            hkdf::expand_label(
                TLS_VERSION_1_3,
                black_box(cipher),
                &prk,
                &[],
                "tls13 c hs traffic",
            )
            .unwrap()
        });
    }
}

mod digest {
    use super::*;

    const HASHES: [HashAlgorithm; 3] = [
        HashAlgorithm::SHA2_256,
        HashAlgorithm::SHA2_384,
        HashAlgorithm::SHA2_512,
    ];

    #[divan::bench(args = HASHES, consts = SIZES)]
    fn sha2<const N: usize>(bencher: Bencher, alg: &HashAlgorithm) {
        let data = payload(N);
        bencher.bench_local(|| hash(black_box(alg), black_box(&data)).unwrap());
    }

    #[divan::bench(consts = SIZES)]
    fn hmac_sha256<const N: usize>(bencher: Bencher) {
        let alg = HmacAlgorithm::HMAC_SHA2_256;
        let key = alg.import_key(SECRET).unwrap();
        let data = payload(N);
        bencher.bench_local(|| alg.hmac(&key, black_box(&data)).unwrap());
    }
}

mod self_encrypt {
    use super::*;

    const PLAINTEXT: &[u8] = b"a resumption token or other opaque server state";

    #[divan::bench]
    fn seal(bencher: Bencher) {
        let se = SelfEncrypt::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256).unwrap();
        bencher.bench_local(|| se.seal(black_box(AAD), black_box(PLAINTEXT)).unwrap());
    }

    #[divan::bench]
    fn open(bencher: Bencher) {
        let se = SelfEncrypt::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256).unwrap();
        let sealed = se.seal(AAD, PLAINTEXT).unwrap();
        bencher.bench_local(|| se.open(black_box(AAD), black_box(&sealed)).unwrap());
    }
}

mod ec {
    use super::*;

    const ECDH_CURVES: [EcCurve; 3] = [EcCurve::X25519, EcCurve::P256, EcCurve::P384];
    const MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

    #[divan::bench(args = ECDH_CURVES)]
    fn keygen(curve: &EcCurve) {
        black_box(ecdh_keygen(black_box(curve)).unwrap());
    }

    #[divan::bench(args = ECDH_CURVES)]
    fn ecdh_agree(bencher: Bencher, curve: &EcCurve) {
        let a = ecdh_keygen(curve).unwrap();
        let b = ecdh_keygen(curve).unwrap();
        bencher.bench_local(|| ecdh(&a.private, black_box(&b.public)).unwrap());
    }

    #[divan::bench]
    fn sign_p256(bencher: Bencher) {
        let kp = ecdh_keygen(&EcCurve::P256).unwrap();
        bencher.bench_local(|| sign_ecdsa(&kp.private, black_box(MESSAGE)).unwrap());
    }

    #[divan::bench]
    fn verify_p256(bencher: Bencher) {
        let kp = ecdh_keygen(&EcCurve::P256).unwrap();
        let sig = sign_ecdsa(&kp.private, MESSAGE).unwrap();
        bencher.bench_local(|| {
            assert!(verify_ecdsa(&kp.public, black_box(MESSAGE), black_box(&sig)).unwrap());
        });
    }

    #[divan::bench]
    fn sign_ed25519(bencher: Bencher) {
        let kp = ecdh_keygen(&EcCurve::Ed25519).unwrap();
        bencher.bench_local(|| sign_eddsa(&kp.private, black_box(MESSAGE)).unwrap());
    }

    #[divan::bench]
    fn verify_ed25519(bencher: Bencher) {
        let kp = ecdh_keygen(&EcCurve::Ed25519).unwrap();
        let sig = sign_eddsa(&kp.private, MESSAGE).unwrap();
        bencher.bench_local(|| {
            assert!(verify_eddsa(&kp.public, black_box(MESSAGE), black_box(&sig)).unwrap());
        });
    }
}
