// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(not(feature = "disable-encryption"))]
#![cfg(test)]

use nss_rs::{Error, aead::AeadAlgorithms, hkdf::HkdfAlgorithm, selfencrypt::SelfEncrypt};
use test_fixture::fixture_init;

#[test]
fn se_create() {
    fixture_init();
    SelfEncrypt::new(HkdfAlgorithm::HKDF_SHA2_256, AeadAlgorithms::Aes128Gcm)
        .expect("constructor works");
}

const PLAINTEXT: &[u8] = b"PLAINTEXT";
const AAD: &[u8] = b"AAD";

fn sealed() -> (SelfEncrypt, Vec<u8>) {
    fixture_init();
    let se = SelfEncrypt::new(HkdfAlgorithm::HKDF_SHA2_256, AeadAlgorithms::Aes128Gcm).unwrap();
    let sealed = se.seal(AAD, PLAINTEXT).expect("sealing works");
    (se, sealed)
}

#[test]
fn seal_open() {
    let (se, sealed) = sealed();
    let opened = se.open(AAD, &sealed).expect("opening works");
    assert_eq!(&opened[..], PLAINTEXT);
}

#[test]
fn seal_rotate_open() {
    let (mut se, sealed) = sealed();
    se.rotate().expect("rotate should be infallible");
    let opened = se.open(AAD, &sealed).expect("opening works");
    assert_eq!(&opened[..], PLAINTEXT);
}

#[test]
fn seal_rotate_twice_open() {
    let (mut se, sealed) = sealed();
    se.rotate().expect("rotate should be infallible");
    se.rotate().expect("rotate should be infallible");
    let res = se.open(AAD, &sealed);
    assert_eq!(res.unwrap_err(), Error::SelfEncrypt);
}

#[test]
fn damage_version() {
    let (se, mut sealed) = sealed();
    sealed[0] ^= 0x80;
    let res = se.open(AAD, &sealed);
    assert_eq!(res.unwrap_err(), Error::SelfEncrypt);
}

fn assert_bad_data<T: std::fmt::Debug>(res: Result<T, Error>) {
    let Err(Error::Nss { name, .. }) = res else {
        panic!("expected SEC_ERROR_BAD_DATA, got {res:?}");
    };
    assert_eq!(name, "SEC_ERROR_BAD_DATA");
}

#[test]
fn damage_salt() {
    let (se, mut sealed) = sealed();
    sealed[4] ^= 0x10;
    let res = se.open(AAD, &sealed);
    assert_bad_data(res);
}

#[test]
fn damage_ciphertext() {
    let (se, mut sealed) = sealed();
    sealed[20] ^= 0x2f;
    let res = se.open(AAD, &sealed);
    assert_bad_data(res);
}

#[test]
fn damage_auth_tag() {
    let (se, mut sealed) = sealed();
    let idx = sealed.len() - 1;
    sealed[idx] ^= 0x3;
    let res = se.open(AAD, &sealed);
    assert_bad_data(res);
}

#[test]
fn truncate() {
    let (se, sealed) = sealed();
    let res = se.open(AAD, &sealed[0..(sealed.len() - 1)]);
    assert_bad_data(res);
}

#[test]
fn truncate_header() {
    let (se, _) = sealed();
    // Ciphertext too short to contain the salt (needs 2 byte header + 16 byte salt).
    let res = se.open(AAD, &[1, 0, 0, 0, 0]);
    assert_eq!(res.unwrap_err(), Error::SelfEncrypt);
}

#[test]
fn seal_open_all_algorithms() {
    fixture_init();
    for kdf in [
        HkdfAlgorithm::HKDF_SHA2_256,
        HkdfAlgorithm::HKDF_SHA2_384,
        HkdfAlgorithm::HKDF_SHA2_512,
    ] {
        for aead in [
            AeadAlgorithms::Aes128Gcm,
            AeadAlgorithms::Aes256Gcm,
            AeadAlgorithms::ChaCha20Poly1305,
        ] {
            let se = SelfEncrypt::new(kdf, aead).unwrap();
            let sealed = se.seal(AAD, PLAINTEXT).unwrap();
            assert_eq!(
                &se.open(AAD, &sealed).unwrap()[..],
                PLAINTEXT,
                "{kdf:?} {aead:?}"
            );
        }
    }
}
