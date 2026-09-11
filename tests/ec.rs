// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "these are tests")]

use nss_rs::{
    Error,
    ec::{
        Curve, convert_to_public, ecdh, ecdh_keygen, ecdh_keygen_extractable, ecdsa_keygen,
        ecdsa_keygen_extractable, eddsa_keygen, eddsa_keygen_extractable, export_pkcs8, export_raw,
        import_pkcs8, sign_ecdsa, sign_eddsa, verify_ecdsa, verify_eddsa,
    },
};
use test_fixture::fixture_init;

const DATA: &[u8] = b"sign me!";

#[test]
fn keygen_p256() {
    fixture_init();

    let key = ecdh_keygen(Curve::P256).unwrap();

    let raw = key.public.key_data().unwrap();
    assert_eq!(65, raw.len());
    assert_eq!(4, raw[0]);

    let alt = key.public.key_data_alt().unwrap();
    assert_eq!(67, alt.len());
    assert_eq!(&[4, 65, 4], &alt[0..3]);
    assert_eq!(&alt[2..], raw.as_slice());
}

#[test]
fn keygen_p384() {
    fixture_init();

    let key = ecdh_keygen(Curve::P384).unwrap();

    let raw = key.public.key_data().unwrap();
    assert_eq!(97, raw.len());
    assert_eq!(4, raw[0]);

    let alt = key.public.key_data_alt().unwrap();
    assert_eq!(99, alt.len());
    assert_eq!(&[4, 97, 4], &alt[0..3]);
    assert_eq!(&alt[2..], raw.as_slice());
}

#[test]
fn keygen_p521() {
    fixture_init();

    let key = ecdh_keygen(Curve::P521).unwrap();

    let raw = key.public.key_data().unwrap();
    assert_eq!(133, raw.len());
    assert_eq!(4, raw[0]);

    let alt = key.public.key_data_alt().unwrap();
    assert_eq!(136, alt.len());
    assert_eq!(&[4, 129, 133, 4], &alt[0..4]);
    assert_eq!(&alt[3..], raw.as_slice());
}

#[test]
fn keygen_ed25519() {
    fixture_init();

    let key = ecdsa_keygen(Curve::Ed25519).unwrap();

    // Not valid for HPKE because keyType = edKey
    assert!(key.public.key_data().is_err());
}

#[test]
fn keygen_x25519() {
    fixture_init();

    let key = ecdh_keygen(Curve::X25519).unwrap();

    assert_eq!(32, key.public.key_data().unwrap().len());
}

fn ecdh_check(curve: Curve, expected_len: usize) {
    fixture_init();

    let a = ecdh_keygen(curve).unwrap();
    let b = ecdh_keygen(curve).unwrap();
    let r1 = ecdh(&a.private, &b.public).unwrap();
    let r2 = ecdh(&b.private, &a.public).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(r1.len(), expected_len);
}

#[test]
fn ecdh_p256() {
    ecdh_check(Curve::P256, 32);
}

#[test]
fn ecdh_x25519() {
    ecdh_check(Curve::X25519, 32);
}

#[test]
fn ecdh_p384() {
    ecdh_check(Curve::P384, 48);
}

#[test]
fn ecdh_p521() {
    ecdh_check(Curve::P521, 66);
}

#[test]
fn ecdh_ed25519() {
    fixture_init();
    assert_eq!(
        ecdh_keygen(Curve::Ed25519).unwrap_err(),
        Error::UnsupportedCurve
    );
}

#[test]
fn clone() {
    fixture_init();

    let a1 = ecdh_keygen(Curve::P256).expect("ecdh_keygen");
    let a2 = a1.clone();

    let a1_debug = format!("{a1:?}");
    let a2_debug = format!("{a2:?}");
    assert_eq!(a1_debug, a2_debug);

    let b = ecdh_keygen(Curve::P256).expect("ecdh_keygen");

    let a1_b = ecdh(&a1.private, &b.public).expect("a1_b/ecdh");
    let a2_b = ecdh(&a2.private, &b.public).expect("a2_b/ecdh");

    let b_a1 = ecdh(&b.private, &a1.public).expect("b_a1/ecdh");
    let b_a2 = ecdh(&b.private, &a2.public).expect("b_a2/ecdh");

    assert_eq!(a1_b, a2_b);
    assert_eq!(a1_b, b_a1);
    assert_eq!(a1_b, b_a2);
}

/// Confirm that PKCS#8 import and export works.
#[test]
fn pkcs8_ecdh() {
    fixture_init();

    for curve in [Curve::P256, Curve::P384, Curve::P521, Curve::X25519] {
        let k = ecdh_keygen_extractable(curve).unwrap();

        let buf = export_pkcs8(&k.private).unwrap();
        let imported = import_pkcs8(&buf).unwrap();

        let other = ecdh_keygen(curve).unwrap();

        let s1 = ecdh(&k.private, &other.public).unwrap();
        let s2 = ecdh(&imported, &other.public).unwrap();
        assert_eq!(s1, s2);
    }
}

#[test]
fn pkcs8_ecdsa() {
    fixture_init();

    for curve in [Curve::P256, Curve::P384, Curve::P521] {
        let k = ecdsa_keygen_extractable(curve).unwrap();
        let buf = export_pkcs8(&k.private).unwrap();
        let imported = import_pkcs8(&buf).unwrap();
        let converted = convert_to_public(&imported).unwrap();

        let signature = sign_ecdsa(&imported, DATA).unwrap();
        assert!(verify_ecdsa(&converted, DATA, &signature).unwrap());
    }
}
#[test]
fn pkcs8_ed25519() {
    fixture_init();

    let k = eddsa_keygen_extractable(Curve::Ed25519).unwrap();
    let buf = export_pkcs8(&k.private).unwrap();
    let imported = import_pkcs8(&buf).unwrap();
    let converted = convert_to_public(&imported).unwrap();

    let signature = sign_eddsa(&imported, DATA).unwrap();
    assert!(verify_eddsa(&converted, DATA, &signature).unwrap());
}

#[test]
fn export_raw_extractable() {
    fixture_init();

    let kp = ecdh_keygen_extractable(Curve::X25519).expect("ecdh_keygen");
    let raw = export_raw(&kp.private).expect("export should work");
    assert!(!raw.is_empty());
}

#[test]
fn export_raw_nonextractable() {
    fixture_init();

    let kp = ecdh_keygen(Curve::X25519).expect("ecdh_keygen");
    export_raw(&kp.private).expect_err("should not be extractable");
}

fn ecdsa_check(curve: Curve, expected_len: usize) {
    fixture_init();

    let a = ecdsa_keygen(curve).unwrap();
    let signature = sign_ecdsa(&a.private, DATA).unwrap();
    assert_eq!(signature.len(), expected_len);
    assert!(verify_ecdsa(&a.public, DATA, &signature).unwrap());

    assert!(!verify_ecdsa(&a.public, b"not DATA", &signature).unwrap());
    let mut tampered = signature;
    tampered[0] ^= 1;
    assert!(!verify_ecdsa(&a.public, DATA, &tampered).unwrap());
}

#[test]
fn ecdsa_p256() {
    ecdsa_check(Curve::P256, 64);
}

#[test]
fn ecdsa_p384() {
    ecdsa_check(Curve::P384, 96);
}

#[test]
fn ecdsa_p521() {
    ecdsa_check(Curve::P521, 132);
}

#[test]
fn ecdsa_x25519() {
    fixture_init();
    assert_eq!(
        ecdsa_keygen(Curve::X25519).unwrap_err(),
        Error::UnsupportedCurve
    );
}

#[test]
fn ed25519() {
    fixture_init();

    let a = eddsa_keygen(Curve::Ed25519).unwrap();
    let signature = sign_eddsa(&a.private, DATA).unwrap();
    assert_eq!(signature.len(), 64);
    assert!(verify_eddsa(&a.public, DATA, &signature).unwrap());

    assert!(!verify_eddsa(&a.public, b"not DATA", &signature).unwrap());
    let mut tampered = signature;
    tampered[0] ^= 1;
    assert!(!verify_eddsa(&a.public, DATA, &tampered).unwrap());
}
