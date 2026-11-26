// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use nss_rs::{
    ec::{
        EcCurve, ecdh, ecdh_keygen, export_ec_private_key_from_raw, import_ec_public_key_from_spki,
    },
    generate_ech_keys,
};
use test_fixture::fixture_init;

#[test]
fn clone() {
    fixture_init();

    let a1 = ecdh_keygen(&EcCurve::P256).expect("ecdh_keygen");
    let a2 = a1.clone();

    let a1_debug = format!("{a1:?}");
    let a2_debug = format!("{a2:?}");
    assert_eq!(a1_debug, a2_debug);

    let b = ecdh_keygen(&EcCurve::P256).expect("ecdh_keygen");

    let a1_b = ecdh(&a1.private, &b.public).expect("a1_b/ecdh");
    let a2_b = ecdh(&a2.private, &b.public).expect("a2_b/ecdh");

    let b_a1 = ecdh(&b.private, &a1.public).expect("b_a1/ecdh");
    let b_a2 = ecdh(&b.private, &a2.public).expect("b_a2/ecdh");

    assert_eq!(a1_b, a2_b);
    assert_eq!(a1_b, b_a1);
    assert_eq!(a1_b, b_a2);
}

#[test]
fn export_raw_extractable() {
    fixture_init();

    let kp = ecdh_keygen(&EcCurve::X25519).expect("ecdh_keygen");
    let raw = export_ec_private_key_from_raw(&kp.private).expect("export");
    assert!(!raw.is_empty());
}

#[test]
fn export_raw_sensitive_reports_failure() {
    fixture_init();

    // ECH keys are generated sensitive, so CKA_VALUE cannot be read back. The
    // export must surface that NSS failure rather than returning an empty key.
    let (sk, _pk) = generate_ech_keys().expect("generate_ech_keys");
    assert!(export_ec_private_key_from_raw(&sk).is_err());
}

#[test]
fn keygen_p256() {
    fixture_init();

    let key = ecdh_keygen(&EcCurve::P256).unwrap();

    let raw = key.public.key_data().unwrap();
    assert_eq!(65, raw.len());
    assert_eq!(4, raw[0]);

    let alt = key.public.key_data_alt().unwrap();
    assert_eq!(67, alt.len());
    assert_eq!(&[4, 65, 4], &alt[0..3]);
    assert_eq!(&alt[2..], raw);
}

#[test]
fn keygen_p384() {
    fixture_init();

    let key = ecdh_keygen(&EcCurve::P384).unwrap();

    let raw = key.public.key_data().unwrap();
    assert_eq!(97, raw.len());
    assert_eq!(4, raw[0]);

    let alt = key.public.key_data_alt().unwrap();
    assert_eq!(99, alt.len());
    assert_eq!(&[4, 97, 4], &alt[0..3]);
    assert_eq!(&alt[2..], raw);
}

#[test]
fn keygen_p521() {
    fixture_init();

    let key = ecdh_keygen(&EcCurve::P521).unwrap();

    let raw = key.public.key_data().unwrap();
    assert_eq!(133, raw.len());
    assert_eq!(4, raw[0]);

    let alt = key.public.key_data_alt().unwrap();
    assert_eq!(136, alt.len());
    assert_eq!(&[4, 129, 133, 4], &alt[0..4]);
    assert_eq!(&alt[3..], raw);
}

#[test]
fn keygen_ed25519() {
    fixture_init();

    let key = ecdh_keygen(&EcCurve::Ed25519).unwrap();

    // Not valid for HPKE because keyType = edKey
    assert!(key.public.key_data().is_err());
}

#[test]
fn keygen_x25519() {
    fixture_init();

    let key = ecdh_keygen(&EcCurve::X25519).unwrap();

    assert_eq!(32, key.public.key_data().unwrap().len());
}

/// Test for <https://github.com/mozilla/nss-rs/issues/136>
#[test]
fn compressed_keys() {
    const COMPRESSED_SPKI: [u8; 59] = [
        0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00, 0x03, 0xd1, 0xb1, 0x56,
        0xdb, 0x88, 0x0d, 0xb6, 0x31, 0x48, 0xb2, 0xe0, 0x81, 0xd5, 0xbe, 0xb6, 0x89, 0x66, 0x83,
        0x65, 0xb5, 0xaa, 0xf6, 0x6a, 0x7d, 0xaa, 0xb5, 0xf9, 0xeb, 0xaf, 0x0a, 0x08, 0xbc,
    ];

    const UNCOMPRESSED_SPKI: [u8; 91] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xd1, 0xb1, 0x56,
        0xdb, 0x88, 0x0d, 0xb6, 0x31, 0x48, 0xb2, 0xe0, 0x81, 0xd5, 0xbe, 0xb6, 0x89, 0x66, 0x83,
        0x65, 0xb5, 0xaa, 0xf6, 0x6a, 0x7d, 0xaa, 0xb5, 0xf9, 0xeb, 0xaf, 0x0a, 0x08, 0xbc, 0x28,
        0x6f, 0xb0, 0x08, 0x3e, 0x14, 0x82, 0x09, 0x4a, 0xec, 0x3c, 0x8f, 0xaf, 0x07, 0x9d, 0x13,
        0x6b, 0x3d, 0xb6, 0x62, 0x8b, 0xbe, 0x03, 0x5c, 0x73, 0xf4, 0xa2, 0x00, 0xde, 0xec, 0x80,
        0x93,
    ];

    let uncompressed_raw_key = &UNCOMPRESSED_SPKI[UNCOMPRESSED_SPKI.len() - 65..];

    fixture_init();
    let me = ecdh_keygen(&EcCurve::P256).expect("compressed keygen");

    // https://www.rfc-editor.org/info/rfc5480/#section-2.2
    // > Implementations ... MAY support the compressed form of the ECC public key.
    let compressed_key =
        import_ec_public_key_from_spki(&COMPRESSED_SPKI).expect("compressed import");

    // > Implementations ... MUST support the uncompressed form ... of the ECC public key.
    let uncompressed_key =
        import_ec_public_key_from_spki(&UNCOMPRESSED_SPKI).expect("uncompressed import");

    // ECDH with compressed key fails: "SEC_ERROR_INVALID_KEY", code: -8152,
    // desc: "The key does not support the requested operation."
    let compressed_ecdh = ecdh(&me.private, &compressed_key).expect("compressed ecdh");
    let uncompressed_ecdh = ecdh(&me.private, &uncompressed_key).expect("uncompressed ecdh");

    assert_eq!(
        uncompressed_ecdh, compressed_ecdh,
        "ECDH with compressed and uncommpressed key derives the same secret",
    );

    let uncompressed_key_data = uncompressed_key.key_data().expect("uncompressed key_data");
    assert_eq!(
        uncompressed_raw_key, uncompressed_key_data,
        "uncompressed_key_data is the raw SEC1-encoded uncompressed point",
    );

    // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1
    // > For P-256, P-384, and P-521, the SerializePublicKey() function of the KEM performs the
    // > **uncompressed** Elliptic-Curve-Point-to-Octet-String conversion according to [SECG].
    //
    // Fails: this retains the compressed value (33 bytes).
    let compressed_key_data = compressed_key.key_data().expect("compressed key_data");
    assert_eq!(
        uncompressed_raw_key, compressed_key_data,
        "compressed_key_data is the raw SEC1-encoded uncompressed point",
    );

    let uncompressed_key_data_alt = uncompressed_key
        .key_data_alt()
        .expect("uncompressed key_data_alt");
    assert_eq!(67, uncompressed_key_data_alt.len());
    assert_eq!(
        uncompressed_raw_key,
        &uncompressed_key_data_alt[2..],
        "uncompressed_key_data_alt is the DER serialization of the raw SEC1-encoded uncompressed point",
    );

    let compressed_key_data_alt = compressed_key
        .key_data_alt()
        .expect("compressed key_data_alt");
    assert_eq!(67, compressed_key_data_alt.len());
    assert_eq!(
        uncompressed_raw_key,
        &compressed_key_data_alt[2..],
        "compressed_key_data_alt is the DER serialization of the raw SEC1-encoded uncompressed point",
    );
}
