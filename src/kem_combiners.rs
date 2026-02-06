// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! KEM Combiners for Hybrid Key Encapsulation.
//!
//! This module provides implementations of various KEM combiners for building
//! hybrid KEMs that combine post-quantum and classical key encapsulation mechanisms.
//!
//! ## Supported Combiners
//!
//! - **X-Wing**: ML-KEM-768 + X25519 as specified in
//!   [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
//!
//! ## Security
//!
//! Hybrid KEMs provide security against both classical and quantum adversaries by
//! combining a post-quantum KEM with a classical KEM. The combined scheme is secure
//! if either component remains secure.

use crate::{
    ec::{ecdh, ecdh_keygen, import_ec_public_key_from_spki, EcCurve},
    err::{Error, Res},
    hash::sha3_256,
    init,
    kem::{mlkem_decapsulate, mlkem_encapsulate, mlkem_generate_keypair, MlKemParameterSet},
    p11::{self, PrivateKey, PublicKey},
};

// ============================================================================
// X-Wing Hybrid KEM (ML-KEM-768 + X25519)
// ============================================================================

/// X-Wing label per draft-connolly-cfrg-xwing-kem.
/// ASCII representation: `\./` + `/^\` = hex 5C 2E 2F 2F 5E 5C
const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

// Key size constants for X-Wing (ML-KEM-768 + X25519) components
/// ML-KEM-768 secret key size in bytes.
const MLKEM768_SECRET_KEY_SIZE: usize = 2400;
/// ML-KEM-768 public key size in bytes.
const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
/// X25519 key size in bytes (both public and private).
const X25519_KEY_SIZE: usize = 32;

/// X-Wing (ML-KEM-768 + X25519) hybrid secret key size in bytes.
pub const XWING_MLKEM768_X25519_SECRET_KEY_SIZE: usize =
    MLKEM768_SECRET_KEY_SIZE + X25519_KEY_SIZE; // 2432
/// X-Wing (ML-KEM-768 + X25519) hybrid public key size in bytes.
pub const XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE: usize =
    MLKEM768_PUBLIC_KEY_SIZE + X25519_KEY_SIZE; // 1216
/// X-Wing (ML-KEM-768 + X25519) ciphertext size in bytes.
pub const XWING_MLKEM768_X25519_CIPHERTEXT_SIZE: usize =
    MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE; // 1120
/// X-Wing (ML-KEM-768 + X25519) shared secret size in bytes.
pub const XWING_MLKEM768_X25519_SHARED_SECRET_SIZE: usize = 32;

/// X-Wing hybrid key pair containing both ML-KEM-768 and X25519 components.
pub struct XWingKeyPair {
    /// ML-KEM-768 public key.
    pub mlkem_public: PublicKey,
    /// ML-KEM-768 private key.
    pub mlkem_private: PrivateKey,
    /// X25519 public key.
    pub x25519_public: PublicKey,
    /// X25519 private key.
    pub x25519_private: PrivateKey,
}

/// Result of X-Wing encapsulation.
pub struct XWingEncapResult {
    /// The 32-byte shared secret.
    pub shared_secret: [u8; 32],
    /// The ciphertext (1120 bytes: ML-KEM ciphertext || X25519 ephemeral public key).
    pub ciphertext: Vec<u8>,
}

impl XWingKeyPair {
    /// Generate a new X-Wing key pair.
    ///
    /// This generates both an ML-KEM-768 key pair and an X25519 key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Res<Self> {
        init()?;

        // Generate ML-KEM-768 key pair
        let mlkem_keypair = mlkem_generate_keypair(MlKemParameterSet::MlKem768)?;

        // Generate X25519 key pair
        let x25519_keypair = ecdh_keygen(&EcCurve::X25519)?;

        Ok(Self {
            mlkem_public: mlkem_keypair.public,
            mlkem_private: mlkem_keypair.private,
            x25519_public: x25519_keypair.public,
            x25519_private: x25519_keypair.private,
        })
    }

    // TODO: Implement public_key_bytes() and secret_key_bytes() when
    // ML-KEM key serialization is properly supported in NSS bindings.
    // The SECKEYPublicKeyStr is currently opaque in bindgen output.
}

/// Extract raw X25519 public key bytes.
/// `CKA_EC_POINT` may return DER-encoded OCTET STRING, so we handle both formats.
fn extract_x25519_public_key_bytes(key: &PublicKey) -> Res<[u8; 32]> {
    let pk_vec = key.key_data_alt()?;
    if pk_vec.len() == 32 {
        Ok(pk_vec.as_slice().try_into().map_err(|_| Error::InvalidInput)?)
    } else if pk_vec.len() == 34 && pk_vec[0] == 0x04 && pk_vec[1] == 0x20 {
        // DER OCTET STRING: 04 20 <32 bytes>
        Ok(pk_vec[2..34].try_into().map_err(|_| Error::InvalidInput)?)
    } else {
        Err(Error::InvalidInput)
    }
}

/// X-Wing combiner function.
///
/// Computes: `SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)`
///
/// # Arguments
///
/// * `ss_m` - ML-KEM-768 shared secret (32 bytes)
/// * `ss_x` - X25519 shared secret (32 bytes)
/// * `ct_x` - X25519 ciphertext/ephemeral public key (32 bytes)
/// * `pk_x` - Recipient's X25519 public key (32 bytes)
fn xwing_combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> Res<[u8; 32]> {
    // Concatenate all inputs: ss_M || ss_X || ct_X || pk_X || XWingLabel
    let mut input = Vec::with_capacity(32 + 32 + 32 + 32 + XWING_LABEL.len());
    input.extend_from_slice(ss_m);
    input.extend_from_slice(ss_x);
    input.extend_from_slice(ct_x);
    input.extend_from_slice(pk_x);
    input.extend_from_slice(XWING_LABEL);

    // Compute SHA3-256
    sha3_256(&input)
}

/// RFC 8410 OID for X25519: 1.3.101.110
const RFC8410_OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];

/// Import a raw X25519 public key from 32 bytes.
pub fn import_x25519_public_key(raw_key: &[u8; 32]) -> Res<PublicKey> {
    // Build SPKI structure for X25519 per RFC 8410
    // SEQUENCE {
    //   SEQUENCE {
    //     OBJECT IDENTIFIER 1.3.101.110 (X25519)
    //   }
    //   BIT STRING (public key)
    // }

    // Calculate lengths:
    // Inner SEQUENCE: OID tag (1) + OID len (1) + OID (3) = 5
    // BIT STRING: tag (1) + len (1) + unused bits (1) + key (32) = 35
    // Outer SEQUENCE contents: Inner SEQUENCE tag (1) + Inner SEQUENCE len (1)
    //                          + Inner SEQUENCE contents (5) + BIT STRING (35) = 42

    let mut spki = Vec::with_capacity(44);

    // Outer SEQUENCE
    spki.push(0x30); // SEQUENCE tag
    spki.push(42); // Length of contents

    // Inner SEQUENCE (algorithm identifier) - no parameters for X25519
    spki.push(0x30); // SEQUENCE tag
    spki.push(5); // Length: OID tag (1) + OID len (1) + OID bytes (3)

    // OID (1.3.101.110)
    spki.push(0x06); // OBJECT IDENTIFIER tag
    spki.push(3); // Length
    spki.extend_from_slice(RFC8410_OID_X25519);

    // BIT STRING (public key)
    spki.push(0x03); // BIT STRING tag
    spki.push(33); // Length (1 byte for unused bits + 32 bytes key)
    spki.push(0x00); // No unused bits
    spki.extend_from_slice(raw_key);

    import_ec_public_key_from_spki(&spki)
}

/// Import an X-Wing (ML-KEM-768 + X25519) public key from raw bytes.
///
/// Expects 1216 bytes: 1184 bytes ML-KEM-768 || 32 bytes X25519.
/// Returns a tuple of (mlkem_public, x25519_public) `PublicKey` objects
/// suitable for passing to `xwing_encapsulate()`.
pub fn import_xwing_public_key(
    raw_key: &[u8],
) -> Res<(PublicKey, PublicKey)> {
    use crate::kem::{import_mlkem_public_key, MlKemParameterSet};

    if raw_key.len() != XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidInput);
    }

    let mlkem_pk_bytes = &raw_key[..MLKEM768_PUBLIC_KEY_SIZE];
    let x25519_pk_bytes: &[u8; 32] = raw_key[MLKEM768_PUBLIC_KEY_SIZE..]
        .try_into()
        .map_err(|_| Error::InvalidInput)?;

    let mlkem_pk = import_mlkem_public_key(mlkem_pk_bytes, MlKemParameterSet::MlKem768)?;
    let x25519_pk = import_x25519_public_key(x25519_pk_bytes)?;

    Ok((mlkem_pk, x25519_pk))
}

/// Encapsulate using an X-Wing public key.
///
/// This function generates a random shared secret and encapsulates it using
/// the X-Wing hybrid KEM, combining ML-KEM-768 and X25519.
///
/// # Arguments
///
/// * `mlkem_public` - The recipient's ML-KEM-768 public key.
/// * `x25519_public` - The recipient's X25519 public key.
///
/// # Returns
///
/// An `XWingEncapResult` containing the shared secret and ciphertext.
///
/// # Errors
///
/// Returns an error if encapsulation fails.
pub fn xwing_encapsulate(
    mlkem_public: &PublicKey,
    x25519_public: &PublicKey,
) -> Res<XWingEncapResult> {
    init()?;

    // Get recipient's X25519 public key bytes (needed for combiner)
    let pk_x = extract_x25519_public_key_bytes(x25519_public)?;

    // 1. Encapsulate with ML-KEM-768
    let target = p11::CKM_HKDF_DERIVE.into();
    let (mlkem_shared_secret, mlkem_ciphertext) = mlkem_encapsulate(mlkem_public, target)?;

    // Extract ML-KEM shared secret bytes
    let ss_m_vec = mlkem_shared_secret.key_data()?;
    let ss_m: [u8; 32] = ss_m_vec.try_into().map_err(|_| Error::InvalidInput)?;

    // 2. Encapsulate with X25519 (generate ephemeral keypair and do ECDH)
    let ephemeral_keypair = ecdh_keygen(&EcCurve::X25519)?;
    let x25519_shared_secret = ecdh(&ephemeral_keypair.private, x25519_public)?;

    // Get ephemeral public key (this is the X25519 "ciphertext")
    let ct_x = extract_x25519_public_key_bytes(&ephemeral_keypair.public)?;

    // Extract X25519 shared secret
    let ss_x: [u8; 32] = x25519_shared_secret
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidInput)?;

    // 3. Combine shared secrets using X-Wing combiner
    let combined_ss = xwing_combiner(&ss_m, &ss_x, &ct_x, &pk_x)?;

    // 4. Build ciphertext: ML-KEM ciphertext || X25519 ephemeral public key
    let mut ciphertext = Vec::with_capacity(XWING_MLKEM768_X25519_CIPHERTEXT_SIZE);
    ciphertext.extend_from_slice(&mlkem_ciphertext);
    ciphertext.extend_from_slice(&ct_x);

    Ok(XWingEncapResult {
        shared_secret: combined_ss,
        ciphertext,
    })
}

/// Decapsulate an X-Wing ciphertext.
///
/// This function recovers the shared secret from an X-Wing ciphertext using
/// the corresponding private keys.
///
/// # Arguments
///
/// * `ciphertext` - The X-Wing ciphertext (1120 bytes).
/// * `mlkem_private` - The recipient's ML-KEM-768 private key.
/// * `x25519_private` - The recipient's X25519 private key.
/// * `x25519_public` - The recipient's X25519 public key (needed for combiner).
///
/// # Returns
///
/// The 32-byte shared secret.
///
/// # Errors
///
/// Returns an error if decapsulation fails or the ciphertext is invalid.
pub fn xwing_decapsulate(
    ciphertext: &[u8],
    mlkem_private: &PrivateKey,
    x25519_private: &PrivateKey,
    x25519_public: &PublicKey,
) -> Res<[u8; 32]> {
    init()?;

    // Validate ciphertext length
    if ciphertext.len() != XWING_MLKEM768_X25519_CIPHERTEXT_SIZE {
        return Err(Error::InvalidInput);
    }

    // Split ciphertext: ML-KEM ciphertext || X25519 ephemeral public key
    let mlkem_ct = &ciphertext[..MLKEM768_CIPHERTEXT_SIZE];
    let ct_x: [u8; 32] = ciphertext[MLKEM768_CIPHERTEXT_SIZE..]
        .try_into()
        .map_err(|_| Error::InvalidInput)?;

    // Get recipient's X25519 public key bytes (needed for combiner)
    let pk_x = extract_x25519_public_key_bytes(x25519_public)?;

    // 1. Decapsulate with ML-KEM-768
    let target = p11::CKM_HKDF_DERIVE.into();
    let mlkem_shared_secret = mlkem_decapsulate(mlkem_private, mlkem_ct, target)?;

    // Extract ML-KEM shared secret bytes
    let ss_m_vec = mlkem_shared_secret.key_data()?;
    let ss_m: [u8; 32] = ss_m_vec.try_into().map_err(|_| Error::InvalidInput)?;

    // 2. Decapsulate with X25519 (ECDH with ephemeral public key)
    // Import the ephemeral public key
    let ephemeral_pk = import_x25519_public_key(&ct_x)?;
    let x25519_shared_secret = ecdh(x25519_private, &ephemeral_pk)?;

    // Extract X25519 shared secret
    let ss_x: [u8; 32] = x25519_shared_secret
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidInput)?;

    // 3. Combine shared secrets using X-Wing combiner
    xwing_combiner(&ss_m, &ss_x, &ct_x, &pk_x)
}


#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use test_fixture::fixture_init;

    use super::*;

    #[test]
    fn test_xwing_label() {
        // Verify the X-Wing label matches the spec: hex 5C 2E 2F 2F 5E 5C
        assert_eq!(XWING_LABEL, b"\\.//^\\");
        assert_eq!(XWING_LABEL, &[0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C]);
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(XWING_MLKEM768_X25519_SECRET_KEY_SIZE, 2432);
        assert_eq!(XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE, 1216);
        assert_eq!(XWING_MLKEM768_X25519_CIPHERTEXT_SIZE, 1120);
        assert_eq!(XWING_MLKEM768_X25519_SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_generate_keypair() {
        fixture_init();
        let keypair = XWingKeyPair::generate().unwrap();

        // Verify keys were generated (the structs exist)
        // Note: public_key_bytes() and secret_key_bytes() serialization
        // is not yet fully implemented due to ML-KEM key structure complexity
        assert!(!(*keypair.mlkem_public).is_null());
        assert!(!(*keypair.mlkem_private).is_null());
        assert!(!(*keypair.x25519_public).is_null());
        assert!(!(*keypair.x25519_private).is_null());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        fixture_init();

        // Generate recipient key pair
        let keypair = XWingKeyPair::generate().unwrap();

        // Encapsulate
        let encap_result =
            xwing_encapsulate(&keypair.mlkem_public, &keypair.x25519_public).unwrap();

        // Verify ciphertext size
        assert_eq!(encap_result.ciphertext.len(), XWING_MLKEM768_X25519_CIPHERTEXT_SIZE);

        // Verify shared secret size
        assert_eq!(encap_result.shared_secret.len(), XWING_MLKEM768_X25519_SHARED_SECRET_SIZE);

        // Decapsulate
        let decap_ss = xwing_decapsulate(
            &encap_result.ciphertext,
            &keypair.mlkem_private,
            &keypair.x25519_private,
            &keypair.x25519_public,
        )
        .unwrap();

        // Verify shared secrets match
        assert_eq!(encap_result.shared_secret, decap_ss);
    }

    #[test]
    fn test_encap_decap_multiple_rounds() {
        fixture_init();

        let keypair = XWingKeyPair::generate().unwrap();

        // Run multiple encap/decap cycles to ensure consistency
        for _ in 0..3 {
            let encap_result =
                xwing_encapsulate(&keypair.mlkem_public, &keypair.x25519_public).unwrap();

            let decap_ss = xwing_decapsulate(
                &encap_result.ciphertext,
                &keypair.mlkem_private,
                &keypair.x25519_private,
                &keypair.x25519_public,
            )
            .unwrap();

            assert_eq!(encap_result.shared_secret, decap_ss);
        }
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        fixture_init();

        let keypair1 = XWingKeyPair::generate().unwrap();
        let keypair2 = XWingKeyPair::generate().unwrap();

        let encap1 = xwing_encapsulate(&keypair1.mlkem_public, &keypair1.x25519_public).unwrap();
        let encap2 = xwing_encapsulate(&keypair2.mlkem_public, &keypair2.x25519_public).unwrap();

        // Different keypairs should produce different shared secrets
        assert_ne!(encap1.shared_secret, encap2.shared_secret);
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        fixture_init();

        let keypair = XWingKeyPair::generate().unwrap();

        // Too short ciphertext
        let short_ct = vec![0u8; XWING_MLKEM768_X25519_CIPHERTEXT_SIZE - 1];
        let result = xwing_decapsulate(
            &short_ct,
            &keypair.mlkem_private,
            &keypair.x25519_private,
            &keypair.x25519_public,
        );
        assert!(result.is_err());

        // Too long ciphertext
        let long_ct = vec![0u8; XWING_MLKEM768_X25519_CIPHERTEXT_SIZE + 1];
        let result = xwing_decapsulate(
            &long_ct,
            &keypair.mlkem_private,
            &keypair.x25519_private,
            &keypair.x25519_public,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_xwing_import_public_key_roundtrip() {
        use crate::err::secstatus_to_res;
        use crate::p11;
        use crate::util::SECItemMut;

        fixture_init();

        let keypair = XWingKeyPair::generate().unwrap();

        // Export ML-KEM public key bytes via PK11_ReadRawAttribute(CKA_VALUE)
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            p11::PK11_ReadRawAttribute(
                p11::PK11ObjectType::PK11_TypePubKey,
                (*keypair.mlkem_public).cast(),
                pkcs11_bindings::CKA_VALUE,
                key_item.as_mut(),
            )
        })
        .unwrap();
        let mlkem_pk_bytes = key_item.as_slice().to_owned();

        // Export X25519 public key bytes
        let x25519_raw = extract_x25519_public_key_bytes(&keypair.x25519_public).unwrap();

        // Concatenate: ML-KEM-768 pk || X25519 pk
        let mut combined = Vec::with_capacity(XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE);
        combined.extend_from_slice(&mlkem_pk_bytes);
        combined.extend_from_slice(&x25519_raw);
        assert_eq!(combined.len(), XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE);

        // Import
        let (imported_mlkem, imported_x25519) = import_xwing_public_key(&combined).unwrap();

        // Encapsulate with imported keys
        let encap = xwing_encapsulate(&imported_mlkem, &imported_x25519).unwrap();

        // Decapsulate with original private keys
        let ss = xwing_decapsulate(
            &encap.ciphertext,
            &keypair.mlkem_private,
            &keypair.x25519_private,
            &keypair.x25519_public,
        )
        .unwrap();

        assert_eq!(encap.shared_secret, ss);
    }

    #[test]
    fn test_xwing_import_invalid_size() {
        fixture_init();

        let result = import_xwing_public_key(&[0u8; 100]);
        assert!(result.is_err());
    }
}
