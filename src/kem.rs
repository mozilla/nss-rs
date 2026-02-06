// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Key Encapsulation Mechanism (KEM) support.
//!
//! This module provides a unified interface for Key Encapsulation Mechanisms,
//! supporting both classical post-quantum KEMs (ML-KEM per FIPS 203) and
//! hybrid KEMs that combine post-quantum and classical algorithms.
//!
//! ## Supported KEMs
//!
//! - **ML-KEM-768**: Post-quantum KEM with 192-bit security level
//! - **ML-KEM-1024**: Post-quantum KEM with 256-bit security level
//! - **X-Wing (ML-KEM-768 + X25519)**: Hybrid KEM combining ML-KEM-768 + X25519

use std::ptr::null_mut;

use crate::{
    err::{secstatus_to_res, Error, IntoResult as _, Res},
    init,
    kem_combiners::{
        xwing_decapsulate, xwing_encapsulate, XWingKeyPair, XWING_MLKEM768_X25519_CIPHERTEXT_SIZE,
        XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE, XWING_MLKEM768_X25519_SECRET_KEY_SIZE, XWING_MLKEM768_X25519_SHARED_SECRET_SIZE,
    },
    p11::{self, PrivateKey, PublicKey, Slot, SymKey},
    prtypes::PRUint32,
    util::SECItemBorrowed,
    ScopedSECItem, SECItem,
};

// ============================================================================
// KEM Parameter Sets
// ============================================================================

/// KEM parameter sets for all supported algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemParameterSet {
    /// ML-KEM-768: Post-quantum KEM with 192-bit security level (FIPS 203)
    MlKem768,
    /// ML-KEM-1024: Post-quantum KEM with 256-bit security level (FIPS 203)
    MlKem1024,
    /// X-Wing (ML-KEM-768 + X25519): Hybrid KEM combining ML-KEM-768 + X25519
    XWingMLKem768X25519,
}

impl KemParameterSet {
    /// Returns the public key size in bytes.
    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
            Self::XWingMLKem768X25519 => XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE,
        }
    }

    /// Returns the private key size in bytes.
    #[must_use]
    pub const fn private_key_bytes(self) -> usize {
        match self {
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
            Self::XWingMLKem768X25519 => XWING_MLKEM768_X25519_SECRET_KEY_SIZE,
        }
    }

    /// Returns the ciphertext size in bytes.
    #[must_use]
    pub const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
            Self::XWingMLKem768X25519 => XWING_MLKEM768_X25519_CIPHERTEXT_SIZE,
        }
    }

    /// Returns the shared secret size in bytes.
    #[must_use]
    pub const fn shared_secret_bytes(self) -> usize {
        match self {
            Self::MlKem768 | Self::MlKem1024 => 32,
            Self::XWingMLKem768X25519 => XWING_MLKEM768_X25519_SHARED_SECRET_SIZE,
        }
    }

    /// Returns true if this is a hybrid KEM.
    #[must_use]
    pub const fn is_hybrid(self) -> bool {
        matches!(self, Self::XWingMLKem768X25519)
    }
}

// ============================================================================
// ML-KEM Parameter Set (for backwards compatibility and internal use)
// ============================================================================

/// ML-KEM parameter sets as defined in FIPS 203.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemParameterSet {
    /// ML-KEM-768: 192-bit security level
    MlKem768,
    /// ML-KEM-1024: 256-bit security level
    MlKem1024,
}

impl MlKemParameterSet {
    /// Returns the PKCS#11 parameter set constant.
    #[must_use]
    pub const fn to_ck_param(self) -> u64 {
        match self {
            Self::MlKem768 => p11::CKP_ML_KEM_768 as u64,
            Self::MlKem1024 => p11::CKP_ML_KEM_1024 as u64,
        }
    }

    /// Returns the public key size in bytes.
    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Returns the private key size in bytes.
    #[must_use]
    pub const fn private_key_bytes(self) -> usize {
        match self {
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Returns the ciphertext size in bytes.
    #[must_use]
    pub const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Returns the shared secret size in bytes (always 32 for ML-KEM).
    #[must_use]
    pub const fn shared_secret_bytes(self) -> usize {
        32
    }
}

impl From<MlKemParameterSet> for KemParameterSet {
    fn from(params: MlKemParameterSet) -> Self {
        match params {
            MlKemParameterSet::MlKem768 => Self::MlKem768,
            MlKemParameterSet::MlKem1024 => Self::MlKem1024,
        }
    }
}

// ============================================================================
// Key Pair Types
// ============================================================================

/// An ML-KEM key pair (for internal use and backwards compatibility).
pub struct MlKemKeypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

/// A unified KEM key pair that can hold any supported KEM type.
pub enum KemKeypair {
    /// ML-KEM-768 key pair
    MlKem768 {
        public: PublicKey,
        private: PrivateKey,
    },
    /// ML-KEM-1024 key pair
    MlKem1024 {
        public: PublicKey,
        private: PrivateKey,
    },
    /// X-Wing hybrid key pair
    XWingMLKem768X25519(XWingKeyPair),
}

impl KemKeypair {
    /// Returns the parameter set for this key pair.
    #[must_use]
    pub const fn parameter_set(&self) -> KemParameterSet {
        match self {
            Self::MlKem768 { .. } => KemParameterSet::MlKem768,
            Self::MlKem1024 { .. } => KemParameterSet::MlKem1024,
            Self::XWingMLKem768X25519(_) => KemParameterSet::XWingMLKem768X25519,
        }
    }
}

/// Result of KEM encapsulation.
pub struct KemEncapResult {
    /// The shared secret bytes.
    pub shared_secret: Vec<u8>,
    /// The ciphertext to send to the private key holder.
    pub ciphertext: Vec<u8>,
}

// ============================================================================
// Internal ML-KEM functions (PK11-based)
// ============================================================================

/// Type alias for PK11 attribute flags.
type Pk11AttrFlags = PRUint32;

/// Generate an ML-KEM key pair (internal).
pub(crate) fn mlkem_generate_keypair(params: MlKemParameterSet) -> Res<MlKemKeypair> {
    init()?;

    let slot = Slot::internal()?;

    let mut ck_param: p11::CK_ULONG = match params {
        MlKemParameterSet::MlKem768 => p11::CKP_ML_KEM_768.into(),
        MlKemParameterSet::MlKem1024 => p11::CKP_ML_KEM_1024.into(),
    };

    let mut public_ptr: *mut p11::SECKEYPublicKey = null_mut();

    let private_ptr = unsafe {
        p11::PK11_GenerateKeyPair(
            *slot,
            p11::CK_MECHANISM_TYPE::from(p11::CKM_ML_KEM_KEY_PAIR_GEN),
            std::ptr::addr_of_mut!(ck_param).cast(),
            &mut public_ptr,
            pkcs11_bindings::CK_FALSE.into(),
            pkcs11_bindings::CK_FALSE.into(),
            null_mut(),
        )
    };

    let private = unsafe { PrivateKey::from_ptr(private_ptr)? };
    let public = unsafe { PublicKey::from_ptr(public_ptr)? };

    Ok(MlKemKeypair { public, private })
}

/// Encapsulate using an ML-KEM public key (internal, returns `SymKey`).
pub(crate) fn mlkem_encapsulate(
    public_key: &PublicKey,
    target: p11::CK_MECHANISM_TYPE,
) -> Res<(SymKey, Vec<u8>)> {
    init()?;

    let attr_flags: Pk11AttrFlags = p11::PK11_ATTR_SESSION | p11::PK11_ATTR_INSENSITIVE;
    let op_flags: p11::CK_FLAGS = p11::CKF_DERIVE.into();

    let mut shared_secret_ptr: *mut p11::PK11SymKey = null_mut();
    let mut ciphertext_ptr: *mut SECItem = null_mut();

    secstatus_to_res(unsafe {
        p11::PK11_Encapsulate(
            **public_key,
            target,
            attr_flags,
            op_flags,
            &mut shared_secret_ptr,
            &mut ciphertext_ptr,
        )
    })?;

    let shared_secret = unsafe { SymKey::from_ptr(shared_secret_ptr)? };
    let ciphertext_item: ScopedSECItem = unsafe { ciphertext_ptr.into_result()? };
    let ciphertext = unsafe { ciphertext_item.into_vec() };

    Ok((shared_secret, ciphertext))
}

/// Decapsulate an ML-KEM ciphertext (internal, returns `SymKey`).
pub(crate) fn mlkem_decapsulate(
    private_key: &PrivateKey,
    ciphertext: &[u8],
    target: p11::CK_MECHANISM_TYPE,
) -> Res<SymKey> {
    init()?;

    let attr_flags: Pk11AttrFlags = p11::PK11_ATTR_SESSION | p11::PK11_ATTR_INSENSITIVE;
    let op_flags: p11::CK_FLAGS = p11::CKF_DERIVE.into();

    let mut ciphertext_item = SECItemBorrowed::wrap(ciphertext)?;
    let ciphertext_ptr: *mut SECItem = ciphertext_item.as_mut();

    let mut shared_secret_ptr: *mut p11::PK11SymKey = null_mut();

    secstatus_to_res(unsafe {
        p11::PK11_Decapsulate(
            **private_key,
            ciphertext_ptr,
            target,
            attr_flags,
            op_flags,
            &mut shared_secret_ptr,
        )
    })?;

    let shared_secret = unsafe { SymKey::from_ptr(shared_secret_ptr)? };

    Ok(shared_secret)
}

// ============================================================================
// ML-KEM Public Key Import
// ============================================================================

/// Import an ML-KEM public key from raw bytes.
///
/// Constructs a `SECKEYPublicKey` with `keyType = kyberKey` and the
/// appropriate `KyberParams`, then uses `SECKEY_CopyPublicKey` to create
/// a properly arena-backed copy, and `PK11_ImportPublicKey` to register
/// it in PKCS#11.
pub fn import_mlkem_public_key(
    raw_key: &[u8],
    params: MlKemParameterSet,
) -> Res<PublicKey> {
    init()?;

    let expected_size = params.public_key_bytes();
    if raw_key.len() != expected_size {
        return Err(Error::InvalidInput);
    }

    let kyber_params = match params {
        MlKemParameterSet::MlKem768 => p11::KyberParams_params_ml_kem768,
        MlKemParameterSet::MlKem1024 => p11::KyberParams_params_ml_kem1024,
    };

    unsafe {
        let mut temp_key: p11::SECKEYPublicKey = std::mem::zeroed();
        temp_key.keyType = p11::KeyType_kyberKey;
        temp_key.u.kyber.as_mut().params = kyber_params;
        temp_key.u.kyber.as_mut().publicValue = SECItem {
            type_: crate::SECItemType::siBuffer,
            data: raw_key.as_ptr() as *mut u8,
            len: raw_key.len() as u32,
        };

        // SECKEY_CopyPublicKey allocates a new arena and deep-copies
        let copied: PublicKey = p11::SECKEY_CopyPublicKey(&temp_key).into_result()?;

        // Register in PKCS#11
        let slot = Slot::internal()?;
        let handle = p11::PK11_ImportPublicKey(
            *slot,
            *copied,
            crate::PR_FALSE,
        );
        if handle == pkcs11_bindings::CK_INVALID_HANDLE {
            return Err(Error::InvalidInput);
        }

        Ok(copied)
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Generate a KEM key pair for the specified parameter set.
///
/// # Arguments
///
/// * `params` - The KEM parameter set to use.
///
/// # Returns
///
/// A `KemKeypair` containing the public and private keys.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or key generation fails.
///
/// # Example
///
/// ```ignore
/// use nss_rs::kem::{generate_keypair, KemParameterSet};
///
/// let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519)?;
/// ```
pub fn generate_keypair(params: KemParameterSet) -> Res<KemKeypair> {
    match params {
        KemParameterSet::MlKem768 => {
            let kp = mlkem_generate_keypair(MlKemParameterSet::MlKem768)?;
            Ok(KemKeypair::MlKem768 {
                public: kp.public,
                private: kp.private,
            })
        }
        KemParameterSet::MlKem1024 => {
            let kp = mlkem_generate_keypair(MlKemParameterSet::MlKem1024)?;
            Ok(KemKeypair::MlKem1024 {
                public: kp.public,
                private: kp.private,
            })
        }
        KemParameterSet::XWingMLKem768X25519 => {
            let kp = XWingKeyPair::generate()?;
            Ok(KemKeypair::XWingMLKem768X25519(kp))
        }
    }
}

/// Encapsulate a shared secret using a KEM public key.
///
/// This function generates a random shared secret and encapsulates it using
/// the provided key pair's public key. The ciphertext can be sent to the
/// holder of the private key, who can decapsulate it to recover the same
/// shared secret.
///
/// # Arguments
///
/// * `keypair` - The KEM key pair (only the public key is used).
///
/// # Returns
///
/// A `KemEncapResult` containing:
/// - `shared_secret`: The raw shared secret bytes.
/// - `ciphertext`: The encapsulation to send to the private key holder.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or encapsulation fails.
///
/// # Example
///
/// ```ignore
/// use nss_rs::kem::{generate_keypair, encapsulate, KemParameterSet};
///
/// let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519)?;
/// let result = encapsulate(&keypair)?;
/// // Send result.ciphertext to the private key holder
/// // Use result.shared_secret for key derivation
/// ```
pub fn encapsulate(keypair: &KemKeypair) -> Res<KemEncapResult> {
    match keypair {
        KemKeypair::MlKem768 { public, .. } | KemKeypair::MlKem1024 { public, .. } => {
            let target = p11::CKM_HKDF_DERIVE.into();
            let (sym_key, ciphertext) = mlkem_encapsulate(public, target)?;
            let shared_secret = sym_key.key_data()?.to_vec();
            Ok(KemEncapResult {
                shared_secret,
                ciphertext,
            })
        }
        KemKeypair::XWingMLKem768X25519(xwing_kp) => {
            let result = xwing_encapsulate(&xwing_kp.mlkem_public, &xwing_kp.x25519_public)?;
            Ok(KemEncapResult {
                shared_secret: result.shared_secret.to_vec(),
                ciphertext: result.ciphertext,
            })
        }
    }
}

/// Decapsulate a ciphertext using a KEM private key.
///
/// This function recovers the shared secret from a ciphertext using the
/// corresponding private key.
///
/// # Arguments
///
/// * `keypair` - The KEM key pair (the private key is used for decapsulation).
/// * `ciphertext` - The encapsulation received from the sender.
///
/// # Returns
///
/// The shared secret as a byte vector.
///
/// # Errors
///
/// Returns an error if NSS initialization fails, decapsulation fails,
/// or the ciphertext is invalid for the key type.
///
/// # Example
///
/// ```ignore
/// use nss_rs::kem::{generate_keypair, decapsulate, KemParameterSet};
///
/// let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519)?;
/// // ... receive ciphertext from sender ...
/// let shared_secret = decapsulate(&keypair, &ciphertext)?;
/// ```
pub fn decapsulate(keypair: &KemKeypair, ciphertext: &[u8]) -> Res<Vec<u8>> {
    // Validate ciphertext length
    let expected_len = keypair.parameter_set().ciphertext_bytes();
    if ciphertext.len() != expected_len {
        return Err(Error::InvalidInput);
    }

    match keypair {
        KemKeypair::MlKem768 { private, .. } | KemKeypair::MlKem1024 { private, .. } => {
            let target = p11::CKM_HKDF_DERIVE.into();
            let sym_key = mlkem_decapsulate(private, ciphertext, target)?;
            Ok(sym_key.key_data()?.to_vec())
        }
        KemKeypair::XWingMLKem768X25519(xwing_kp) => {
            let ss = xwing_decapsulate(
                ciphertext,
                &xwing_kp.mlkem_private,
                &xwing_kp.x25519_private,
                &xwing_kp.x25519_public,
            )?;
            Ok(ss.to_vec())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use test_fixture::fixture_init;

    use super::*;

    // ========================================================================
    // Unified API tests
    // ========================================================================

    #[test]
    fn test_mlkem768_unified() {
        fixture_init();

        let keypair = generate_keypair(KemParameterSet::MlKem768).unwrap();
        assert_eq!(keypair.parameter_set(), KemParameterSet::MlKem768);

        let encap_result = encapsulate(&keypair).unwrap();
        assert_eq!(
            encap_result.ciphertext.len(),
            KemParameterSet::MlKem768.ciphertext_bytes()
        );
        assert_eq!(
            encap_result.shared_secret.len(),
            KemParameterSet::MlKem768.shared_secret_bytes()
        );

        let decap_ss = decapsulate(&keypair, &encap_result.ciphertext).unwrap();
        assert_eq!(encap_result.shared_secret, decap_ss);
    }

    #[test]
    fn test_mlkem1024_unified() {
        fixture_init();

        let keypair = generate_keypair(KemParameterSet::MlKem1024).unwrap();
        assert_eq!(keypair.parameter_set(), KemParameterSet::MlKem1024);

        let encap_result = encapsulate(&keypair).unwrap();
        assert_eq!(
            encap_result.ciphertext.len(),
            KemParameterSet::MlKem1024.ciphertext_bytes()
        );
        assert_eq!(
            encap_result.shared_secret.len(),
            KemParameterSet::MlKem1024.shared_secret_bytes()
        );

        let decap_ss = decapsulate(&keypair, &encap_result.ciphertext).unwrap();
        assert_eq!(encap_result.shared_secret, decap_ss);
    }

    #[test]
    fn test_xwing_unified() {
        fixture_init();

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();
        assert_eq!(keypair.parameter_set(), KemParameterSet::XWingMLKem768X25519);
        assert!(keypair.parameter_set().is_hybrid());

        let encap_result = encapsulate(&keypair).unwrap();
        assert_eq!(
            encap_result.ciphertext.len(),
            KemParameterSet::XWingMLKem768X25519.ciphertext_bytes()
        );
        assert_eq!(
            encap_result.shared_secret.len(),
            KemParameterSet::XWingMLKem768X25519.shared_secret_bytes()
        );

        let decap_ss = decapsulate(&keypair, &encap_result.ciphertext).unwrap();
        assert_eq!(encap_result.shared_secret, decap_ss);
    }

    #[test]
    fn test_xwing_multiple_rounds() {
        fixture_init();

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        for _ in 0..3 {
            let encap_result = encapsulate(&keypair).unwrap();
            let decap_ss = decapsulate(&keypair, &encap_result.ciphertext).unwrap();
            assert_eq!(encap_result.shared_secret, decap_ss);
        }
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        fixture_init();

        let keypair1 = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();
        let keypair2 = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        let encap1 = encapsulate(&keypair1).unwrap();
        let encap2 = encapsulate(&keypair2).unwrap();

        // Different keypairs should produce different shared secrets
        assert_ne!(encap1.shared_secret, encap2.shared_secret);
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        fixture_init();

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        // Too short
        let short_ct = vec![0u8; KemParameterSet::XWingMLKem768X25519.ciphertext_bytes() - 1];
        assert!(decapsulate(&keypair, &short_ct).is_err());

        // Too long
        let long_ct = vec![0u8; KemParameterSet::XWingMLKem768X25519.ciphertext_bytes() + 1];
        assert!(decapsulate(&keypair, &long_ct).is_err());
    }

    #[test]
    fn test_parameter_set_sizes() {
        // ML-KEM-768
        assert_eq!(KemParameterSet::MlKem768.public_key_bytes(), 1184);
        assert_eq!(KemParameterSet::MlKem768.private_key_bytes(), 2400);
        assert_eq!(KemParameterSet::MlKem768.ciphertext_bytes(), 1088);
        assert_eq!(KemParameterSet::MlKem768.shared_secret_bytes(), 32);
        assert!(!KemParameterSet::MlKem768.is_hybrid());

        // ML-KEM-1024
        assert_eq!(KemParameterSet::MlKem1024.public_key_bytes(), 1568);
        assert_eq!(KemParameterSet::MlKem1024.private_key_bytes(), 3168);
        assert_eq!(KemParameterSet::MlKem1024.ciphertext_bytes(), 1568);
        assert_eq!(KemParameterSet::MlKem1024.shared_secret_bytes(), 32);
        assert!(!KemParameterSet::MlKem1024.is_hybrid());

        // X-Wing
        assert_eq!(KemParameterSet::XWingMLKem768X25519.public_key_bytes(), XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE);
        assert_eq!(KemParameterSet::XWingMLKem768X25519.private_key_bytes(), XWING_MLKEM768_X25519_SECRET_KEY_SIZE);
        assert_eq!(KemParameterSet::XWingMLKem768X25519.ciphertext_bytes(), XWING_MLKEM768_X25519_CIPHERTEXT_SIZE);
        assert_eq!(KemParameterSet::XWingMLKem768X25519.shared_secret_bytes(), XWING_MLKEM768_X25519_SHARED_SECRET_SIZE);
        assert!(KemParameterSet::XWingMLKem768X25519.is_hybrid());
    }

    #[test]
    fn test_mlkem_parameter_set_conversion() {
        assert_eq!(
            KemParameterSet::from(MlKemParameterSet::MlKem768),
            KemParameterSet::MlKem768
        );
        assert_eq!(
            KemParameterSet::from(MlKemParameterSet::MlKem1024),
            KemParameterSet::MlKem1024
        );
    }

    // ========================================================================
    // Legacy API tests (for backwards compatibility)
    // ========================================================================

    // ========================================================================
    // Import tests
    // ========================================================================

    #[test]
    fn test_mlkem768_import_public_key_roundtrip() {
        use crate::err::secstatus_to_res;
        use crate::util::SECItemMut;

        fixture_init();

        // Generate a keypair
        let keypair = generate_keypair(KemParameterSet::MlKem768).unwrap();
        let KemKeypair::MlKem768 {
            ref public,
            ref private,
        } = keypair
        else {
            panic!("Expected MlKem768 keypair");
        };

        // Export public key bytes via PK11_ReadRawAttribute(CKA_VALUE)
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            p11::PK11_ReadRawAttribute(
                p11::PK11ObjectType::PK11_TypePubKey,
                (**public).cast(),
                pkcs11_bindings::CKA_VALUE,
                key_item.as_mut(),
            )
        })
        .unwrap();
        let pk_bytes = key_item.as_slice().to_owned();
        assert_eq!(pk_bytes.len(), MlKemParameterSet::MlKem768.public_key_bytes());

        // Import from raw bytes
        let imported_pk =
            import_mlkem_public_key(&pk_bytes, MlKemParameterSet::MlKem768).unwrap();

        // Encapsulate with imported public key
        let target = p11::CKM_HKDF_DERIVE.into();
        let (ss_key, ciphertext) = mlkem_encapsulate(&imported_pk, target).unwrap();
        let shared_secret = ss_key.key_data().unwrap().to_vec();

        // Decapsulate with original private key
        let dec_key = mlkem_decapsulate(private, &ciphertext, target).unwrap();
        let decap_ss = dec_key.key_data().unwrap().to_vec();

        assert_eq!(shared_secret, decap_ss);
    }

    #[test]
    fn test_mlkem_import_invalid_size() {
        fixture_init();

        let result = import_mlkem_public_key(&[0u8; 100], MlKemParameterSet::MlKem768);
        assert!(result.is_err());
    }

    // ========================================================================
    // Legacy API tests (for backwards compatibility)
    // ========================================================================

    #[test]
    fn test_mlkem_parameter_set_sizes() {
        // ML-KEM-768 sizes
        assert_eq!(MlKemParameterSet::MlKem768.public_key_bytes(), 1184);
        assert_eq!(MlKemParameterSet::MlKem768.private_key_bytes(), 2400);
        assert_eq!(MlKemParameterSet::MlKem768.ciphertext_bytes(), 1088);
        assert_eq!(MlKemParameterSet::MlKem768.shared_secret_bytes(), 32);

        // ML-KEM-1024 sizes
        assert_eq!(MlKemParameterSet::MlKem1024.public_key_bytes(), 1568);
        assert_eq!(MlKemParameterSet::MlKem1024.private_key_bytes(), 3168);
        assert_eq!(MlKemParameterSet::MlKem1024.ciphertext_bytes(), 1568);
        assert_eq!(MlKemParameterSet::MlKem1024.shared_secret_bytes(), 32);
    }
}
