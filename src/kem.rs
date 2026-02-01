// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Key Encapsulation Mechanism (KEM) support for ML-KEM (FIPS 203).
//!
//! This module provides Rust bindings for NSS's ML-KEM implementation,
//! supporting ML-KEM-768 and ML-KEM-1024 parameter sets.

use std::ptr::null_mut;

use crate::{
    err::{secstatus_to_res, IntoResult as _, Res},
    init,
    p11::{self, PrivateKey, PublicKey, Slot, SymKey},
    prtypes::PRUint32,
    util::SECItemBorrowed,
    ScopedSECItem, SECItem,
};

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

/// An ML-KEM key pair.
pub struct MlKemKeypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

/// Type alias for PK11 attribute flags.
type Pk11AttrFlags = PRUint32;

/// Generate an ML-KEM key pair.
///
/// # Arguments
///
/// * `params` - The ML-KEM parameter set to use.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or key generation fails.
pub fn generate_keypair(params: MlKemParameterSet) -> Res<MlKemKeypair> {
    init()?;

    let slot = Slot::internal()?;

    // Create the parameter for key generation (the parameter set as CK_ULONG)
    // The parameter is passed as a pointer to the CK_ULONG value
    let mut ck_param: p11::CK_ULONG = match params {
        MlKemParameterSet::MlKem768 => p11::CKP_ML_KEM_768.into(),
        MlKemParameterSet::MlKem1024 => p11::CKP_ML_KEM_1024.into(),
    };

    let mut public_ptr: *mut p11::SECKEYPublicKey = null_mut();

    // Generate the key pair using the standard ML-KEM mechanism
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

/// Encapsulate a shared secret using an ML-KEM public key.
///
/// This function generates a random shared secret and encapsulates it using
/// the provided public key. The encapsulation (ciphertext) can be sent to
/// the holder of the corresponding private key, who can decapsulate it to
/// recover the same shared secret.
///
/// # Arguments
///
/// * `public_key` - The recipient's ML-KEM public key.
/// * `target` - The target mechanism for the derived symmetric key (e.g., `CKM_HKDF_DERIVE`).
///
/// # Returns
///
/// A tuple of `(shared_secret, ciphertext)` where:
/// - `shared_secret` is a symmetric key that can be used for further key derivation.
/// - `ciphertext` is the encapsulation that should be sent to the private key holder.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or encapsulation fails.
pub fn encapsulate(
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

/// Decapsulate a ciphertext using an ML-KEM private key.
///
/// This function recovers the shared secret from an encapsulation (ciphertext)
/// using the corresponding private key.
///
/// # Arguments
///
/// * `private_key` - The ML-KEM private key.
/// * `ciphertext` - The encapsulation received from the sender.
/// * `target` - The target mechanism for the derived symmetric key (e.g., `CKM_HKDF_DERIVE`).
///
/// # Returns
///
/// The shared secret as a symmetric key.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or decapsulation fails.
pub fn decapsulate(
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use test_fixture::fixture_init;

    use super::*;

    #[test]
    fn generate_mlkem768_keypair() {
        fixture_init();
        let keypair = generate_keypair(MlKemParameterSet::MlKem768).unwrap();
        // Keypair was successfully created (from_ptr would have failed if null)
        assert!(!(*keypair.public).is_null());
        assert!(!(*keypair.private).is_null());
    }

    #[test]
    fn generate_mlkem1024_keypair() {
        fixture_init();
        let keypair = generate_keypair(MlKemParameterSet::MlKem1024).unwrap();
        // Keypair was successfully created (from_ptr would have failed if null)
        assert!(!(*keypair.public).is_null());
        assert!(!(*keypair.private).is_null());
    }

    #[test]
    fn encapsulate_decapsulate_mlkem768() {
        fixture_init();

        // Generate a key pair
        let keypair = generate_keypair(MlKemParameterSet::MlKem768).unwrap();

        // Encapsulate using the public key
        let target = p11::CKM_HKDF_DERIVE.into();
        let (shared_secret1, ciphertext) = encapsulate(&keypair.public, target).unwrap();

        // Verify ciphertext size
        assert_eq!(
            ciphertext.len(),
            MlKemParameterSet::MlKem768.ciphertext_bytes()
        );

        // Decapsulate using the private key
        let shared_secret2 = decapsulate(&keypair.private, &ciphertext, target).unwrap();

        // Verify that both shared secrets are the same
        let ss1 = shared_secret1.key_data().unwrap();
        let ss2 = shared_secret2.key_data().unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), MlKemParameterSet::MlKem768.shared_secret_bytes());
    }

    #[test]
    fn encapsulate_decapsulate_mlkem1024() {
        fixture_init();

        // Generate a key pair
        let keypair = generate_keypair(MlKemParameterSet::MlKem1024).unwrap();

        // Encapsulate using the public key
        let target = p11::CKM_HKDF_DERIVE.into();
        let (shared_secret1, ciphertext) = encapsulate(&keypair.public, target).unwrap();

        // Verify ciphertext size
        assert_eq!(
            ciphertext.len(),
            MlKemParameterSet::MlKem1024.ciphertext_bytes()
        );

        // Decapsulate using the private key
        let shared_secret2 = decapsulate(&keypair.private, &ciphertext, target).unwrap();

        // Verify that both shared secrets are the same
        let ss1 = shared_secret1.key_data().unwrap();
        let ss2 = shared_secret2.key_data().unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(
            ss1.len(),
            MlKemParameterSet::MlKem1024.shared_secret_bytes()
        );
    }

    #[test]
    fn parameter_set_sizes() {
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
