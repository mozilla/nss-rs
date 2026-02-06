// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Cryptographic hash functions.
//!
//! This module provides access to NSS's hash function implementations,
//! supporting both SHA-2 and SHA-3 families.

use std::convert::TryFrom as _;

use crate::{
    err::IntoResult as _,
    init, p11,
    p11::{PK11_HashBuf, SECOidTag},
    Error,
};

/// Supported hash algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-2 256-bit (32 bytes output)
    SHA2_256,
    /// SHA-2 384-bit (48 bytes output)
    SHA2_384,
    /// SHA-2 512-bit (64 bytes output)
    SHA2_512,
    /// SHA-3 224-bit (28 bytes output)
    SHA3_224,
    /// SHA-3 256-bit (32 bytes output)
    SHA3_256,
    /// SHA-3 384-bit (48 bytes output)
    SHA3_384,
    /// SHA-3 512-bit (64 bytes output)
    SHA3_512,
}

const fn hash_alg_to_oid(alg: &HashAlgorithm) -> SECOidTag::Type {
    match alg {
        HashAlgorithm::SHA2_256 => SECOidTag::SEC_OID_SHA256,
        HashAlgorithm::SHA2_384 => SECOidTag::SEC_OID_SHA384,
        HashAlgorithm::SHA2_512 => SECOidTag::SEC_OID_SHA512,
        HashAlgorithm::SHA3_224 => SECOidTag::SEC_OID_SHA3_224,
        HashAlgorithm::SHA3_256 => SECOidTag::SEC_OID_SHA3_256,
        HashAlgorithm::SHA3_384 => SECOidTag::SEC_OID_SHA3_384,
        HashAlgorithm::SHA3_512 => SECOidTag::SEC_OID_SHA3_512,
    }
}

/// Returns the output length in bytes for the given hash algorithm.
#[must_use]
pub const fn hash_alg_to_hash_len(alg: &HashAlgorithm) -> usize {
    match alg {
        HashAlgorithm::SHA2_256 => p11::SHA256_LENGTH as usize,
        HashAlgorithm::SHA2_384 => p11::SHA384_LENGTH as usize,
        HashAlgorithm::SHA2_512 => p11::SHA512_LENGTH as usize,
        HashAlgorithm::SHA3_224 => 28,
        HashAlgorithm::SHA3_256 => p11::SHA3_256_LENGTH as usize,
        HashAlgorithm::SHA3_384 => p11::SHA3_384_LENGTH as usize,
        HashAlgorithm::SHA3_512 => p11::SHA3_512_LENGTH as usize,
    }
}

/// Compute a cryptographic hash of the input data.
///
/// # Arguments
///
/// * `alg` - The hash algorithm to use.
/// * `data` - The data to hash.
///
/// # Returns
///
/// The hash digest as a byte vector.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn hash(alg: &HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
    init()?;

    let data_len: i32 = match i32::try_from(data.len()) {
        Ok(data_len) => data_len,
        _ => return Err(Error::Internal),
    };
    let expected_len = hash_alg_to_hash_len(alg);
    let mut digest = vec![0u8; expected_len];
    unsafe {
        PK11_HashBuf(
            hash_alg_to_oid(alg),
            digest.as_mut_ptr(),
            data.as_ptr(),
            data_len,
        )
        .into_result()?;
    };
    Ok(digest)
}

/// Convenience function for SHA-256 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    let digest = hash(&HashAlgorithm::SHA2_256, data)?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Convenience function for SHA-384 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha384(data: &[u8]) -> Result<[u8; 48], Error> {
    let digest = hash(&HashAlgorithm::SHA2_384, data)?;
    let mut result = [0u8; 48];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Convenience function for SHA-512 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha512(data: &[u8]) -> Result<[u8; 64], Error> {
    let digest = hash(&HashAlgorithm::SHA2_512, data)?;
    let mut result = [0u8; 64];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Convenience function for SHA3-224 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha3_224(data: &[u8]) -> Result<[u8; 28], Error> {
    let digest = hash(&HashAlgorithm::SHA3_224, data)?;
    let mut result = [0u8; 28];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Convenience function for SHA3-256 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha3_256(data: &[u8]) -> Result<[u8; 32], Error> {
    let digest = hash(&HashAlgorithm::SHA3_256, data)?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Convenience function for SHA3-384 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha3_384(data: &[u8]) -> Result<[u8; 48], Error> {
    let digest = hash(&HashAlgorithm::SHA3_384, data)?;
    let mut result = [0u8; 48];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Convenience function for SHA3-512 hash.
///
/// # Errors
///
/// Returns an error if NSS initialization fails or the hash operation fails.
pub fn sha3_512(data: &[u8]) -> Result<[u8; 64], Error> {
    let digest = hash(&HashAlgorithm::SHA3_512, data)?;
    let mut result = [0u8; 64];
    result.copy_from_slice(&digest);
    Ok(result)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use test_fixture::fixture_init;

    use super::*;

    #[test]
    fn test_sha256() {
        fixture_init();
        let data = b"hello world";
        let digest = sha256(data).unwrap();
        assert_eq!(digest.len(), 32);
        // Known SHA-256 hash of "hello world"
        assert_eq!(
            hex::encode(digest),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha384() {
        fixture_init();
        let data = b"hello world";
        let digest = sha384(data).unwrap();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_sha512() {
        fixture_init();
        let data = b"hello world";
        let digest = sha512(data).unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_sha3_224() {
        fixture_init();
        let data = b"hello world";
        let digest = sha3_224(data).unwrap();
        assert_eq!(digest.len(), 28);
    }

    #[test]
    fn test_sha3_256() {
        fixture_init();
        let data = b"hello world";
        let digest = sha3_256(data).unwrap();
        assert_eq!(digest.len(), 32);
        // Known SHA3-256 hash of "hello world"
        assert_eq!(
            hex::encode(digest),
            "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
        );
    }

    #[test]
    fn test_sha3_384() {
        fixture_init();
        let data = b"hello world";
        let digest = sha3_384(data).unwrap();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_sha3_512() {
        fixture_init();
        let data = b"hello world";
        let digest = sha3_512(data).unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_hash_empty() {
        fixture_init();
        let data = b"";
        let digest = sha256(data).unwrap();
        // Known SHA-256 hash of empty string
        assert_eq!(
            hex::encode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_algorithm_lengths() {
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA2_256), 32);
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA2_384), 48);
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA2_512), 64);
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA3_224), 28);
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA3_256), 32);
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA3_384), 48);
        assert_eq!(hash_alg_to_hash_len(&HashAlgorithm::SHA3_512), 64);
    }
}
