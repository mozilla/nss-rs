// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    convert::TryFrom as _,
    fmt::{self, Debug},
    os::raw::{c_char, c_int, c_uint},
    ptr::{null, null_mut},
};

use pkcs11_bindings::{CKA_ENCRYPT, CKM_AES_ECB, CKM_CHACHA20};

use crate::{
    SECItemBorrowed,
    constants::{
        Cipher, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
        Version,
    },
    err::{Error, Res, secstatus_to_res},
    p11::{
        CK_ATTRIBUTE_TYPE, CK_CHACHA20_PARAMS, CK_MECHANISM_TYPE, Context, PK11_CipherOp,
        PK11_CreateContextBySymKey, PK11_Encrypt, PK11_GetBlockSize, PK11SymKey, SymKey,
    },
};

experimental_api!(SSL_HkdfExpandLabelWithMech(
    version: Version,
    cipher: Cipher,
    prk: *mut PK11SymKey,
    handshake_hash: *const u8,
    handshake_hash_len: c_uint,
    label: *const c_char,
    label_len: c_uint,
    mech: CK_MECHANISM_TYPE,
    key_size: c_uint,
    secret: *mut *mut PK11SymKey,
));

/// Creates an AES-ECB `PK11Context` from a `SymKey`.
fn make_aes_ctx(key: &SymKey) -> Res<Context> {
    Context::from_ptr(unsafe {
        PK11_CreateContextBySymKey(
            CK_MECHANISM_TYPE::from(CKM_AES_ECB),
            CK_ATTRIBUTE_TYPE::from(CKA_ENCRYPT),
            **key,
            SECItemBorrowed::make_empty().as_ref(),
        )
    })
    .map_err(|_| Error::CipherInit)
}

pub enum Key {
    /// AES-ECB header-protection context.  `PK11_CloneContext` is not supported for
    /// AES-ECB, so the `SymKey` is stored alongside `ctx` to enable duplication via
    /// `try_clone`.
    #[non_exhaustive]
    Aes { ctx: Context, key: SymKey },
    /// The `ChaCha20` mask invokes `PK11_Encrypt` on each call because the counter
    /// and nonce change per invocation.
    #[non_exhaustive]
    Chacha(SymKey),
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "hp::Key")
    }
}

impl Key {
    pub const SAMPLE_SIZE: usize = 16;

    /// QUIC-specific API for extracting a header-protection key.
    ///
    /// # Errors
    ///
    /// Errors if HKDF fails or if the label is too long to fit in a `c_uint`.
    ///
    /// # Panics
    ///
    /// When `cipher` is not known to this code.
    pub fn extract(version: Version, cipher: Cipher, prk: &SymKey, label: &str) -> Res<Self> {
        let l = label.as_bytes();
        let mut secret: *mut PK11SymKey = null_mut();

        let (mech, key_size) = match cipher {
            TLS_AES_128_GCM_SHA256 => (CK_MECHANISM_TYPE::from(CKM_AES_ECB), 16),
            TLS_AES_256_GCM_SHA384 => (CK_MECHANISM_TYPE::from(CKM_AES_ECB), 32),
            TLS_CHACHA20_POLY1305_SHA256 => (CK_MECHANISM_TYPE::from(CKM_CHACHA20), 32),
            _ => unreachable!(),
        };

        // Note that this doesn't allow for passing null() for the handshake hash.
        // A zero-length slice produces an identical result.
        unsafe {
            SSL_HkdfExpandLabelWithMech(
                version,
                cipher,
                **prk,
                null(),
                0,
                l.as_ptr().cast(),
                c_uint::try_from(l.len())?,
                mech,
                key_size,
                &raw mut secret,
            )
        }?;
        let key = SymKey::from_ptr(secret).or(Err(Error::Hkdf))?;

        let res = match cipher {
            TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => {
                let ctx = make_aes_ctx(&key)?;
                Self::Aes { ctx, key }
            }
            TLS_CHACHA20_POLY1305_SHA256 => Self::Chacha(key),
            _ => unreachable!(),
        };

        debug_assert_eq!(
            res.block_size(),
            usize::try_from(unsafe { PK11_GetBlockSize(mech, null_mut()) })?
        );
        Ok(res)
    }

    const fn block_size(&self) -> usize {
        match self {
            Self::Aes { .. } => 16,
            Self::Chacha(_) => 64,
        }
    }

    /// Duplicate this key, creating a new independent instance.
    ///
    /// # Errors
    ///
    /// Errors if NSS context creation fails for AES keys.
    pub fn try_clone(&self) -> Res<Self> {
        match self {
            Self::Aes { key, .. } => {
                let key = key.clone();
                let ctx = make_aes_ctx(&key)?;
                Ok(Self::Aes { ctx, key })
            }
            Self::Chacha(k) => Ok(Self::Chacha(k.clone())),
        }
    }

    /// Generate a header protection mask for QUIC.
    ///
    /// # Errors
    ///
    /// An error is returned if the NSS functions fail.
    ///
    /// # Panics
    ///
    /// In debug builds, if NSS returns an unexpected output length.
    pub fn mask(&self, sample: &[u8; Self::SAMPLE_SIZE]) -> Res<[u8; Self::SAMPLE_SIZE]> {
        let mut output = [0; Self::SAMPLE_SIZE];

        match self {
            Self::Aes { ctx, .. } => {
                let mut output_len: c_int = 0;
                // SAFETY: `Deref` on `Context` copies the raw `*mut PK11Context` pointer
                // value; no Rust reference to the pointee is created.  `Key` contains raw
                // pointers (`!Sync`), so concurrent invocations are impossible, and
                // AES-ECB full-block operations retain no inter-call state in the context.
                secstatus_to_res(unsafe {
                    PK11_CipherOp(
                        **ctx,
                        output.as_mut_ptr(),
                        &raw mut output_len,
                        c_int::try_from(output.len())?,
                        sample.as_ptr().cast(),
                        c_int::try_from(Self::SAMPLE_SIZE)?,
                    )
                })?;
                debug_assert_eq!(usize::try_from(output_len)?, output.len());
                Ok(output)
            }

            Self::Chacha(key) => {
                let params: CK_CHACHA20_PARAMS = CK_CHACHA20_PARAMS {
                    pBlockCounter: sample.as_ptr().cast_mut(),
                    blockCounterBits: 32,
                    pNonce: sample[4..].as_ptr().cast_mut(),
                    ulNonceBits: 96,
                };
                let mut output_len: c_uint = 0;
                let mut param_item = SECItemBorrowed::wrap_struct(&params)?;
                secstatus_to_res(unsafe {
                    PK11_Encrypt(
                        **key,
                        CK_MECHANISM_TYPE::from(CKM_CHACHA20),
                        std::ptr::from_mut(param_item.as_mut()),
                        output[..].as_mut_ptr(),
                        &raw mut output_len,
                        c_uint::try_from(output.len())?,
                        [0; Self::SAMPLE_SIZE].as_ptr(),
                        c_uint::try_from(Self::SAMPLE_SIZE)?,
                    )
                })?;
                debug_assert_eq!(usize::try_from(output_len)?, output.len());
                Ok(output)
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::{
        constants::{TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3},
        hkdf,
        hp::Key,
    };

    #[test]
    fn debug_format() {
        test_fixture::fixture_init();
        let prk = hkdf::import_key(TLS_VERSION_1_3, &[0; 32]).unwrap();
        let key = Key::extract(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256, &prk, "test").unwrap();
        assert_eq!(format!("{key:?}"), "hp::Key");
    }
}
