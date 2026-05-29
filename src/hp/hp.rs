// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// PKCS#11 backend for hp::Key: calls PK11_CipherOp and PK11_Encrypt through
// the softoken session layer.

use std::{
    os::raw::{c_int, c_uint},
    ptr::{null, null_mut},
};

use pkcs11_bindings::{CKA_ENCRYPT, CKM_AES_ECB, CKM_CHACHA20};

use super::{SAMPLE_SIZE, SSL_HkdfExpandLabelWithMech};
use crate::{
    SECItemBorrowed,
    aead::AeadAlgorithms,
    constants::{Cipher, Version},
    err::{Error, Res, secstatus_to_res},
    p11::{
        CK_ATTRIBUTE_TYPE, CK_CHACHA20_PARAMS, CK_MECHANISM_TYPE, Context, PK11_CipherOp,
        PK11_CreateContextBySymKey, PK11_Encrypt, PK11_GetBlockSize, PK11SymKey, SymKey,
    },
};

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

enum KeyKind {
    // PK11_CloneContext is not supported for AES-ECB, so the SymKey is stored
    // alongside ctx to enable duplication via try_clone.
    Aes { ctx: Context, key: SymKey },
    // The ChaCha20 mask invokes PK11_Encrypt on each call because the counter
    // and nonce change per invocation.
    Chacha(SymKey),
}

pub struct Key {
    kind: KeyKind,
}

impl Key {
    pub fn extract(version: Version, cipher: Cipher, prk: &SymKey, label: &str) -> Res<Self> {
        let l = label.as_bytes();
        let mut secret: *mut PK11SymKey = null_mut();
        let spec = AeadAlgorithms::try_from(cipher)?;

        // Derive all spec-dependent values in one place so the AES-vs-ChaCha
        // decision is made exactly once.
        let (mech, make_kind): (CK_MECHANISM_TYPE, fn(SymKey) -> Res<KeyKind>) = match spec {
            AeadAlgorithms::Aes128Gcm | AeadAlgorithms::Aes256Gcm => {
                (CK_MECHANISM_TYPE::from(CKM_AES_ECB), |key| {
                    Ok(KeyKind::Aes {
                        ctx: make_aes_ctx(&key)?,
                        key,
                    })
                })
            }
            AeadAlgorithms::ChaCha20Poly1305 => (CK_MECHANISM_TYPE::from(CKM_CHACHA20), |key| {
                Ok(KeyKind::Chacha(key))
            }),
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
                spec.key_len(),
                &raw mut secret,
            )
        }?;
        let key = SymKey::from_ptr(secret).or(Err(Error::Hkdf))?;
        let kind = make_kind(key)?;

        debug_assert_eq!(
            match spec {
                AeadAlgorithms::Aes128Gcm | AeadAlgorithms::Aes256Gcm => 16,
                AeadAlgorithms::ChaCha20Poly1305 => 64,
            },
            usize::try_from(unsafe { PK11_GetBlockSize(mech, null_mut()) })?
        );
        Ok(Self { kind })
    }

    pub fn try_clone(&self) -> Res<Self> {
        let kind = match &self.kind {
            KeyKind::Aes { key, .. } => {
                let key = key.clone();
                let ctx = make_aes_ctx(&key)?;
                KeyKind::Aes { ctx, key }
            }
            KeyKind::Chacha(k) => KeyKind::Chacha(k.clone()),
        };
        Ok(Self { kind })
    }

    pub fn mask(&self, sample: &[u8; SAMPLE_SIZE]) -> Res<[u8; SAMPLE_SIZE]> {
        let mut output = [0u8; SAMPLE_SIZE];
        match &self.kind {
            KeyKind::Aes { ctx, .. } => {
                let mut output_len: c_int = 0;
                // SAFETY: Deref on Context copies the raw *mut PK11Context pointer
                // value; no Rust reference to the pointee is created.  Key is !Sync,
                // so concurrent invocations are impossible, and AES-ECB full-block
                // operations retain no inter-call state in the context.
                secstatus_to_res(unsafe {
                    PK11_CipherOp(
                        **ctx,
                        output.as_mut_ptr(),
                        &raw mut output_len,
                        c_int::try_from(output.len())?,
                        sample.as_ptr().cast(),
                        c_int::try_from(SAMPLE_SIZE)?,
                    )
                })?;
                debug_assert_eq!(usize::try_from(output_len)?, output.len());
                Ok(output)
            }
            KeyKind::Chacha(key) => {
                let params = CK_CHACHA20_PARAMS {
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
                        [0u8; SAMPLE_SIZE].as_ptr(),
                        c_uint::try_from(SAMPLE_SIZE)?,
                    )
                })?;
                debug_assert_eq!(usize::try_from(output_len)?, output.len());
                Ok(output)
            }
        }
    }
}
