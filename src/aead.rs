// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{os::raw::c_int, ptr::null_mut};

#[cfg(feature = "disable-encryption")]
pub use recprot::AEAD_NULL_TAG;
pub use recprot::RecordProtection;

use crate::{
    SECItemBorrowed, SymKey,
    err::{Error, Res},
    p11::{
        self, CK_ATTRIBUTE_TYPE, CK_GENERATOR_FUNCTION, CK_MECHANISM_TYPE, CKA_DECRYPT,
        CKA_ENCRYPT, CKA_NSS_MESSAGE, CKG_GENERATE_COUNTER_XOR, CKG_NO_GENERATE, CKM_AES_GCM,
        CKM_CHACHA20_POLY1305, Context, PK11_AEADOp, PK11_CreateContextBySymKey,
    },
    secstatus_to_res,
};

#[cfg(not(feature = "disable-encryption"))]
mod recprot {
    use std::{
        fmt,
        os::raw::{c_char, c_int, c_uint},
        ptr::{null, null_mut},
    };

    use crate::{
        Cipher, Error, Res, SECItemBorrowed, SymKey, Version,
        constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
        err::{sec::SEC_ERROR_BAD_DATA, secstatus_to_res},
        hp::SSL_HkdfExpandLabelWithMech,
        p11::{
            CK_ATTRIBUTE_TYPE, CK_GENERATOR_FUNCTION, CK_MECHANISM_TYPE, CKA_DECRYPT, CKA_ENCRYPT,
            CKA_NSS_MESSAGE, CKG_NO_GENERATE, CKM_AES_GCM, CKM_CHACHA20_POLY1305, CKM_HKDF_DATA,
            Context, PK11_AEADOp, PK11_CreateContextBySymKey, PK11SymKey,
        },
    };

    fn cipher_mech_and_key_len(cipher: Cipher) -> Res<(CK_MECHANISM_TYPE, c_uint)> {
        match cipher {
            TLS_AES_128_GCM_SHA256 => Ok((CK_MECHANISM_TYPE::from(CKM_AES_GCM), 16)),
            TLS_AES_256_GCM_SHA384 => Ok((CK_MECHANISM_TYPE::from(CKM_AES_GCM), 32)),
            TLS_CHACHA20_POLY1305_SHA256 => {
                Ok((CK_MECHANISM_TYPE::from(CKM_CHACHA20_POLY1305), 32))
            }
            _ => Err(Error::UnsupportedCipher),
        }
    }

    fn expand_label(
        version: Version,
        cipher: Cipher,
        secret: &SymKey,
        label: &str,
        mech: CK_MECHANISM_TYPE,
        key_len: c_uint,
    ) -> Res<SymKey> {
        let mut ptr: *mut PK11SymKey = null_mut();
        unsafe {
            SSL_HkdfExpandLabelWithMech(
                version,
                cipher,
                **secret,
                null(),
                0,
                label.as_ptr().cast::<c_char>(),
                c_uint::try_from(label.len())?,
                mech,
                key_len,
                &raw mut ptr,
            )
        }?;
        SymKey::from_ptr(ptr)
    }

    fn make_ctx(
        mech: CK_MECHANISM_TYPE,
        op: CK_ATTRIBUTE_TYPE,
        key: &SymKey,
        nonce_base: &[u8; super::NONCE_LEN],
    ) -> Res<Context> {
        let ptr = unsafe {
            PK11_CreateContextBySymKey(
                mech,
                op,
                **key,
                SECItemBorrowed::wrap(nonce_base.as_slice())?.as_ref(),
            )
        };
        Context::from_ptr(ptr)
    }

    /// Calls `PK11_AEADOp` with the fixed parameters for this module (`CKG_NO_GENERATE`, no
    /// counter generation) and returns the number of output bytes written.
    ///
    /// # Safety
    ///
    /// `output`, `tag`, and `input` must be valid for `output_max`, `TAG_LEN`, and `input_len`
    /// bytes respectively. `output` and `input` may fully overlap (in-place operation); `tag`
    /// must not overlap with the `output` region.
    #[expect(
        clippy::too_many_arguments,
        reason = "Thin wrapper over a 14-argument C function."
    )]
    unsafe fn aead_op(
        ctx: &Context,
        nonce_base: &[u8; super::NONCE_LEN],
        count: u64,
        aad: &[u8],
        output: *mut u8,
        output_max: usize,
        tag: *mut u8,
        input: *const u8,
        input_len: usize,
    ) -> Res<usize> {
        let mut nonce = super::xor_nonce(nonce_base, count);
        let mut out_len: c_int = 0;
        secstatus_to_res(unsafe {
            PK11_AEADOp(
                **ctx,
                CK_GENERATOR_FUNCTION::from(CKG_NO_GENERATE),
                super::c_int_len(super::NONCE_LEN - super::COUNTER_LEN)?,
                nonce.as_mut_ptr(),
                super::c_int_len(super::NONCE_LEN)?,
                aad.as_ptr(),
                super::c_int_len(aad.len())?,
                output,
                &raw mut out_len,
                super::c_int_len(output_max)?,
                tag,
                super::c_int_len(super::TAG_LEN)?,
                input,
                super::c_int_len(input_len)?,
            )
        })?;
        Ok(usize::try_from(out_len)?)
    }

    pub struct RecordProtection {
        ctx_encrypt: Context,
        ctx_decrypt: Context,
        nonce_base: [u8; super::NONCE_LEN],
    }

    impl RecordProtection {
        /// Create a new AEAD instance.
        ///
        /// # Errors
        ///
        /// Returns `Error` when the underlying crypto operations fail.
        pub fn new(version: Version, cipher: Cipher, secret: &SymKey, prefix: &str) -> Res<Self> {
            let (mech, key_len) = cipher_mech_and_key_len(cipher)?;
            let key = expand_label(
                version,
                cipher,
                secret,
                &format!("{prefix}key"),
                mech,
                key_len,
            )?;
            let iv_key = expand_label(
                version,
                cipher,
                secret,
                &format!("{prefix}iv"),
                CK_MECHANISM_TYPE::from(CKM_HKDF_DATA),
                c_uint::try_from(super::NONCE_LEN)?,
            )?;
            let nonce_base: [u8; super::NONCE_LEN] =
                iv_key.key_data()?.try_into().map_err(|_| Error::Internal)?;
            let ctx_encrypt = make_ctx(
                mech,
                CK_ATTRIBUTE_TYPE::from(CKA_NSS_MESSAGE | CKA_ENCRYPT),
                &key,
                &nonce_base,
            )?;
            let ctx_decrypt = make_ctx(
                mech,
                CK_ATTRIBUTE_TYPE::from(CKA_NSS_MESSAGE | CKA_DECRYPT),
                &key,
                &nonce_base,
            )?;
            Ok(Self {
                ctx_encrypt,
                ctx_decrypt,
                nonce_base,
            })
        }

        /// Get the expansion size (authentication tag length) for this AEAD.
        #[must_use]
        #[expect(clippy::missing_const_for_fn, clippy::unused_self)]
        pub fn expansion(&self) -> usize {
            super::TAG_LEN
        }

        /// Encrypt plaintext with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when encryption fails.
        pub fn encrypt<'a>(
            &self,
            count: u64,
            aad: &[u8],
            input: &[u8],
            output: &'a mut [u8],
        ) -> Res<&'a [u8]> {
            if output.len()
                < input
                    .len()
                    .checked_add(super::TAG_LEN)
                    .ok_or(Error::IntegerOverflow)?
            {
                return Err(Error::from(SEC_ERROR_BAD_DATA));
            }
            let out_len = unsafe {
                aead_op(
                    &self.ctx_encrypt,
                    &self.nonce_base,
                    count,
                    aad,
                    output.as_mut_ptr(),
                    input.len(),
                    output.as_mut_ptr().add(input.len()),
                    input.as_ptr(),
                    input.len(),
                )
            }?;
            debug_assert_eq!(out_len, input.len());
            Ok(&output[..out_len + super::TAG_LEN])
        }

        /// Encrypt plaintext in place with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when encryption fails.
        pub fn encrypt_in_place(&self, count: u64, aad: &[u8], data: &mut [u8]) -> Res<usize> {
            if data.len() < self.expansion() {
                return Err(Error::from(SEC_ERROR_BAD_DATA));
            }
            let pt_len = data.len() - self.expansion();
            let data_ptr = data.as_mut_ptr();
            let out_len = unsafe {
                aead_op(
                    &self.ctx_encrypt,
                    &self.nonce_base,
                    count,
                    aad,
                    data_ptr,
                    pt_len,
                    data_ptr.add(pt_len),
                    data_ptr.cast_const(),
                    pt_len,
                )
            }?;
            debug_assert_eq!(out_len, pt_len);
            Ok(data.len())
        }

        /// Decrypt ciphertext with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when decryption or authentication fails.
        pub fn decrypt<'a>(
            &self,
            count: u64,
            aad: &[u8],
            input: &[u8],
            output: &'a mut [u8],
        ) -> Res<&'a [u8]> {
            let ct_len = input
                .len()
                .checked_sub(super::TAG_LEN)
                .ok_or_else(|| Error::from(SEC_ERROR_BAD_DATA))?;
            if output.len() < ct_len {
                return Err(Error::from(SEC_ERROR_BAD_DATA));
            }
            let mut tag = [0u8; super::TAG_LEN];
            tag.copy_from_slice(&input[ct_len..]);
            let out_len = unsafe {
                aead_op(
                    &self.ctx_decrypt,
                    &self.nonce_base,
                    count,
                    aad,
                    output.as_mut_ptr(),
                    output.len(),
                    tag.as_mut_ptr(),
                    input.as_ptr(),
                    ct_len,
                )
            }?;
            Ok(&output[..out_len])
        }

        /// Decrypt ciphertext in place with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when decryption or authentication fails.
        pub fn decrypt_in_place(&self, count: u64, aad: &[u8], data: &mut [u8]) -> Res<usize> {
            let ct_len = data
                .len()
                .checked_sub(super::TAG_LEN)
                .ok_or_else(|| Error::from(SEC_ERROR_BAD_DATA))?;
            let data_ptr = data.as_mut_ptr();
            let out_len = unsafe {
                aead_op(
                    &self.ctx_decrypt,
                    &self.nonce_base,
                    count,
                    aad,
                    data_ptr,
                    data.len(),
                    data_ptr.add(ct_len),
                    data_ptr.cast_const(),
                    ct_len,
                )
            }?;
            debug_assert_eq!(out_len, ct_len);
            Ok(ct_len)
        }
    }

    impl fmt::Debug for RecordProtection {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "[AEAD Context]")
        }
    }
}

#[cfg(feature = "disable-encryption")]
mod recprot {
    use std::fmt;

    use crate::{Cipher, Error, Res, SymKey, Version, err::sec::SEC_ERROR_BAD_DATA};

    pub const AEAD_NULL_TAG: &[u8] = &[0x0a; 16];

    pub struct RecordProtection {}

    impl RecordProtection {
        fn decrypt_check(&self, _count: u64, _aad: &[u8], input: &[u8]) -> Res<usize> {
            if input.len() < self.expansion() {
                return Err(Error::from(SEC_ERROR_BAD_DATA));
            }

            let len_encrypted = input
                .len()
                .checked_sub(self.expansion())
                .ok_or_else(|| Error::from(SEC_ERROR_BAD_DATA))?;
            // Check that:
            // 1) expansion is all zeros and
            // 2) if the encrypted data is also supplied that at least some values are no zero
            //    (otherwise padding will be interpreted as a valid packet)
            if &input[len_encrypted..] == AEAD_NULL_TAG
                && (len_encrypted == 0 || input[..len_encrypted].iter().any(|x| *x != 0x0))
            {
                Ok(len_encrypted)
            } else {
                Err(Error::from(SEC_ERROR_BAD_DATA))
            }
        }

        /// Create a new AEAD instance.
        ///
        /// # Errors
        ///
        /// Returns `Error` when the underlying crypto operations fail.
        #[expect(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
        pub fn new(
            _version: Version,
            _cipher: Cipher,
            _secret: &SymKey,
            _prefix: &str,
        ) -> Res<Self> {
            Ok(Self {})
        }

        /// Get the expansion size (authentication tag length) for this AEAD.
        #[must_use]
        #[expect(clippy::missing_const_for_fn, clippy::unused_self)]
        pub fn expansion(&self) -> usize {
            AEAD_NULL_TAG.len()
        }

        /// Encrypt plaintext with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when encryption fails.
        #[expect(clippy::unnecessary_wraps)]
        pub fn encrypt<'a>(
            &self,
            _count: u64,
            _aad: &[u8],
            input: &[u8],
            output: &'a mut [u8],
        ) -> Res<&'a [u8]> {
            let l = input.len();
            output[..l].copy_from_slice(input);
            output[l..l + self.expansion()].copy_from_slice(AEAD_NULL_TAG);
            Ok(&output[..l + self.expansion()])
        }

        /// Encrypt plaintext in place with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when encryption fails.
        #[expect(clippy::unnecessary_wraps)]
        pub fn encrypt_in_place(&self, _count: u64, _aad: &[u8], data: &mut [u8]) -> Res<usize> {
            let pos = data.len() - self.expansion();
            data[pos..].copy_from_slice(AEAD_NULL_TAG);
            Ok(data.len())
        }

        /// Decrypt ciphertext with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when decryption or authentication fails.
        pub fn decrypt<'a>(
            &self,
            count: u64,
            aad: &[u8],
            input: &[u8],
            output: &'a mut [u8],
        ) -> Res<&'a [u8]> {
            self.decrypt_check(count, aad, input).map(|len| {
                output[..len].copy_from_slice(&input[..len]);
                &output[..len]
            })
        }

        /// Decrypt ciphertext in place with associated data.
        ///
        /// # Errors
        ///
        /// Returns `Error` when decryption or authentication fails.
        #[expect(
            clippy::needless_pass_by_ref_mut,
            reason = "Copy encryption enabled API"
        )]
        pub fn decrypt_in_place(&self, count: u64, aad: &[u8], data: &mut [u8]) -> Res<usize> {
            self.decrypt_check(count, aad, data)
        }
    }

    impl fmt::Debug for RecordProtection {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "[NULL AEAD]")
        }
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    mod tests {
        use super::{AEAD_NULL_TAG, RecordProtection};

        fn aead() -> RecordProtection {
            RecordProtection {}
        }

        #[test]
        fn expansion() {
            assert_eq!(aead().expansion(), AEAD_NULL_TAG.len());
        }

        #[test]
        fn debug() {
            assert_eq!(format!("{:?}", aead()), "[NULL AEAD]");
        }

        #[test]
        fn encrypt_decrypt_roundtrip() {
            let a = aead();
            let plaintext = b"hello world";
            let mut out = vec![0u8; plaintext.len() + a.expansion()];
            let encrypted = a.encrypt(0, b"aad", plaintext, &mut out).unwrap();
            assert_eq!(encrypted.len(), plaintext.len() + a.expansion());
            assert_eq!(&encrypted[..plaintext.len()], plaintext);
            assert_eq!(&encrypted[plaintext.len()..], AEAD_NULL_TAG);

            let mut dec_out = vec![0u8; plaintext.len()];
            let decrypted = a.decrypt(0, b"aad", encrypted, &mut dec_out).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn encrypt_in_place_roundtrip() {
            let a = aead();
            let plaintext = b"hello";
            let mut buf = plaintext.to_vec();
            buf.resize(plaintext.len() + a.expansion(), 0);
            let len = a.encrypt_in_place(0, b"", &mut buf).unwrap();
            assert_eq!(len, buf.len());
            assert_eq!(&buf[plaintext.len()..], AEAD_NULL_TAG);

            let dec_len = a.decrypt_in_place(0, b"", &mut buf).unwrap();
            assert_eq!(dec_len, plaintext.len());
            assert_eq!(&buf[..dec_len], plaintext);
        }

        #[test]
        fn decrypt_empty_plaintext() {
            // Zero-length plaintext (just the tag) is valid.
            let a = aead();
            let mut out = vec![0u8; a.expansion()];
            a.encrypt(0, b"", b"", &mut out).unwrap();
            let mut dec = vec![];
            let res = a.decrypt(0, b"", &out, &mut dec).unwrap();
            assert_eq!(res, b"");
        }

        #[test]
        fn decrypt_fails_too_short() {
            let a = aead();
            let short = &AEAD_NULL_TAG[..a.expansion() - 1];
            assert!(a.decrypt(0, b"", short, &mut []).is_err());
        }

        #[test]
        fn decrypt_fails_bad_tag() {
            let a = aead();
            let plaintext = b"test";
            let mut buf = vec![0u8; plaintext.len() + a.expansion()];
            a.encrypt(0, b"", plaintext, &mut buf).unwrap();
            // Corrupt the tag.
            let tag_start = plaintext.len();
            buf[tag_start] ^= 0xff;
            assert!(a.decrypt(0, b"", &buf, &mut []).is_err());
        }

        #[test]
        fn decrypt_rejects_all_zero_data_bytes() {
            // All-zero plaintext with correct tag should fail (looks like padding).
            let a = aead();
            let mut buf = vec![0u8; 4 + a.expansion()];
            buf[4..].copy_from_slice(AEAD_NULL_TAG);
            assert!(a.decrypt(0, b"", &buf, &mut []).is_err());
        }
    }
}

/// All the nonces are the same length.  Exploit that.
pub const NONCE_LEN: usize = 12;

/// The portion of the nonce that is a counter.
const COUNTER_LEN: usize = size_of::<SequenceNumber>();

fn xor_nonce(base: &[u8; NONCE_LEN], count: SequenceNumber) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    for (n, &s) in nonce[NONCE_LEN - COUNTER_LEN..]
        .iter_mut()
        .zip(&count.to_be_bytes())
    {
        *n ^= s;
    }
    nonce
}

/// The NSS API insists on us identifying the tag separately, which is awful.
/// All of the AEAD functions here have a tag of this length, so use a fixed offset.
const TAG_LEN: usize = 16;

pub type SequenceNumber = u64;

/// All the lengths used by `PK11_AEADOp` are signed.  This converts to that.
fn c_int_len<T>(l: T) -> Res<c_int>
where
    T: TryInto<c_int>,
    T::Error: std::error::Error,
{
    l.try_into().map_err(|_| Error::IntegerOverflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl Mode {
    fn p11mode(self) -> CK_ATTRIBUTE_TYPE {
        CK_ATTRIBUTE_TYPE::from(
            CKA_NSS_MESSAGE
                | match self {
                    Self::Encrypt => CKA_ENCRYPT,
                    Self::Decrypt => CKA_DECRYPT,
                },
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlgorithms {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct Aead {
    mode: Mode,
    ctx: Context,
    nonce_base: [u8; NONCE_LEN],
}

impl Aead {
    fn mech(algorithm: AeadAlgorithms) -> CK_MECHANISM_TYPE {
        CK_MECHANISM_TYPE::from(match algorithm {
            AeadAlgorithms::Aes128Gcm | AeadAlgorithms::Aes256Gcm => CKM_AES_GCM,
            AeadAlgorithms::ChaCha20Poly1305 => CKM_CHACHA20_POLY1305,
        })
    }

    fn make_nonce(nonce: &mut [u8; NONCE_LEN], seq: SequenceNumber) {
        *nonce = xor_nonce(nonce, seq);
    }

    pub fn import_key(algorithm: AeadAlgorithms, key: &[u8]) -> Result<SymKey, Error> {
        let slot = p11::Slot::internal().map_err(|_| Error::Internal)?;

        let key_item = SECItemBorrowed::wrap(key)?;
        let key_item_ptr = std::ptr::from_ref(key_item.as_ref()).cast_mut();

        let ptr = unsafe {
            p11::PK11_ImportSymKey(
                *slot,
                Self::mech(algorithm),
                p11::PK11Origin::PK11_OriginUnwrap,
                CK_ATTRIBUTE_TYPE::from(CKA_ENCRYPT | CKA_DECRYPT),
                key_item_ptr,
                null_mut(),
            )
        };
        SymKey::from_ptr(ptr)
    }

    pub fn new(
        mode: Mode,
        algorithm: AeadAlgorithms,
        key: &SymKey,
        nonce_base: [u8; NONCE_LEN],
    ) -> Result<Self, Error> {
        crate::init()?;

        let ptr = unsafe {
            PK11_CreateContextBySymKey(
                Self::mech(algorithm),
                mode.p11mode(),
                **key,
                SECItemBorrowed::wrap(&nonce_base[..])?.as_ref(),
            )
        };
        Ok(Self {
            mode,
            ctx: Context::from_ptr(ptr)?,
            nonce_base,
        })
    }

    pub fn encrypt(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
        crate::init()?;

        assert_eq!(self.mode, Mode::Encrypt);
        // A copy for the nonce generator to write into.  But we don't use the value.
        let mut nonce = self.nonce_base;
        // Ciphertext with enough space for the tag.
        // Even though we give the operation a separate buffer for the tag,
        // reserve the capacity on allocation.
        let mut ct = vec![0; pt.len() + TAG_LEN];
        let mut ct_len: c_int = 0;
        let mut tag = vec![0; TAG_LEN];
        secstatus_to_res(unsafe {
            PK11_AEADOp(
                *self.ctx,
                CK_GENERATOR_FUNCTION::from(CKG_GENERATE_COUNTER_XOR),
                c_int_len(NONCE_LEN - COUNTER_LEN)?, // Fixed portion of the nonce.
                nonce.as_mut_ptr(),
                c_int_len(nonce.len())?,
                aad.as_ptr(),
                c_int_len(aad.len())?,
                ct.as_mut_ptr(),
                &raw mut ct_len,
                c_int_len(ct.len())?, // signed :(
                tag.as_mut_ptr(),
                c_int_len(tag.len())?,
                pt.as_ptr(),
                c_int_len(pt.len())?,
            )
        })?;
        ct.truncate(usize::try_from(ct_len).map_err(|_| Error::IntegerOverflow)?);
        debug_assert_eq!(ct.len(), pt.len());
        ct.append(&mut tag);
        Ok(ct)
    }

    /// Encrypt with an explicit sequence number. Mirrors `decrypt`'s nonce
    /// construction: the final nonce is `nonce_base XOR encode_be(seq)` over
    /// the trailing 8 bytes. The NSS PKCS#11 context's internal counter is
    /// not used (`CKG_NO_GENERATE`). The caller must never reuse
    /// `(nonce_base, seq)` with the same key.
    pub fn encrypt_with_seq(
        &mut self,
        aad: &[u8],
        seq: SequenceNumber,
        pt: &[u8],
    ) -> Result<Vec<u8>, Error> {
        crate::init()?;

        assert_eq!(self.mode, Mode::Encrypt);
        let mut nonce = self.nonce_base;
        Self::make_nonce(&mut nonce, seq);
        let mut ct = vec![0; pt.len() + TAG_LEN];
        let mut ct_len: c_int = 0;
        let mut tag = vec![0; TAG_LEN];
        secstatus_to_res(unsafe {
            PK11_AEADOp(
                *self.ctx,
                CK_GENERATOR_FUNCTION::from(CKG_NO_GENERATE),
                c_int_len(NONCE_LEN - COUNTER_LEN)?,
                nonce.as_mut_ptr(),
                c_int_len(nonce.len())?,
                aad.as_ptr(),
                c_int_len(aad.len())?,
                ct.as_mut_ptr(),
                &raw mut ct_len,
                c_int_len(ct.len())?,
                tag.as_mut_ptr(),
                c_int_len(tag.len())?,
                pt.as_ptr(),
                c_int_len(pt.len())?,
            )
        })?;
        ct.truncate(usize::try_from(ct_len).map_err(|_| Error::IntegerOverflow)?);
        debug_assert_eq!(ct.len(), pt.len());
        ct.append(&mut tag);
        Ok(ct)
    }

    pub fn decrypt(
        &mut self,
        aad: &[u8],
        seq: SequenceNumber,
        ct: &[u8],
    ) -> Result<Vec<u8>, Error> {
        crate::init()?;

        assert_eq!(self.mode, Mode::Decrypt);
        let mut nonce = self.nonce_base;
        Self::make_nonce(&mut nonce, seq);
        let mut pt = vec![0; ct.len()]; // NSS needs more space than it uses for plaintext.
        let mut pt_len: c_int = 0;
        let pt_expected = ct.len().checked_sub(TAG_LEN).ok_or(Error::AeadTruncated)?;
        secstatus_to_res(unsafe {
            PK11_AEADOp(
                *self.ctx,
                CK_GENERATOR_FUNCTION::from(CKG_NO_GENERATE),
                c_int_len(NONCE_LEN - COUNTER_LEN)?, // Fixed portion of the nonce.
                nonce.as_mut_ptr(),
                c_int_len(nonce.len())?,
                aad.as_ptr(),
                c_int_len(aad.len())?,
                pt.as_mut_ptr(),
                &raw mut pt_len,
                c_int_len(pt.len())?,
                ct.as_ptr().add(pt_expected).cast_mut(),
                c_int_len(TAG_LEN)?,
                ct.as_ptr(),
                c_int_len(pt_expected)?,
            )
        })?;
        let len = usize::try_from(pt_len).map_err(|_| Error::IntegerOverflow)?;
        debug_assert_eq!(len, pt_expected);
        pt.truncate(len);
        Ok(pt)
    }
}

#[cfg(test)]
mod test {
    use test_fixture::fixture_init;

    use crate::aead::{Aead, AeadAlgorithms, Mode, NONCE_LEN, SequenceNumber};

    /// Check that the first invocation of encryption matches expected values.
    /// Also check decryption of the same.
    fn check0(
        algorithm: AeadAlgorithms,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
        ct: &[u8],
    ) {
        fixture_init();
        let k = Aead::import_key(algorithm, key).unwrap();

        let mut enc = Aead::new(Mode::Encrypt, algorithm, &k, *nonce).unwrap();
        let ciphertext = enc.encrypt(aad, pt).unwrap();
        assert_eq!(&ciphertext[..], ct);

        let mut dec = Aead::new(Mode::Decrypt, algorithm, &k, *nonce).unwrap();
        let plaintext = dec.decrypt(aad, 0, ct).unwrap();
        assert_eq!(&plaintext[..], pt);
    }

    fn decrypt(
        algorithm: AeadAlgorithms,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        seq: SequenceNumber,
        aad: &[u8],
        pt: &[u8],
        ct: &[u8],
    ) {
        let k = Aead::import_key(algorithm, key).unwrap();
        let mut dec = Aead::new(Mode::Decrypt, algorithm, &k, *nonce).unwrap();
        let plaintext = dec.decrypt(aad, seq, ct).unwrap();
        assert_eq!(&plaintext[..], pt);
    }

    /// This tests the AEAD in QUIC in combination with the HKDF code.
    /// This is an AEAD-only example.
    #[test]
    fn quic_retry() {
        const KEY: &[u8] = &[
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
            0xc8, 0x4e,
        ];
        const NONCE: &[u8; NONCE_LEN] = &[
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
        ];
        const AAD: &[u8] = &[
            0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0xff, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65,
            0x6e,
        ];
        const CT: &[u8] = &[
            0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24,
            0x96, 0xba,
        ];
        check0(AeadAlgorithms::Aes128Gcm, KEY, NONCE, AAD, &[], CT);
    }

    #[test]
    fn quic_server_initial() {
        const ALG: AeadAlgorithms = AeadAlgorithms::Aes128Gcm;
        const KEY: &[u8] = &[
            0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06,
            0x7e, 0x37,
        ];
        const NONCE_BASE: &[u8; NONCE_LEN] = &[
            0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
        ];
        // Note that this integrates the sequence number of 1 from the example,
        // otherwise we can't use a sequence number of 0 to encrypt.
        const NONCE: &[u8; NONCE_LEN] = &[
            0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3f,
        ];
        const AAD: &[u8] = &[
            0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
        ];
        const PT: &[u8] = &[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
            0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
            0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
            0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
            0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
            0x04,
        ];
        const CT: &[u8] = &[
            0x5a, 0x48, 0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac, 0x40, 0x6a, 0x58, 0x16,
            0xb6, 0x39, 0x41, 0x00, 0xf3, 0x7a, 0x1c, 0x69, 0x79, 0x75, 0x54, 0x78, 0x0b, 0xb3,
            0x8c, 0xc5, 0xa9, 0x9f, 0x5e, 0xde, 0x4c, 0xf7, 0x3c, 0x3e, 0xc2, 0x49, 0x3a, 0x18,
            0x39, 0xb3, 0xdb, 0xcb, 0xa3, 0xf6, 0xea, 0x46, 0xc5, 0xb7, 0x68, 0x4d, 0xf3, 0x54,
            0x8e, 0x7d, 0xde, 0xb9, 0xc3, 0xbf, 0x9c, 0x73, 0xcc, 0x3f, 0x3b, 0xde, 0xd7, 0x4b,
            0x56, 0x2b, 0xfb, 0x19, 0xfb, 0x84, 0x02, 0x2f, 0x8e, 0xf4, 0xcd, 0xd9, 0x37, 0x95,
            0xd7, 0x7d, 0x06, 0xed, 0xbb, 0x7a, 0xaf, 0x2f, 0x58, 0x89, 0x18, 0x50, 0xab, 0xbd,
            0xca, 0x3d, 0x20, 0x39, 0x8c, 0x27, 0x64, 0x56, 0xcb, 0xc4, 0x21, 0x58, 0x40, 0x7d,
            0xd0, 0x74, 0xee,
        ];
        check0(ALG, KEY, NONCE, AAD, PT, CT);
        decrypt(ALG, KEY, NONCE_BASE, 1, AAD, PT, CT);
    }

    #[test]
    fn quic_chacha() {
        const ALG: AeadAlgorithms = AeadAlgorithms::ChaCha20Poly1305;
        const KEY: &[u8] = &[
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c,
            0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79,
            0xfb, 0x23, 0xe1, 0xc8,
        ];
        const NONCE_BASE: &[u8; NONCE_LEN] = &[
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
        ];
        // Note that this integrates the sequence number of 654360564 from the example,
        // otherwise we can't use a sequence number of 0 to encrypt.
        const NONCE: &[u8; NONCE_LEN] = &[
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x6d, 0x41, 0x7e, 0xb0,
        ];
        const AAD: &[u8] = &[0x42, 0x00, 0xbf, 0xf4];
        const PT: &[u8] = &[0x01];
        const CT: &[u8] = &[
            0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2,
            0x5a, 0x5b, 0xfb,
        ];
        check0(ALG, KEY, NONCE, AAD, PT, CT);
        // Now use the real nonce and sequence number from the example.
        decrypt(ALG, KEY, NONCE_BASE, 654_360_564, AAD, PT, CT);
    }

    fn roundtrip_encrypt_with_seq(algorithm: AeadAlgorithms, key: &[u8]) {
        const NONCE_BASE: [u8; NONCE_LEN] = [0; NONCE_LEN];
        const AAD: &[u8] = b"associated";
        const PT: &[u8] = b"hello sframe";
        const SEQ: SequenceNumber = 0x0123_4567_89ab;

        fixture_init();

        let k = Aead::import_key(algorithm, key).unwrap();
        let mut enc = Aead::new(Mode::Encrypt, algorithm, &k, NONCE_BASE).unwrap();
        let ct = enc.encrypt_with_seq(AAD, SEQ, PT).unwrap();

        let mut dec = Aead::new(Mode::Decrypt, algorithm, &k, NONCE_BASE).unwrap();
        let pt = dec.decrypt(AAD, SEQ, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn encrypt_with_seq_aes128gcm() {
        const KEY: &[u8] = &[0x42; 16];
        roundtrip_encrypt_with_seq(AeadAlgorithms::Aes128Gcm, KEY);
    }

    #[test]
    fn encrypt_with_seq_aes256gcm() {
        const KEY: &[u8] = &[0x42; 32];
        roundtrip_encrypt_with_seq(AeadAlgorithms::Aes256Gcm, KEY);
    }

    #[test]
    fn encrypt_with_seq_chacha20poly1305() {
        const KEY: &[u8] = &[0x42; 32];
        roundtrip_encrypt_with_seq(AeadAlgorithms::ChaCha20Poly1305, KEY);
    }
}
