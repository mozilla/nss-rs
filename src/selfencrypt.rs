// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{fmt::Write as _, io::Write as _, mem};

use log::{info, trace};

use crate::{
    aead::{Aead, AeadAlgorithms, Mode, NONCE_LEN},
    err::{Error, Res},
    hkdf::{Hkdf, HkdfAlgorithm},
    p11::{CKA_DECRYPT, CKA_ENCRYPT, SymKey, random},
};

#[must_use]
pub fn hex<A: AsRef<[u8]>>(buf: A) -> String {
    let mut ret = String::with_capacity(buf.as_ref().len() * 2);
    for b in buf.as_ref() {
        write!(&mut ret, "{b:02x}").expect("write OK");
    }
    ret
}

/// The authentication tag length of all supported AEAD algorithms.
const TAG_LEN: usize = 16;

/// The length of the key used with each HKDF algorithm.
const fn kdf_key_len(kdf: HkdfAlgorithm) -> usize {
    match kdf {
        HkdfAlgorithm::HKDF_SHA2_256 => 32,
        HkdfAlgorithm::HKDF_SHA2_384 => 48,
        HkdfAlgorithm::HKDF_SHA2_512 => 64,
    }
}

const MAX_KDF_KEY_LEN: usize = kdf_key_len(HkdfAlgorithm::HKDF_SHA2_512);

#[derive(Debug)]
pub struct SelfEncrypt {
    kdf: HkdfAlgorithm,
    aead: AeadAlgorithms,
    key_id: u8,
    key: SymKey,
    old_key: Option<SymKey>,
}

impl SelfEncrypt {
    const VERSION: u8 = 1;
    const SALT_LENGTH: usize = 16;
    /// Version, key ID, and salt.
    const HEADER_LEN: usize = 2 + Self::SALT_LENGTH;

    /// Create a new instance that derives keys with `kdf` and protects data with `aead`.
    ///
    /// # Errors
    ///
    /// Failure to generate a new HKDF key using NSS results in an error.
    pub fn new(kdf: HkdfAlgorithm, aead: AeadAlgorithms) -> Res<Self> {
        let key = Self::generate_key(kdf)?;
        Ok(Self {
            kdf,
            aead,
            key_id: 0,
            key,
            old_key: None,
        })
    }

    fn generate_key(kdf: HkdfAlgorithm) -> Res<SymKey> {
        let ikm = random::<MAX_KDF_KEY_LEN>();
        Hkdf::new(kdf).import_secret(&ikm[..kdf_key_len(kdf)])
    }

    fn make_aead(&self, k: &SymKey, salt: &[u8], mode: Mode) -> Res<Aead> {
        debug_assert_eq!(salt.len(), Self::SALT_LENGTH);
        let hkdf = Hkdf::new(self.kdf);
        let prk = hkdf.extract(salt, k)?;
        let operation = match mode {
            Mode::Encrypt => CKA_ENCRYPT,
            Mode::Decrypt => CKA_DECRYPT,
        };
        let key = hkdf.expand_key_with_mech(
            &prk,
            b"neqo self key",
            self.aead.p11_mech(),
            operation,
            usize::try_from(self.aead.key_len())?,
        )?;
        let nonce_base: [u8; NONCE_LEN] = hkdf
            .expand_data(&prk, b"neqo self iv", NONCE_LEN)?
            .try_into()
            .map_err(|_| Error::Internal)?;
        Aead::new(mode, self.aead, &key, nonce_base)
    }

    /// Rotate keys.  This causes any previous key that is being held to be replaced by the current
    /// key.
    ///
    /// # Errors
    ///
    /// Failure to generate a new HKDF key using NSS results in an error.
    pub fn rotate(&mut self) -> Res<()> {
        let new_key = Self::generate_key(self.kdf)?;
        self.old_key = Some(mem::replace(&mut self.key, new_key));
        let (kid, _) = self.key_id.overflowing_add(1);
        self.key_id = kid;
        info!("[SelfEncrypt] Rotated keys to {}", self.key_id);
        Ok(())
    }

    /// Seal an item using the underlying key.  This produces a single buffer that contains
    /// the encrypted `plaintext`, plus a version number and salt.
    /// `aad` is only used as input to the AEAD, it is not included in the output; the
    /// caller is responsible for carrying the AAD as appropriate.
    ///
    /// # Errors
    ///
    /// Failure to protect using NSS AEAD APIs produces an error.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Res<Vec<u8>> {
        // Format is:
        // struct {
        //   uint8 version;
        //   uint8 key_id;
        //   uint8 salt[16];
        //   opaque aead_encrypted(plaintext)[length as expanded];
        // };
        // AAD covers the entire header, plus the value of the AAD parameter that is provided.
        let salt = random::<{ Self::SALT_LENGTH }>();
        let mut cipher = self.make_aead(&self.key, &salt, Mode::Encrypt)?;
        let encoded_len = Self::HEADER_LEN + plaintext.len() + TAG_LEN;

        let mut extended_aad = Vec::<u8>::with_capacity(Self::HEADER_LEN + aad.len());
        extended_aad.push(Self::VERSION);
        extended_aad.push(self.key_id);
        extended_aad.extend_from_slice(&salt);
        extended_aad.extend_from_slice(aad);

        // Each salt produces a fresh key, so a fixed sequence number is safe.
        let ct = cipher.encrypt_with_seq(extended_aad.as_ref(), 0, plaintext)?;
        let mut output = Vec::<u8>::with_capacity(encoded_len);
        output.extend_from_slice(&extended_aad[..Self::HEADER_LEN]);
        output.extend_from_slice(&ct);
        trace!(
            "[SelfEncrypt] seal {} {} -> {}",
            hex(aad),
            hex(plaintext),
            hex(&output)
        );
        Ok(output)
    }

    const fn select_key(&self, kid: u8) -> Option<&SymKey> {
        if kid == self.key_id {
            Some(&self.key)
        } else {
            let (prev_key_id, _) = self.key_id.overflowing_sub(1);
            if kid == prev_key_id {
                self.old_key.as_ref()
            } else {
                None
            }
        }
    }

    /// Open the protected `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an error when the self-encrypted object is invalid;
    /// when the keys have been rotated; or when NSS fails.
    #[expect(clippy::similar_names, reason = "aad is similar to aead.")]
    pub fn open(&self, aad: &[u8], ciphertext: &[u8]) -> Res<Vec<u8>> {
        if *ciphertext.first().ok_or(Error::SelfEncrypt)? != Self::VERSION {
            return Err(Error::SelfEncrypt);
        }
        let Some(key) = self.select_key(*ciphertext.get(1).ok_or(Error::SelfEncrypt)?) else {
            return Err(Error::SelfEncrypt);
        };
        let salt = ciphertext
            .get(2..Self::HEADER_LEN)
            .ok_or(Error::SelfEncrypt)?;

        let mut extended_aad = Vec::<u8>::with_capacity(Self::HEADER_LEN + aad.len());
        extended_aad
            .write_all(&ciphertext[..Self::HEADER_LEN])
            .unwrap_or_else(|_| unreachable!("Buffer has enough capacity."));
        extended_aad
            .write_all(aad)
            .unwrap_or_else(|_| unreachable!("Buffer has enough capacity."));

        let mut aead = self.make_aead(key, salt, Mode::Decrypt)?;
        let output = aead.decrypt(extended_aad.as_ref(), 0, &ciphertext[Self::HEADER_LEN..])?;
        trace!(
            "[SelfEncrypt] open {} {} -> {}",
            hex(aad),
            hex(ciphertext),
            hex(&output)
        );
        Ok(output)
    }
}
