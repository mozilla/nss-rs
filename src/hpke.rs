// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    ops::Deref,
    os::raw::c_uint,
    ptr::{null, null_mut},
};

use crate::{
    ec::{Curve, Keypair, ecdh_keygen},
    err::{Error, Res, sec::SEC_ERROR_INVALID_ARGS, secstatus_to_res},
    init,
    item::{SECItem, SECItemBorrowed, ScopedSECItem},
    null_safe_slice,
    p11::{self, HpkeContext, PRBool, PrivateKey, PublicKey, SymKey},
};

macro_rules! hpke_algorithm_id {
    // t = target type
    // h = the HPKE-native type from the p11 bindings
    // n = the name to give the variant (`t::n` is the target)
    // v = the integer value allocated to that variant in the HPKE spec
    ($t:ident: $h:ty { $($n:ident = $v:expr),+ $(,)? }) => {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum $t {
    $($n = $v),+
}

impl TryFrom<u16> for $t {
    type Error = $crate::err::Error;
    fn try_from(v: u16) -> Result<Self, $crate::err::Error> {
        match v {
            $($v => Ok(Self::$n),)+
            _ => Err($crate::err::Error::UnknownIdentifier),
        }
    }
}

impl From<$t> for $h {
    fn from(value: $t) -> Self {
        Self::from(u16::from(value))
    }
}

impl From<$t> for u16 {
    fn from(value: $t) -> Self {
        value as u16
    }
}
    };
}

hpke_algorithm_id!(KemAlgorithm: p11::HpkeKemId::Type {
    P256Sha256 = 16,
    P384Sha384 = 17,
    P521Sha512 = 18,
    X25519Sha256 = 32,
    X448Sha512 = 33,
});

impl TryFrom<KemAlgorithm> for Curve {
    type Error = Error;
    fn try_from(value: KemAlgorithm) -> Res<Self> {
        match value {
            KemAlgorithm::P256Sha256 => Ok(Self::P256),
            KemAlgorithm::P384Sha384 => Ok(Self::P384),
            KemAlgorithm::P521Sha512 => Ok(Self::P521),
            KemAlgorithm::X25519Sha256 => Ok(Self::X25519),
            KemAlgorithm::X448Sha512 => Err(Error::UnsupportedCurve),
        }
    }
}

hpke_algorithm_id!(KdfAlgorithm: p11::HpkeKdfId::Type {
    HkdfSha256 = 1,
    HkdfSha384 = 2,
    HkdfSha512 = 3,
});

impl TryFrom<KdfAlgorithm> for crate::hkdf::HkdfAlgorithm {
    type Error = Error;
    fn try_from(value: KdfAlgorithm) -> Res<Self> {
        match value {
            KdfAlgorithm::HkdfSha256 => Ok(Self::HKDF_SHA2_256),
            KdfAlgorithm::HkdfSha384 => Ok(Self::HKDF_SHA2_384),
            KdfAlgorithm::HkdfSha512 => Ok(Self::HKDF_SHA2_512),
        }
    }
}

hpke_algorithm_id!(AeadAlgorithm: p11::HpkeAeadId::Type {
    Aes128Gcm = 1,
    Aes256Gcm = 2,
    ChaCha20Poly1305 = 3,
});

impl TryFrom<AeadAlgorithm> for crate::aead::AeadAlgorithms {
    type Error = Error;
    fn try_from(value: AeadAlgorithm) -> Res<Self> {
        match value {
            AeadAlgorithm::Aes128Gcm => Ok(Self::Aes128Gcm),
            AeadAlgorithm::Aes256Gcm => Ok(Self::Aes256Gcm),
            AeadAlgorithm::ChaCha20Poly1305 => Ok(Self::ChaCha20Poly1305),
        }
    }
}

/// Configuration for `Hpke`.
#[derive(Clone, Copy)]
pub struct Config {
    kem: KemAlgorithm,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
}

impl Config {
    #[must_use]
    pub const fn new(kem: KemAlgorithm, kdf: KdfAlgorithm, aead: AeadAlgorithm) -> Self {
        Self { kem, kdf, aead }
    }

    #[must_use]
    pub const fn kem(self) -> KemAlgorithm {
        self.kem
    }

    #[must_use]
    pub const fn kdf(self) -> KdfAlgorithm {
        self.kdf
    }

    #[must_use]
    pub const fn aead(self) -> AeadAlgorithm {
        self.aead
    }

    #[must_use]
    pub fn supported(self) -> bool {
        if init().is_err() {
            return false;
        }
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_ValidateParameters(
                p11::HpkeKemId::Type::from(self.kem),
                p11::HpkeKdfId::Type::from(self.kdf),
                p11::HpkeAeadId::Type::from(self.aead),
            )
        })
        .is_ok()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            kem: KemAlgorithm::X25519Sha256,
            kdf: KdfAlgorithm::HkdfSha256,
            aead: AeadAlgorithm::Aes128Gcm,
        }
    }
}

pub trait Exporter {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey>;
    fn export_raw(&self, info: &[u8], len: usize) -> Res<Vec<u8>> {
        self.export(info, len)?.key_data().map(Vec::from)
    }
}

unsafe fn destroy_hpke_context(cx: *mut HpkeContext) {
    unsafe {
        p11::PK11_HPKE_DestroyContext(cx, PRBool::from(true));
    }
}

scoped_ptr!(Context, HpkeContext, destroy_hpke_context);

impl Context {
    fn new(config: Config) -> Res<Self> {
        init()?;
        let ptr = unsafe {
            p11::PK11_HPKE_NewContext(
                p11::HpkeKemId::Type::from(config.kem),
                p11::HpkeKdfId::Type::from(config.kdf),
                p11::HpkeKemId::Type::from(config.aead),
                null_mut(),
                null(),
            )
        };
        Self::from_ptr(ptr)
    }
}

impl Exporter for Context {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut out: *mut p11::PK11SymKey = null_mut();

        secstatus_to_res(unsafe {
            p11::PK11_HPKE_ExportSecret(
                self.ptr,
                SECItemBorrowed::wrap(info).as_ptr().cast_mut(), // const_cast!
                c_uint::try_from(len)?,
                &raw mut out,
            )
        })?;
        SymKey::from_ptr(out)
    }
}

#[expect(clippy::module_name_repetitions)]
pub struct HpkeS {
    context: Context,
    config: Config,
}

impl HpkeS {
    /// Create a new context that uses the KEM mode for sending.
    pub fn new(config: Config, pk_r: &PublicKey, info: &[u8]) -> Res<Self> {
        let Keypair {
            private: sk_e,
            public: pk_e,
        } = ecdh_keygen(Curve::try_from(config.kem)?)?;
        let context = Context::new(config)?;
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_SetupS(
                *context,
                *pk_e,
                *sk_e,
                **pk_r,
                SECItemBorrowed::wrap(info).as_ptr(),
            )
        })?;
        Ok(Self { context, config })
    }

    #[must_use]
    pub const fn config(&self) -> Config {
        self.config
    }

    /// Get the encapsulated KEM secret.
    pub fn enc(&self) -> Res<Vec<u8>> {
        let v = unsafe { p11::PK11_HPKE_GetEncapPubKey(*self.context) };
        let r = unsafe { v.as_ref() }.ok_or_else(|| Error::from(SEC_ERROR_INVALID_ARGS))?;
        // This is just an alias, so we can't use a `SECItem`.
        let slc = unsafe { null_safe_slice(r.data, usize::try_from(r.len)?) };
        Ok(Vec::from(slc))
    }

    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut SECItem = null_mut();
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_Seal(
                *self.context,
                SECItemBorrowed::wrap(aad).as_ptr(),
                SECItemBorrowed::wrap(pt).as_ptr(),
                &raw mut out,
            )
        })?;
        let v = ScopedSECItem::from_ptr(out)?;
        Ok(v.into_vec())
    }
}

impl Exporter for HpkeS {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        self.context.export(info, len)
    }
}

impl Deref for HpkeS {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[expect(clippy::module_name_repetitions)]
pub struct HpkeR {
    context: Context,
    config: Config,
}

impl HpkeR {
    /// Create a new context that uses the KEM mode for sending.
    pub fn new(
        config: Config,
        pk_r: &PublicKey,
        sk_r: &PrivateKey,
        enc: &[u8],
        info: &[u8],
    ) -> Res<Self> {
        let context = Context::new(config)?;
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_SetupR(
                *context,
                **pk_r,
                **sk_r,
                SECItemBorrowed::wrap(enc).as_ptr(),
                SECItemBorrowed::wrap(info).as_ptr(),
            )
        })?;
        Ok(Self { context, config })
    }

    #[must_use]
    pub const fn config(&self) -> Config {
        self.config
    }

    pub fn decode_public_key(kem: KemAlgorithm, k: &[u8]) -> Res<PublicKey> {
        // NSS uses a context for this, but we don't want that API. A dummy works fine.
        let context = Context::new(Config {
            kem,
            ..Config::default()
        })?;
        let mut ptr: *mut p11::SECKEYPublicKey = null_mut();
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_Deserialize(
                *context,
                k.as_ptr(),
                c_uint::try_from(k.len())?,
                &raw mut ptr,
            )
        })?;
        PublicKey::from_ptr(ptr)
    }

    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut SECItem = null_mut();
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_Open(
                *self.context,
                SECItemBorrowed::wrap(aad).as_ptr(),
                SECItemBorrowed::wrap(ct).as_ptr(),
                &raw mut out,
            )
        })?;
        let v = ScopedSECItem::from_ptr(out)?;
        Ok(v.into_vec())
    }
}

impl Exporter for HpkeR {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        self.context.export(info, len)
    }
}

impl Deref for HpkeR {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[cfg(test)]
mod test {
    use test_fixture::fixture_init;

    use crate::{
        ec::{Curve, Keypair, ecdh_keygen},
        hpke::{AeadAlgorithm, Config, Exporter as _, HpkeR, HpkeS},
    };

    const INFO: &[u8] = b"info";
    const AAD: &[u8] = b"aad";
    const PT: &[u8] = b"message";

    #[test]
    fn make() {
        fixture_init();
        let cfg = Config::default();
        let Keypair {
            private: sk_r,
            public: pk_r,
        } = ecdh_keygen(Curve::try_from(cfg.kem()).unwrap()).unwrap();
        let hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let _hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &hpke_s.enc().unwrap(), INFO).unwrap();
    }

    fn seal_open(aead: AeadAlgorithm) {
        fixture_init();
        let cfg = Config {
            aead,
            ..Config::default()
        };
        assert!(cfg.supported());
        let Keypair {
            private: sk_r,
            public: pk_r,
        } = ecdh_keygen(Curve::try_from(cfg.kem()).unwrap()).unwrap();
        // Send
        let mut hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receive
        let mut hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn seal_open_gcm128() {
        seal_open(AeadAlgorithm::Aes128Gcm);
    }

    #[test]
    fn seal_open_gcm256() {
        seal_open(AeadAlgorithm::Aes256Gcm);
    }

    #[test]
    fn seal_open_chacha() {
        seal_open(AeadAlgorithm::ChaCha20Poly1305);
    }

    #[test]
    fn export() {
        const CONTEXT: &[u8] = b"context";
        const LEN: usize = 30;

        fixture_init();
        let cfg = Config::default();
        let Keypair {
            private: sk_r,
            public: pk_r,
        } = ecdh_keygen(Curve::try_from(cfg.kem()).unwrap()).unwrap();

        let hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let s_export = hpke_s.export(CONTEXT, LEN).unwrap();

        let hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &enc, INFO).unwrap();
        let r_export = hpke_r.export(CONTEXT, LEN).unwrap();

        assert_eq!(s_export.key_data().unwrap(), r_export.key_data().unwrap());
    }
}
