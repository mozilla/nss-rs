// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{
    err::{sec::SEC_ERROR_INVALID_ARGS, secstatus_to_res, Error},
    p11::{PrivateKey, PublicKey, Slot},
};
use crate::aead::{Aead as AeadCtx, AeadAlgorithms, Mode as AeadMode, NONCE_LEN};
use crate::err::Res;
use crate::hkdf::{Hkdf, HkdfAlgorithm};
use crate::hmac::{hmac as compute_hmac, HmacAlgorithm};
use crate::kem::KemKeypair;
use crate::kem_combiners::{xwing_decapsulate, xwing_encapsulate};
use crate::p11;
use crate::p11::SymKey;
use crate::PRBool;
use crate::SECItem;
use crate::{ScopedSECItem, SECItemBorrowed};
use log::{log_enabled, trace};
use std::{
    convert::TryFrom,
    ops::Deref,
    os::raw::c_uint,
    ptr::{addr_of_mut, null, null_mut},
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KemAlgorithm {
    X25519Sha256 = 32,
    XWingMLKem768X25519 = 48,
}

/// Configuration for `Hpke`.
#[derive(Clone, Copy)]
pub struct Config {
    kem: KemAlgorithm,
    kdf: HkdfAlgorithm,
    aead: AeadAlgorithms,
}

impl Config {
    pub fn new(kem: KemAlgorithm, kdf: HkdfAlgorithm, aead: AeadAlgorithms) -> Self {
        Self { kem, kdf, aead }
    }

    pub fn kem(self) -> KemAlgorithm {
        self.kem
    }

    pub fn kdf(self) -> HkdfAlgorithm {
        self.kdf
    }

    pub fn aead(self) -> AeadAlgorithms {
        self.aead
    }

    pub fn supported(self) -> bool {
        let kem_id = self.kem.hpke_kem_id();
        let kdf_id = self.kdf.hpke_kdf_id();
        let aead_id = self.aead.hpke_aead_id();
        // For hybrid KEMs, we handle the key schedule ourselves.
        if self.kem == KemAlgorithm::XWingMLKem768X25519 {
            // Supported if KDF and AEAD are valid HPKE choices
            return kdf_id != 0 && aead_id != 0;
        }
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_ValidateParameters(
                c_uint::from(kem_id),
                c_uint::from(kdf_id),
                c_uint::from(aead_id),
            )
        })
        .is_ok()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            kem: KemAlgorithm::X25519Sha256,
            kdf: HkdfAlgorithm::HKDF_SHA2_256,
            aead: AeadAlgorithms::Aes128Gcm,
        }
    }
}

pub trait Exporter {
    fn export(&self, info: &[u8], len: usize) -> Res<Vec<u8>>;
}

unsafe fn destroy_hpke_context(cx: *mut p11::HpkeContext) {
    p11::PK11_HPKE_DestroyContext(cx, PRBool::from(true));
}

scoped_ptr!(ScopedHpkeContext, p11::HpkeContext, destroy_hpke_context);

impl ScopedHpkeContext {
    fn new(config: Config) -> Result<Self, Error> {
        let ptr = unsafe {
            p11::PK11_HPKE_NewContext(
                c_uint::from(config.kem.hpke_kem_id()),
                c_uint::from(config.kdf.hpke_kdf_id()),
                c_uint::from(config.aead.hpke_aead_id()),
                null_mut(),
                null(),
            )
        };
        let ctx = unsafe { Self::from_ptr(ptr) }?;
        Ok(ctx)
    }
}

impl Exporter for ScopedHpkeContext {
    fn export(&self, info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        let mut out: *mut p11::PK11SymKey = null_mut();
        let info_item = SECItemBorrowed::wrap(info)?;
        let info_item_ptr = info_item.as_ref() as *const SECItem;

        secstatus_to_res(unsafe {
            p11::PK11_HPKE_ExportSecret(
                self.ptr,
                info_item_ptr,
                c_uint::try_from(len).unwrap(),
                &mut out,
            )
        })?;
        let secret = unsafe { SymKey::from_ptr(out)? };
        Ok(secret.key_data()?.to_vec())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct HpkeS {
    context: ScopedHpkeContext,
    config: Config,
}

impl HpkeS {
    /// Create a new context that uses the KEM mode for sending.
    #[allow(clippy::similar_names)]
    pub fn new(config: Config, pk_r: &mut PublicKey, info: &[u8]) -> Res<Self> {
        let (sk_e, pk_e) = generate_key_pair(config.kem)?;
        let context = ScopedHpkeContext::new(config)?;
        let info_item = SECItemBorrowed::wrap(info)?;
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_SetupS(
                *context,
                *pk_e,
                *sk_e,
                **pk_r,
                info_item.as_ref() as *const SECItem,
            )
        })?;
        Ok(Self { context, config })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    /// Get the encapsulated KEM secret.
    pub fn enc(&self) -> Res<Vec<u8>> {
        let v = unsafe { p11::PK11_HPKE_GetEncapPubKey(*self.context) };
        let r = unsafe { v.as_ref() }.ok_or_else(|| Error::from(SEC_ERROR_INVALID_ARGS))?;
        // This is just an alias, so we can't use `Item`.
        let len = usize::try_from(r.len).unwrap();
        let slc = unsafe { std::slice::from_raw_parts(r.data, len) };
        Ok(Vec::from(slc))
    }

    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut SECItem = null_mut();
        let aad_item = SECItemBorrowed::wrap(aad)?;
        let pt_item = SECItemBorrowed::wrap(pt)?;
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_Seal(
                *self.context,
                aad_item.as_ref() as *const SECItem,
                pt_item.as_ref() as *const SECItem,
                &mut out,
            )
        })?;
        let v = unsafe { ScopedSECItem::from_ptr(out)? };
        Ok(unsafe { v.into_vec() })
    }
}

impl Exporter for HpkeS {
    fn export(&self, info: &[u8], len: usize) -> Res<Vec<u8>> {
        self.context.export(info, len)
    }
}

impl Deref for HpkeS {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct HpkeR {
    context: ScopedHpkeContext,
    config: Config,
}

impl HpkeR {
    /// Create a new context that uses the KEM mode for receiving.
    #[allow(clippy::similar_names)]
    pub fn new(
        config: Config,
        pk_r: &PublicKey,
        sk_r: &mut PrivateKey,
        enc: &[u8],
        info: &[u8],
    ) -> Res<Self> {
        let context = ScopedHpkeContext::new(config)?;
        let enc_item = SECItemBorrowed::wrap(enc)?;
        let info_item = SECItemBorrowed::wrap(info)?;
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_SetupR(
                *context,
                **pk_r,
                **sk_r,
                enc_item.as_ref() as *const SECItem,
                info_item.as_ref() as *const SECItem,
            )
        })?;
        Ok(Self { context, config })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn decode_public_key(kem: KemAlgorithm, k: &[u8]) -> Res<PublicKey> {
        // NSS uses a context for this, but we don't want that, but a dummy one works fine.
        let context = ScopedHpkeContext::new(Config {
            kem,
            ..Config::default()
        })?;
        let mut ptr: *mut p11::SECKEYPublicKey = null_mut();
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_Deserialize(
                *context,
                k.as_ptr(),
                c_uint::try_from(k.len()).unwrap(),
                &mut ptr,
            )
        })?;
        unsafe { PublicKey::from_ptr(ptr) }
    }

    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut SECItem = null_mut();
        let aad_item = SECItemBorrowed::wrap(aad)?;
        let ct_item = SECItemBorrowed::wrap(ct)?;
        secstatus_to_res(unsafe {
            p11::PK11_HPKE_Open(
                *self.context,
                aad_item.as_ref() as *const SECItem,
                ct_item.as_ref() as *const SECItem,
                &mut out,
            )
        })?;
        let v = unsafe { ScopedSECItem::from_ptr(out)? };
        Ok(unsafe { v.into_vec() })
    }
}

impl Exporter for HpkeR {
    fn export(&self, info: &[u8], len: usize) -> Res<Vec<u8>> {
        self.context.export(info, len)
    }
}

impl Deref for HpkeR {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

/// Generate a key pair for the identified KEM.
pub fn generate_key_pair(kem: KemAlgorithm) -> Result<(PrivateKey, PublicKey), Error> {
    if kem != KemAlgorithm::X25519Sha256 {
        return Err(Error::InvalidInput);
    }
    let slot = Slot::internal()?;

    let oid_data = unsafe { p11::SECOID_FindOIDByTag(p11::SECOidTag::SEC_OID_CURVE25519) };
    let oid = unsafe { oid_data.as_ref() }.ok_or(Error::Internal)?;
    let oid_slc =
        unsafe { std::slice::from_raw_parts(oid.oid.data, usize::try_from(oid.oid.len).unwrap()) };
    let mut params: Vec<u8> = Vec::with_capacity(oid_slc.len() + 2);
    params.push(u8::try_from(p11::SEC_ASN1_OBJECT_ID).unwrap());
    params.push(u8::try_from(oid.oid.len).unwrap());
    params.extend_from_slice(oid_slc);

    let mut public_ptr: *mut p11::SECKEYPublicKey = null_mut();
    let mut param_item = SECItemBorrowed::wrap(&params)?;

    // Try to make an insensitive key so that we can read the key data for tracing.
    let insensitive_secret_ptr = if log_enabled!(log::Level::Trace) {
        unsafe {
            p11::PK11_GenerateKeyPairWithOpFlags(
                *slot,
                p11::CK_MECHANISM_TYPE::from(p11::CKM_EC_KEY_PAIR_GEN),
                addr_of_mut!(param_item).cast(),
                &mut public_ptr,
                p11::PK11_ATTR_SESSION | p11::PK11_ATTR_INSENSITIVE | p11::PK11_ATTR_PUBLIC,
                p11::CK_FLAGS::from(p11::CKF_DERIVE),
                p11::CK_FLAGS::from(p11::CKF_DERIVE),
                null_mut(),
            )
        }
    } else {
        null_mut()
    };
    assert_eq!(insensitive_secret_ptr.is_null(), public_ptr.is_null());
    let secret_ptr = if insensitive_secret_ptr.is_null() {
        unsafe {
            p11::PK11_GenerateKeyPairWithOpFlags(
                *slot,
                p11::CK_MECHANISM_TYPE::from(p11::CKM_EC_KEY_PAIR_GEN),
                addr_of_mut!(param_item).cast(),
                &mut public_ptr,
                p11::PK11_ATTR_SESSION | p11::PK11_ATTR_SENSITIVE | p11::PK11_ATTR_PRIVATE,
                p11::CK_FLAGS::from(p11::CKF_DERIVE),
                p11::CK_FLAGS::from(p11::CKF_DERIVE),
                null_mut(),
            )
        }
    } else {
        insensitive_secret_ptr
    };
    assert_eq!(secret_ptr.is_null(), public_ptr.is_null());
    let sk = unsafe { PrivateKey::from_ptr(secret_ptr)? };
    let pk = unsafe { PublicKey::from_ptr(public_ptr)? };
    trace!("Generated key pair: sk={:?} pk={:?}", sk, pk);
    Ok((sk, pk))
}

// ============================================================================
// HPKE ID methods
// ============================================================================

impl KemAlgorithm {
    /// HPKE KEM identifier per RFC 9180.
    #[must_use]
    pub const fn hpke_kem_id(self) -> u16 {
        match self {
            Self::X25519Sha256 => 0x0020,
            Self::XWingMLKem768X25519 => 0x0030,
        }
    }
}

impl HkdfAlgorithm {
    /// HPKE KDF identifier per RFC 9180.
    #[must_use]
    pub const fn hpke_kdf_id(self) -> u16 {
        match self {
            Self::HKDF_SHA2_256 => 0x0001,
            Self::HKDF_SHA2_384 => 0x0002,
            Self::HKDF_SHA2_512 => 0x0003,
        }
    }

    /// Hash output length (Nh) for this KDF.
    #[must_use]
    pub const fn hash_len(self) -> usize {
        match self {
            Self::HKDF_SHA2_256 => 32,
            Self::HKDF_SHA2_384 => 48,
            Self::HKDF_SHA2_512 => 64,
        }
    }

    /// Map to the corresponding HMAC algorithm.
    #[must_use]
    pub const fn to_hmac_algorithm(self) -> HmacAlgorithm {
        match self {
            Self::HKDF_SHA2_256 => HmacAlgorithm::HMAC_SHA2_256,
            Self::HKDF_SHA2_384 => HmacAlgorithm::HMAC_SHA2_384,
            Self::HKDF_SHA2_512 => HmacAlgorithm::HMAC_SHA2_512,
        }
    }
}

impl AeadAlgorithms {
    /// HPKE AEAD identifier per RFC 9180.
    #[must_use]
    pub const fn hpke_aead_id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
        }
    }

    /// AEAD key length (Nk) in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }
}

// ============================================================================
// HPKE Key Schedule (RFC 9180)
// ============================================================================

const HPKE_MODE_BASE: u8 = 0x00;
const HPKE_MODE_PSK: u8 = 0x01;
const HPKE_LABEL: &[u8] = b"HPKE-v1";

/// Build the HPKE suite_id: `"HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)`
fn build_suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> Vec<u8> {
    let mut suite_id = Vec::with_capacity(4 + 6);
    suite_id.extend_from_slice(b"HPKE");
    suite_id.extend_from_slice(&kem_id.to_be_bytes());
    suite_id.extend_from_slice(&kdf_id.to_be_bytes());
    suite_id.extend_from_slice(&aead_id.to_be_bytes());
    suite_id
}

/// Build labeled IKM: `"HPKE-v1" || suite_id || label || ikm`
fn build_labeled_ikm(suite_id: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HPKE_LABEL.len() + suite_id.len() + label.len() + ikm.len());
    out.extend_from_slice(HPKE_LABEL);
    out.extend_from_slice(suite_id);
    out.extend_from_slice(label);
    out.extend_from_slice(ikm);
    out
}

/// Build labeled info: `I2OSP(L,2) || "HPKE-v1" || suite_id || label || info`
fn build_labeled_info(len: u16, suite_id: &[u8], label: &[u8], info: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(2 + HPKE_LABEL.len() + suite_id.len() + label.len() + info.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(HPKE_LABEL);
    out.extend_from_slice(suite_id);
    out.extend_from_slice(label);
    out.extend_from_slice(info);
    out
}

/// HKDF-Extract using HMAC: `HMAC-Hash(salt, labeled_ikm)`
fn labeled_extract(
    kdf: HkdfAlgorithm,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Res<Vec<u8>> {
    let labeled_ikm = build_labeled_ikm(suite_id, label, ikm);
    let hmac_alg = kdf.to_hmac_algorithm();
    let salt = if salt.is_empty() {
        vec![0u8; kdf.hash_len()]
    } else {
        salt.to_vec()
    };
    Ok(compute_hmac(&hmac_alg, &salt, &labeled_ikm)?)
}

/// HKDF-Expand using Hkdf::expand_data: `HKDF-Expand(prk, labeled_info, L)`
fn labeled_expand(
    kdf: HkdfAlgorithm,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Res<Vec<u8>> {
    let labeled_info =
        build_labeled_info(u16::try_from(len).map_err(|_| Error::IntegerOverflow)?, suite_id, label, info);
    let hkdf = Hkdf::new(kdf);
    let prk_key = hkdf
        .import_secret(prk)
        .map_err(|_| Error::Internal)?;
    hkdf.expand_data(&prk_key, &labeled_info, len)
        .map_err(|_| Error::Internal)
}

/// Key schedule state produced by `hpke_key_schedule_base`.
struct KeyScheduleResult {
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
}

/// HPKE base-mode key schedule (RFC 9180 Section 5.1).
fn hpke_key_schedule_base(
    config: Config,
    shared_secret: &[u8],
    info: &[u8],
) -> Res<KeyScheduleResult> {
    let kdf = config.kdf;
    let aead = config.aead;
    let suite_id = build_suite_id(
        config.kem.hpke_kem_id(),
        kdf.hpke_kdf_id(),
        aead.hpke_aead_id(),
    );

    let mode_bytes = [HPKE_MODE_BASE];
    let psk_id_hash = labeled_extract(kdf, &suite_id, b"", b"psk_id_hash", b"")?;
    let info_hash = labeled_extract(kdf, &suite_id, b"", b"info_hash", info)?;

    let mut ks_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ks_context.extend_from_slice(&mode_bytes);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let secret = labeled_extract(kdf, &suite_id, shared_secret, b"secret", b"")?;

    let key = labeled_expand(kdf, &suite_id, &secret, b"key", &ks_context, aead.key_len())?;
    let base_nonce = labeled_expand(kdf, &suite_id, &secret, b"base_nonce", &ks_context, NONCE_LEN)?;
    let exporter_secret =
        labeled_expand(kdf, &suite_id, &secret, b"exp", &ks_context, kdf.hash_len())?;

    Ok(KeyScheduleResult {
        key,
        base_nonce,
        exporter_secret,
    })
}

/// HPKE PSK-mode key schedule (RFC 9180 Section 5.1).
///
/// Same as base mode but incorporates the PSK and PSK ID into the key schedule.
fn hpke_key_schedule_psk(
    config: Config,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Res<KeyScheduleResult> {
    let kdf = config.kdf;
    let aead = config.aead;
    let suite_id = build_suite_id(
        config.kem.hpke_kem_id(),
        kdf.hpke_kdf_id(),
        aead.hpke_aead_id(),
    );

    let mode_bytes = [HPKE_MODE_PSK];
    let psk_id_hash = labeled_extract(kdf, &suite_id, b"", b"psk_id_hash", psk_id)?;
    let info_hash = labeled_extract(kdf, &suite_id, b"", b"info_hash", info)?;

    let mut ks_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ks_context.extend_from_slice(&mode_bytes);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let secret = labeled_extract(kdf, &suite_id, shared_secret, b"secret", psk)?;

    let key = labeled_expand(kdf, &suite_id, &secret, b"key", &ks_context, aead.key_len())?;
    let base_nonce = labeled_expand(kdf, &suite_id, &secret, b"base_nonce", &ks_context, NONCE_LEN)?;
    let exporter_secret =
        labeled_expand(kdf, &suite_id, &secret, b"exp", &ks_context, kdf.hash_len())?;

    Ok(KeyScheduleResult {
        key,
        base_nonce,
        exporter_secret,
    })
}

/// HPKE Export function (RFC 9180 Section 5.3).
fn hpke_export(
    kdf: HkdfAlgorithm,
    suite_id: &[u8],
    exporter_secret: &[u8],
    exporter_context: &[u8],
    len: usize,
) -> Res<Vec<u8>> {
    labeled_expand(kdf, suite_id, exporter_secret, b"sec", exporter_context, len)
}

// ============================================================================
// Hybrid HPKE Sender (HpkeHybridS)
// ============================================================================

#[allow(clippy::module_name_repetitions)]
pub struct HpkeHybridS {
    config: Config,
    enc: Vec<u8>,
    encrypt_ctx: AeadCtx,
    exporter_secret: Vec<u8>,
    suite_id: Vec<u8>,
}

impl HpkeHybridS {
    /// Create a new hybrid HPKE sender context from raw public key bytes.
    ///
    /// Imports the recipient's public key from raw bytes (1216 bytes for X-Wing),
    /// performs X-Wing encapsulation, then runs the HPKE key schedule.
    pub fn from_public_key_bytes(config: Config, pk_bytes: &[u8], info: &[u8]) -> Res<Self> {
        use crate::kem_combiners::import_xwing_public_key;

        let (mlkem_pk, x25519_pk) = import_xwing_public_key(pk_bytes)?;
        let encap_result = xwing_encapsulate(&mlkem_pk, &x25519_pk)?;

        let ks = hpke_key_schedule_base(config, &encap_result.shared_secret, info)?;

        let nonce_base: [u8; NONCE_LEN] = ks
            .base_nonce
            .try_into()
            .map_err(|_| Error::Internal)?;
        let sym_key = AeadCtx::import_key(config.aead, &ks.key)?;
        let encrypt_ctx = AeadCtx::new(AeadMode::Encrypt, config.aead, &sym_key, nonce_base)?;

        let suite_id = build_suite_id(
            config.kem.hpke_kem_id(),
            config.kdf.hpke_kdf_id(),
            config.aead.hpke_aead_id(),
        );

        Ok(Self {
            config,
            enc: encap_result.ciphertext,
            encrypt_ctx,
            exporter_secret: ks.exporter_secret,
            suite_id,
        })
    }

    /// Create a new hybrid HPKE sender context.
    ///
    /// Performs X-Wing encapsulation against the recipient's key pair,
    /// then runs the HPKE key schedule to derive encryption keys.
    pub fn new(config: Config, keypair: &KemKeypair, info: &[u8]) -> Res<Self> {
        let KemKeypair::XWingMLKem768X25519(ref xwing_kp) = *keypair else {
            return Err(Error::InvalidInput);
        };

        // X-Wing encapsulate
        let encap_result =
            xwing_encapsulate(&xwing_kp.mlkem_public, &xwing_kp.x25519_public)?;

        // Run HPKE key schedule
        let ks = hpke_key_schedule_base(config, &encap_result.shared_secret, info)?;

        // Import AEAD key and create encryption context
        let nonce_base: [u8; NONCE_LEN] = ks
            .base_nonce
            .try_into()
            .map_err(|_| Error::Internal)?;
        let sym_key = AeadCtx::import_key(config.aead, &ks.key)?;
        let encrypt_ctx = AeadCtx::new(AeadMode::Encrypt, config.aead, &sym_key, nonce_base)?;

        let suite_id = build_suite_id(
            config.kem.hpke_kem_id(),
            config.kdf.hpke_kdf_id(),
            config.aead.hpke_aead_id(),
        );

        Ok(Self {
            config,
            enc: encap_result.ciphertext,
            encrypt_ctx,
            exporter_secret: ks.exporter_secret,
            suite_id,
        })
    }

    /// Create a new hybrid HPKE sender context with PSK (PSK mode).
    ///
    /// Performs X-Wing encapsulation against the recipient's key pair,
    /// then runs the HPKE PSK key schedule with the provided PSK and PSK ID.
    pub fn new_psk(
        config: Config,
        keypair: &KemKeypair,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Res<Self> {
        let KemKeypair::XWingMLKem768X25519(ref xwing_kp) = *keypair else {
            return Err(Error::InvalidInput);
        };

        let encap_result =
            xwing_encapsulate(&xwing_kp.mlkem_public, &xwing_kp.x25519_public)?;

        let ks = hpke_key_schedule_psk(config, &encap_result.shared_secret, info, psk, psk_id)?;

        let nonce_base: [u8; NONCE_LEN] = ks
            .base_nonce
            .try_into()
            .map_err(|_| Error::Internal)?;
        let sym_key = AeadCtx::import_key(config.aead, &ks.key)?;
        let encrypt_ctx = AeadCtx::new(AeadMode::Encrypt, config.aead, &sym_key, nonce_base)?;

        let suite_id = build_suite_id(
            config.kem.hpke_kem_id(),
            config.kdf.hpke_kdf_id(),
            config.aead.hpke_aead_id(),
        );

        Ok(Self {
            config,
            enc: encap_result.ciphertext,
            encrypt_ctx,
            exporter_secret: ks.exporter_secret,
            suite_id,
        })
    }

    /// Create a new hybrid HPKE sender context from raw public key bytes with PSK (PSK mode).
    pub fn from_public_key_bytes_psk(
        config: Config,
        pk_bytes: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Res<Self> {
        use crate::kem_combiners::import_xwing_public_key;

        let (mlkem_pk, x25519_pk) = import_xwing_public_key(pk_bytes)?;
        let encap_result = xwing_encapsulate(&mlkem_pk, &x25519_pk)?;

        let ks = hpke_key_schedule_psk(config, &encap_result.shared_secret, info, psk, psk_id)?;

        let nonce_base: [u8; NONCE_LEN] = ks
            .base_nonce
            .try_into()
            .map_err(|_| Error::Internal)?;
        let sym_key = AeadCtx::import_key(config.aead, &ks.key)?;
        let encrypt_ctx = AeadCtx::new(AeadMode::Encrypt, config.aead, &sym_key, nonce_base)?;

        let suite_id = build_suite_id(
            config.kem.hpke_kem_id(),
            config.kdf.hpke_kdf_id(),
            config.aead.hpke_aead_id(),
        );

        Ok(Self {
            config,
            enc: encap_result.ciphertext,
            encrypt_ctx,
            exporter_secret: ks.exporter_secret,
            suite_id,
        })
    }

    /// Return the KEM ciphertext (enc) to send to the receiver.
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    pub fn config(&self) -> Config {
        self.config
    }

    /// Encrypt plaintext with associated data.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        self.encrypt_ctx.seal(aad, pt)
    }
}

impl Exporter for HpkeHybridS {
    fn export(&self, info: &[u8], len: usize) -> Res<Vec<u8>> {
        hpke_export(self.config.kdf, &self.suite_id, &self.exporter_secret, info, len)
    }
}

impl Deref for HpkeHybridS {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

// ============================================================================
// Hybrid HPKE Receiver (HpkeHybridR)
// ============================================================================

#[allow(clippy::module_name_repetitions)]
pub struct HpkeHybridR {
    config: Config,
    decrypt_ctx: AeadCtx,
    seq: u64,
    exporter_secret: Vec<u8>,
    suite_id: Vec<u8>,
}

impl HpkeHybridR {
    /// Create a new hybrid HPKE receiver context.
    ///
    /// Performs X-Wing decapsulation using the recipient's private key,
    /// then runs the HPKE key schedule to derive decryption keys.
    pub fn new(config: Config, keypair: &KemKeypair, enc: &[u8], info: &[u8]) -> Res<Self> {
        let KemKeypair::XWingMLKem768X25519(ref xwing_kp) = *keypair else {
            return Err(Error::InvalidInput);
        };

        // X-Wing decapsulate
        let shared_secret = xwing_decapsulate(
            enc,
            &xwing_kp.mlkem_private,
            &xwing_kp.x25519_private,
            &xwing_kp.x25519_public,
        )?;

        // Run HPKE key schedule
        let ks = hpke_key_schedule_base(config, &shared_secret, info)?;

        // Import AEAD key and create decryption context
        let nonce_base: [u8; NONCE_LEN] = ks
            .base_nonce
            .try_into()
            .map_err(|_| Error::Internal)?;
        let sym_key = AeadCtx::import_key(config.aead, &ks.key)?;
        let decrypt_ctx = AeadCtx::new(AeadMode::Decrypt, config.aead, &sym_key, nonce_base)?;

        let suite_id = build_suite_id(
            config.kem.hpke_kem_id(),
            config.kdf.hpke_kdf_id(),
            config.aead.hpke_aead_id(),
        );

        Ok(Self {
            config,
            decrypt_ctx,
            seq: 0,
            exporter_secret: ks.exporter_secret,
            suite_id,
        })
    }

    /// Create a new hybrid HPKE receiver context with PSK (PSK mode).
    ///
    /// Performs X-Wing decapsulation using the recipient's private key,
    /// then runs the HPKE PSK key schedule with the provided PSK and PSK ID.
    pub fn new_psk(
        config: Config,
        keypair: &KemKeypair,
        enc: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Res<Self> {
        let KemKeypair::XWingMLKem768X25519(ref xwing_kp) = *keypair else {
            return Err(Error::InvalidInput);
        };

        let shared_secret = xwing_decapsulate(
            enc,
            &xwing_kp.mlkem_private,
            &xwing_kp.x25519_private,
            &xwing_kp.x25519_public,
        )?;

        let ks = hpke_key_schedule_psk(config, &shared_secret, info, psk, psk_id)?;

        let nonce_base: [u8; NONCE_LEN] = ks
            .base_nonce
            .try_into()
            .map_err(|_| Error::Internal)?;
        let sym_key = AeadCtx::import_key(config.aead, &ks.key)?;
        let decrypt_ctx = AeadCtx::new(AeadMode::Decrypt, config.aead, &sym_key, nonce_base)?;

        let suite_id = build_suite_id(
            config.kem.hpke_kem_id(),
            config.kdf.hpke_kdf_id(),
            config.aead.hpke_aead_id(),
        );

        Ok(Self {
            config,
            decrypt_ctx,
            seq: 0,
            exporter_secret: ks.exporter_secret,
            suite_id,
        })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    /// Decrypt ciphertext with associated data.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let pt = self.decrypt_ctx.open(aad, self.seq, ct)?;
        self.seq += 1;
        Ok(pt)
    }
}

impl Exporter for HpkeHybridR {
    fn export(&self, info: &[u8], len: usize) -> Res<Vec<u8>> {
        hpke_export(self.config.kdf, &self.suite_id, &self.exporter_secret, info, len)
    }
}

impl Deref for HpkeHybridR {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod test {
    use super::{generate_key_pair, AeadAlgorithms, Config, HpkeR, HpkeS};
    use test_fixture::fixture_init;

    const INFO: &[u8] = b"info";
    const AAD: &[u8] = b"aad";
    const PT: &[u8] = b"message";

    #[allow(clippy::similar_names)] // for sk_x and pk_x
    #[test]
    fn make() {
        fixture_init();
        let cfg = Config::default();
        let (mut sk_r, mut pk_r) = generate_key_pair(cfg.kem()).unwrap();
        let hpke_s = HpkeS::new(cfg, &mut pk_r, INFO).unwrap();
        let _hpke_r = HpkeR::new(cfg, &pk_r, &mut sk_r, &hpke_s.enc().unwrap(), INFO).unwrap();
    }

    #[allow(clippy::similar_names)] // for sk_x and pk_x
    fn seal_open(aead: AeadAlgorithms) {
        // Setup
        fixture_init();
        let cfg = Config {
            aead,
            ..Config::default()
        };
        assert!(cfg.supported());
        let (mut sk_r, mut pk_r) = generate_key_pair(cfg.kem()).unwrap();

        // Send
        let mut hpke_s = HpkeS::new(cfg, &mut pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receive
        let mut hpke_r = HpkeR::new(cfg, &pk_r, &mut sk_r, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn seal_open_gcm() {
        seal_open(AeadAlgorithms::Aes128Gcm);
    }

    #[test]
    fn seal_open_chacha() {
        seal_open(AeadAlgorithms::ChaCha20Poly1305);
    }
}

#[cfg(test)]
mod hybrid_tests {
    use super::{AeadAlgorithms, Config, Exporter, HpkeHybridR, HpkeHybridS, KemAlgorithm};
    use crate::hkdf::HkdfAlgorithm;
    use crate::kem::{generate_keypair, KemParameterSet};
    use test_fixture::fixture_init;

    const INFO: &[u8] = b"hybrid-hpke-test-info";
    const AAD: &[u8] = b"hybrid-hpke-test-aad";
    const PT: &[u8] = b"hybrid-hpke-test-message";

    fn hybrid_seal_open(aead: AeadAlgorithms) {
        fixture_init();
        let cfg = Config::new(KemAlgorithm::XWingMLKem768X25519, HkdfAlgorithm::HKDF_SHA2_256, aead);

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        // Sender
        let mut hpke_s = HpkeHybridS::new(cfg, &keypair, INFO).unwrap();
        let enc = hpke_s.enc().to_vec();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receiver
        let mut hpke_r = HpkeHybridR::new(cfg, &keypair, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn test_hybrid_seal_open_aes128gcm() {
        hybrid_seal_open(AeadAlgorithms::Aes128Gcm);
    }

    #[test]
    fn test_hybrid_seal_open_aes256gcm() {
        hybrid_seal_open(AeadAlgorithms::Aes256Gcm);
    }

    #[test]
    fn test_hybrid_seal_open_chacha20() {
        hybrid_seal_open(AeadAlgorithms::ChaCha20Poly1305);
    }

    #[test]
    fn test_hybrid_multiple_messages() {
        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes128Gcm,
        );

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        let mut hpke_s = HpkeHybridS::new(cfg, &keypair, INFO).unwrap();
        let enc = hpke_s.enc().to_vec();

        let mut hpke_r = HpkeHybridR::new(cfg, &keypair, &enc, INFO).unwrap();

        for i in 0..5 {
            let msg = format!("message number {i}");
            let ct = hpke_s.seal(AAD, msg.as_bytes()).unwrap();
            let pt = hpke_r.open(AAD, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_hybrid_export() {
        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes128Gcm,
        );

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        let hpke_s = HpkeHybridS::new(cfg, &keypair, INFO).unwrap();
        let enc = hpke_s.enc().to_vec();

        let hpke_r = HpkeHybridR::new(cfg, &keypair, &enc, INFO).unwrap();

        let export_context = b"export-context";
        let export_s = hpke_s.export(export_context, 32).unwrap();
        let export_r = hpke_r.export(export_context, 32).unwrap();

        assert_eq!(export_s, export_r);
        assert_eq!(export_s.len(), 32);
    }

    #[test]
    fn test_hybrid_config() {
        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes128Gcm,
        );

        assert_eq!(cfg.kem(), KemAlgorithm::XWingMLKem768X25519);
        assert!(cfg.supported());
    }

    #[test]
    fn test_hybrid_from_public_key_bytes() {
        use crate::err::secstatus_to_res;
        use crate::kem_combiners::{
            XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE,
        };
        use crate::p11;
        use crate::util::SECItemMut;

        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes256Gcm,
        );

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();

        // Export public key bytes from the keypair
        let crate::kem::KemKeypair::XWingMLKem768X25519(ref xwing) = keypair else {
            panic!("Expected XWing keypair");
        };

        // ML-KEM public key via PK11_ReadRawAttribute(CKA_VALUE)
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            p11::PK11_ReadRawAttribute(
                p11::PK11ObjectType::PK11_TypePubKey,
                (*xwing.mlkem_public).cast(),
                pkcs11_bindings::CKA_VALUE,
                key_item.as_mut(),
            )
        })
        .unwrap();
        let mlkem_pk_bytes = key_item.as_slice().to_owned();

        // X25519 public key via key_data_alt()
        let x25519_raw = xwing.x25519_public.key_data_alt().unwrap();
        let x25519_pk = if x25519_raw.len() == 32 {
            x25519_raw
        } else if x25519_raw.len() == 34 && x25519_raw[0] == 0x04 && x25519_raw[1] == 0x20 {
            x25519_raw[2..34].to_vec()
        } else {
            panic!("Unexpected X25519 key format");
        };

        let mut pk_bytes = Vec::with_capacity(XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE);
        pk_bytes.extend_from_slice(&mlkem_pk_bytes);
        pk_bytes.extend_from_slice(&x25519_pk);
        assert_eq!(pk_bytes.len(), XWING_MLKEM768_X25519_PUBLIC_KEY_SIZE);

        // Sender uses from_public_key_bytes
        let mut hpke_s = HpkeHybridS::from_public_key_bytes(cfg, &pk_bytes, INFO).unwrap();
        let enc = hpke_s.enc().to_vec();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receiver uses the original keypair
        let mut hpke_r = HpkeHybridR::new(cfg, &keypair, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn test_hybrid_psk_mode() {
        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes256Gcm,
        );

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();
        let psk = b"this is a pre-shared key value!x"; // 32 bytes
        let psk_id = b"my-psk-id";

        // PSK mode sender
        let mut hpke_s = HpkeHybridS::new_psk(cfg, &keypair, INFO, psk, psk_id).unwrap();
        let enc = hpke_s.enc().to_vec();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // PSK mode receiver
        let mut hpke_r = HpkeHybridR::new_psk(cfg, &keypair, &enc, INFO, psk, psk_id).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn test_hybrid_psk_mode_wrong_psk_fails() {
        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes256Gcm,
        );

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();
        let psk = b"this is a pre-shared key value!x"; // 32 bytes
        let wrong_psk = b"this is the WRONG psk value!!!!x";
        let psk_id = b"my-psk-id";

        // Sender with correct PSK
        let mut hpke_s = HpkeHybridS::new_psk(cfg, &keypair, INFO, psk, psk_id).unwrap();
        let enc = hpke_s.enc().to_vec();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receiver with wrong PSK - should fail to decrypt
        let mut hpke_r = HpkeHybridR::new_psk(cfg, &keypair, &enc, INFO, wrong_psk, psk_id).unwrap();
        let result = hpke_r.open(AAD, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_psk_base_mismatch_fails() {
        fixture_init();
        let cfg = Config::new(
            KemAlgorithm::XWingMLKem768X25519,
            HkdfAlgorithm::HKDF_SHA2_256,
            AeadAlgorithms::Aes256Gcm,
        );

        let keypair = generate_keypair(KemParameterSet::XWingMLKem768X25519).unwrap();
        let psk = b"this is a pre-shared key value!x";
        let psk_id = b"my-psk-id";

        // Sender with PSK mode
        let mut hpke_s = HpkeHybridS::new_psk(cfg, &keypair, INFO, psk, psk_id).unwrap();
        let enc = hpke_s.enc().to_vec();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receiver with Base mode (no PSK) - should fail
        let mut hpke_r = HpkeHybridR::new(cfg, &keypair, &enc, INFO).unwrap();
        let result = hpke_r.open(AAD, &ct);
        assert!(result.is_err());
    }
}
