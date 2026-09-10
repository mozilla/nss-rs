// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr;

use log::trace;

use crate::{
    PrivateKey, PublicKey, Res, der,
    err::{Error, IntoResult as _, sec::SEC_ERROR_BAD_SIGNATURE, secstatus_to_res},
    init,
    item::{SECItemBorrowed, SECItemMut, ScopedSECItem},
    null_safe_slice,
    p11::{
        self, CK_FLAGS, CK_INVALID_HANDLE, CK_MECHANISM_TYPE, CKA_DERIVE, CKA_VALUE, CKD_NULL,
        CKF_DERIVE, CKF_SIGN, CKF_VERIFY, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM_ECDH1_DERIVE, CKM_ECDSA, CKM_EDDSA, CKM_SHA512_HMAC,
        KU_ALL, PK11_ATTR_INSENSITIVE, PK11_ATTR_PRIVATE, PK11_ATTR_PUBLIC, PK11_ATTR_SENSITIVE,
        PK11_ATTR_SESSION, PK11_ExportDERPrivateKeyInfo, PK11_GenerateKeyPairWithOpFlags,
        PK11_ImportDERPrivateKeyInfoAndReturnKey, PK11_ImportPublicKey, PK11_PubDeriveWithKDF,
        PK11_ReadRawAttribute, PK11ObjectType::PK11_TypePrivKey,
        SECKEY_DecodeDERSubjectPublicKeyInfo, SECOidTag, Slot,
    },
    ssl::PRBool,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Curve {
    P256,
    P384,
    P521,
    X25519,
    Ed25519,
}

impl Curve {
    #[must_use]
    pub const fn can_sign(self) -> bool {
        matches!(self, Self::P256 | Self::P384 | Self::P521 | Self::Ed25519)
    }

    #[must_use]
    pub const fn can_ecdh(self) -> bool {
        matches!(self, Self::P256 | Self::P384 | Self::P521 | Self::X25519)
    }

    const fn to_mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::P256 | Self::P384 | Self::P521 => CKM_EC_KEY_PAIR_GEN,
            Self::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN,
            Self::X25519 => CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        }
    }

    fn get_oid(self) -> Res<Vec<u8>> {
        let oid_tag = SECOidTag::Type::from(self);
        let oid_data_ptr = unsafe { p11::SECOID_FindOIDByTag(oid_tag) }.into_result()?;
        let oid_data = unsafe { &*oid_data_ptr };
        let oid_bytes = unsafe { null_safe_slice(oid_data.oid.data, oid_data.oid.len) };
        der::object_id(oid_bytes)
    }
}

impl From<Curve> for SECOidTag::Type {
    fn from(v: Curve) -> Self {
        match v {
            Curve::X25519 => SECOidTag::SEC_OID_X25519,
            Curve::Ed25519 => SECOidTag::SEC_OID_ED25519_SIGNATURE,
            Curve::P256 => SECOidTag::SEC_OID_ANSIX962_EC_PRIME256V1,
            Curve::P384 => SECOidTag::SEC_OID_SECG_EC_SECP384R1,
            Curve::P521 => SECOidTag::SEC_OID_SECG_EC_SECP521R1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

fn ec_keygen(curve: Curve, flags: CK_FLAGS, sensitive: bool) -> Res<Keypair> {
    init()?;

    // Get the OID for the Curve
    let oid_bytes = curve.get_oid()?;
    let oid = SECItemBorrowed::wrap(&oid_bytes);

    let mech = curve.to_mechanism();
    let attrs = PK11_ATTR_SESSION
        | if sensitive {
            PK11_ATTR_SENSITIVE | PK11_ATTR_PRIVATE
        } else {
            PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC
        };

    // Get the PKCS11 slot
    let slot = Slot::internal()?;

    // Create a pointer for the public key
    let mut public_ptr = ptr::null_mut();
    let secret_ptr = unsafe {
        PK11_GenerateKeyPairWithOpFlags(
            *slot,
            mech,
            oid.as_ptr().cast_mut().cast(), // void* cast
            &raw mut public_ptr,
            attrs,
            flags,
            flags,
            ptr::null_mut(),
        )
    };
    assert_eq!(secret_ptr.is_null(), public_ptr.is_null());

    let sk = PrivateKey::from_ptr(secret_ptr)?;
    let pk = PublicKey::from_ptr(public_ptr)?;
    trace!("Generated key pair: sk={sk:?} pk={pk:?}");

    Ok(Keypair {
        public: pk,
        private: sk,
    })
}

pub fn ecdh_keygen(curve: Curve) -> Res<Keypair> {
    if !curve.can_ecdh() {
        // TODO: use bool::ok_or when MSRV hits 1.98
        return Err(Error::UnsupportedCurve);
    }
    ec_keygen(curve, CK_FLAGS::from(CKF_DERIVE), true)
}

pub fn ecdsa_keygen(curve: Curve) -> Res<Keypair> {
    if !curve.can_sign() {
        return Err(Error::UnsupportedCurve);
    }
    ec_keygen(curve, CK_FLAGS::from(CKF_SIGN | CKF_VERIFY), true)
}

/// Ed25519 keygen in NSS is identical to ECDSA keygen, so this is
/// just an alias for [`ecdsa_keygen`].
pub use ecdsa_keygen as eddsa_keygen;

pub fn ecdh_keygen_extractable(curve: Curve) -> Res<Keypair> {
    if !curve.can_ecdh() {
        return Err(Error::UnsupportedCurve);
    }
    ec_keygen(curve, CK_FLAGS::from(CKF_DERIVE), false)
}

pub fn ecdsa_keygen_extractable(curve: Curve) -> Res<Keypair> {
    if !curve.can_sign() {
        return Err(Error::UnsupportedCurve);
    }
    ec_keygen(curve, CK_FLAGS::from(CKF_SIGN | CKF_VERIFY), false)
}

/// Ed25519 keygen in NSS is identical to ECDSA keygen, so this is
/// just an alias for [`ecdsa_keygen`].
pub use ecdsa_keygen_extractable as eddsa_keygen_extractable;

pub fn export_pkcs8(key: &PrivateKey) -> Res<Vec<u8>> {
    init()?;
    let sk: ScopedSECItem =
        unsafe { PK11_ExportDERPrivateKeyInfo(**key, ptr::null_mut()) }.into_result()?;
    Ok(sk.into_vec())
}

pub fn import_spki(spki: &[u8]) -> Res<PublicKey> {
    init()?;
    let spki_item = SECItemBorrowed::wrap(spki);
    let spki_item_ptr = spki_item.as_ptr();
    let slot = Slot::internal()?;
    unsafe {
        let spki = SECKEY_DecodeDERSubjectPublicKeyInfo(spki_item_ptr).into_result()?;
        let pk: PublicKey = p11::SECKEY_ExtractPublicKey(spki.as_mut().ok_or(Error::InvalidInput)?)
            .into_result()?;

        let handle = PK11_ImportPublicKey(*slot, *pk, PRBool::from(false));
        if handle == CK_INVALID_HANDLE {
            return Err(Error::InvalidInput);
        }

        Ok(pk)
    }
}

pub fn import_pkcs8(pki: &[u8]) -> Res<PrivateKey> {
    init()?;

    // Get the PKCS11 slot
    let slot = Slot::internal()?;
    let der_pki = SECItemBorrowed::wrap(pki);

    // Create a pointer for the private key
    let mut pk_ptr = ptr::null_mut();

    secstatus_to_res(unsafe {
        PK11_ImportDERPrivateKeyInfoAndReturnKey(
            *slot,
            der_pki.as_ptr().cast_mut(), // const_cast!
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            KU_ALL,
            &raw mut pk_ptr,
            ptr::null_mut(),
        )
    })?;

    PrivateKey::from_ptr(pk_ptr)
}

pub fn export_raw(key: &PrivateKey) -> Res<Vec<u8>> {
    init()?;
    let mut key_item = SECItemMut::make_empty();
    secstatus_to_res(unsafe {
        PK11_ReadRawAttribute(PK11_TypePrivKey, key.cast(), CKA_VALUE, key_item.as_mut())
    })?;
    Ok(key_item.as_slice().to_owned())
}

pub fn ecdh(sk: &PrivateKey, pk: &PublicKey) -> Res<Vec<u8>> {
    init()?;
    let sym_key = unsafe {
        PK11_PubDeriveWithKDF(
            **sk,
            **pk,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            CKM_ECDH1_DERIVE,
            CKM_SHA512_HMAC, // not used
            CKA_DERIVE,
            0,
            CKD_NULL,
            ptr::null_mut(),
            ptr::null_mut(),
        )
        .into_result()?
    };

    let key = sym_key.key_data()?;
    Ok(key.to_vec())
}

pub fn convert_to_public(sk: &PrivateKey) -> Res<PublicKey> {
    init()?;
    unsafe {
        let pk = p11::SECKEY_ConvertToPublicKey(**sk).into_result()?;
        Ok(pk)
    }
}

fn sign(private_key: &PrivateKey, data: &[u8], mechanism: CK_MECHANISM_TYPE) -> Res<Vec<u8>> {
    init()?;

    // The buffer has to be exactly the right size: Ed25519 rejects anything else.
    let expected_len = usize::try_from(unsafe { p11::PK11_SignatureLen(**private_key) })
        .map_err(|_| Error::InvalidInput)?;
    if expected_len == 0 {
        return Err(Error::InvalidInput);
    }
    let mut sigbuf = vec![0u8; expected_len];
    let data_to_sign = SECItemBorrowed::wrap(data);
    let mut signature = SECItemBorrowed::wrap_mut(&mut sigbuf);

    secstatus_to_res(unsafe {
        p11::PK11_SignWithMechanism(
            **private_key,
            mechanism,
            ptr::null_mut(),
            signature.as_mut_ptr(),
            data_to_sign.as_ptr(),
        )
    })?;

    let actual_len = signature.len();
    debug_assert_eq!(actual_len, expected_len);
    sigbuf.truncate(actual_len);
    Ok(sigbuf)
}

pub fn sign_ecdsa(private_key: &PrivateKey, data: &[u8]) -> Res<Vec<u8>> {
    sign(private_key, data, CKM_ECDSA)
}

pub fn sign_eddsa(private_key: &PrivateKey, data: &[u8]) -> Res<Vec<u8>> {
    sign(private_key, data, CKM_EDDSA)
}

fn verify(
    public_key: &PublicKey,
    data: &[u8],
    signature: &[u8],
    mechanism: CK_MECHANISM_TYPE,
) -> Res<bool> {
    init()?;
    let data_to_sign = SECItemBorrowed::wrap(data);
    let signature = SECItemBorrowed::wrap(signature);

    let res = secstatus_to_res(unsafe {
        p11::PK11_VerifyWithMechanism(
            **public_key,
            mechanism,
            ptr::null_mut(),
            signature.as_ptr(),
            data_to_sign.as_ptr(),
            ptr::null_mut(),
        )
    });

    // Catch a BAD_SIGNATURE error and convert to Ok(false).
    match res {
        Ok(()) => Ok(true),
        Err(Error::Nss { code, .. }) if code == SEC_ERROR_BAD_SIGNATURE => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn verify_ecdsa(public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Res<bool> {
    verify(public_key, data, signature, CKM_ECDSA)
}

pub fn verify_eddsa(public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Res<bool> {
    verify(public_key, data, signature, CKM_EDDSA)
}
