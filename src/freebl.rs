// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Bindings to NSS's freebl AEAD primitives, bypassing the PKCS#11 session
// layer.
//
// NOTE: calling these functions directly bypasses softoken's FIPS power-on
// self-test gate. This is intentional for neqo (non-FIPS) and saves ~7.6%
// CPU on the PK11_AEADOp hot path (sftk_SessionFromHandle + mutex overhead).
//
// Functions are accessed through FREEBL_GetVector() rather than as direct
// symbol references, because on some platforms (e.g. FreeBSD) the freebl
// shared library only exports FREEBL_GetVector and does not export individual
// function symbols. The partial FREEBLVectorStr layout was verified against
// lib/freebl/loader.h in NSS 3.x.

use std::{
    os::raw::{c_int, c_uchar, c_uint, c_ulong, c_void},
    sync::OnceLock,
};

use crate::{aead::Mode, err::Res};

// NSS_AES = 0 (ECB), NSS_AES_GCM = 4, AES_BLOCK_SIZE = 16 (from blapit.h)
pub const NSS_AES: c_int = 0;
pub const NSS_AES_GCM: c_int = 4;
pub const AES_BLOCK_SIZE: c_uint = 16;

// Opaque freebl cipher contexts.
#[repr(C)]
pub struct AESContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ChaCha20Poly1305Context {
    _private: [u8; 0],
}

// GCM message-level params (PKCS#11 v3, pkcs11t.h).
// For CKG_NO_GENERATE (ivGenerator = 0), pIv/ulIvLen supply the full nonce.
// For encrypt, pTag is the output tag buffer; for decrypt, pTag is the input
// tag to verify. ulTagBits = TAG_LEN * 8 = 128.
//
// NSS's pkcs11t.h pulls in pkcs11p.h which applies `#pragma pack(push,
// cryptoki, 1)` on all platforms.  On LP64 all six fields are 8 bytes wide so
// packing is a no-op (sizeof = 48).  On Windows LLP64 (CK_ULONG = 4 bytes)
// packing removes the natural 4-byte padding before `pTag` (sizeof = 32).
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[expect(non_snake_case, reason = "PKCS#11 naming conventions.")]
pub struct CK_GCM_MESSAGE_PARAMS {
    pub pIv: *mut c_uchar,
    pub ulIvLen: c_ulong,
    pub ulIvFixedBits: c_ulong,
    pub ivGenerator: c_ulong, // CK_GENERATOR_FUNCTION; 0 = CKG_NO_GENERATE
    pub pTag: *mut c_uchar,
    pub ulTagBits: c_ulong,
}

// LP64: pointer == c_ulong == 8 bytes, no padding even packed → size = 6 × 8.
// Windows LLP64: packed size = 32, which != 6 × 4 = 24, so skip the check.
#[cfg(not(target_os = "windows"))]
const _: () = assert!(size_of::<CK_GCM_MESSAGE_PARAMS>() == 6 * size_of::<c_ulong>());

// Function pointer type for ChaCha20-Poly1305 encrypt/decrypt.
// Both operations share an identical signature; direction is baked in at
// construction time by storing either the encrypt or decrypt pointer.
pub type ChaChaOpFn = unsafe extern "C" fn(
    *const ChaCha20Poly1305Context,
    *mut c_uchar,
    *mut c_uint,
    c_uint,
    *const c_uchar,
    c_uint,
    *const c_uchar,
    c_uint,
    *const c_uchar,
    c_uint,
    *mut c_uchar,
) -> c_int;

type AesCreateFn = unsafe extern "C" fn(
    *const c_uchar,
    *const c_uchar,
    c_int,
    c_int,
    c_uint,
    c_uint,
) -> *mut AESContext;
type AesDestroyFn = unsafe extern "C" fn(*mut AESContext, c_int);
type AesEncryptFn = unsafe extern "C" fn(
    *mut AESContext,
    *mut c_uchar,
    *mut c_uint,
    c_uint,
    *const c_uchar,
    c_uint,
) -> c_int;
type AesAeadFn = unsafe extern "C" fn(
    *mut AESContext,
    *mut c_uchar,
    *mut c_uint,
    c_uint,
    *const c_uchar,
    c_uint,
    *mut c_void,
    c_uint,
    *const c_uchar,
    c_uint,
) -> c_int;
type ChaChaCreateFn =
    unsafe extern "C" fn(*const c_uchar, c_uint, c_uint) -> *mut ChaCha20Poly1305Context;
type ChaChaDestroyFn = unsafe extern "C" fn(*mut ChaCha20Poly1305Context, c_int);
type ChaCha20XorFn = unsafe extern "C" fn(
    *mut c_uchar,
    *const c_uchar,
    c_uint,
    *const c_uchar,
    *const c_uchar,
    u32,
) -> c_int;

// Partial FREEBLVectorStr layout (lib/freebl/loader.h, NSS 3.x).
// Only the fields needed for AEAD and HP operations are named; the rest are
// opaque padding. Field positions (1-indexed from function pointers):
//   30: p_AES_CreateContext        31: p_AES_DestroyContext
//   32: p_AES_Encrypt              33: (p_AES_Decrypt, skipped)
//  211: p_ChaCha20Poly1305_Create 212: p_ChaCha20Poly1305_Destroy
//  228: p_ChaCha20_Xor
//  235: p_ChaCha20Poly1305_Encrypt 236: p_ChaCha20Poly1305_Decrypt
//  237: p_AES_AEAD
#[repr(C)]
#[expect(
    non_snake_case,
    reason = "Matches C field names from loader.h for cross-reference."
)]
struct FREEBLVectorPartial {
    length: u16,
    version: u16,
    _pre_aes: [*const c_void; 29],                              // 1–29
    p_AES_CreateContext: Option<AesCreateFn>,                   // 30
    p_AES_DestroyContext: Option<AesDestroyFn>,                 // 31
    p_AES_Encrypt: Option<AesEncryptFn>,                        // 32
    _skip_33: *const c_void,                                    // 33 (p_AES_Decrypt, unused)
    _between1: [*const c_void; 177],                            // 34–210
    p_ChaCha20Poly1305_CreateContext: Option<ChaChaCreateFn>,   // 211
    p_ChaCha20Poly1305_DestroyContext: Option<ChaChaDestroyFn>, // 212
    _between2: [*const c_void; 15],                             // 213–227
    p_ChaCha20_Xor: Option<ChaCha20XorFn>,                      // 228
    _between2b: [*const c_void; 6],                             // 229–234
    p_ChaCha20Poly1305_Encrypt: Option<ChaChaOpFn>,             // 235
    p_ChaCha20Poly1305_Decrypt: Option<ChaChaOpFn>,             // 236
    p_AES_AEAD: Option<AesAeadFn>,                              // 237
}

// Extracted, non-nullable function pointers with idiomatic Rust names.
struct FreeblFns {
    aes_create: AesCreateFn,
    aes_destroy: AesDestroyFn,
    aes_encrypt: AesEncryptFn,
    aes_aead: AesAeadFn,
    chacha_create: ChaChaCreateFn,
    chacha_destroy: ChaChaDestroyFn,
    chacha_encrypt: ChaChaOpFn,
    chacha_decrypt: ChaChaOpFn,
    chacha_xor: ChaCha20XorFn,
}

unsafe extern "C" {
    fn FREEBL_GetVector() -> *const FREEBLVectorPartial;
}

fn freebl() -> &'static FreeblFns {
    static FREEBL: OnceLock<FreeblFns> = OnceLock::new();
    FREEBL.get_or_init(|| {
        let ptr = unsafe { FREEBL_GetVector() };
        assert!(!ptr.is_null(), "FREEBL_GetVector() returned null");
        let v = unsafe { &*ptr };
        assert!(
            usize::from(v.length) >= size_of::<FREEBLVectorPartial>(),
            "freebl vector too short (length {}, need {})",
            v.length,
            size_of::<FREEBLVectorPartial>(),
        );
        FreeblFns {
            aes_create: v.p_AES_CreateContext.expect("freebl: AES_CreateContext"),
            aes_destroy: v.p_AES_DestroyContext.expect("freebl: AES_DestroyContext"),
            aes_encrypt: v.p_AES_Encrypt.expect("freebl: AES_Encrypt"),
            aes_aead: v.p_AES_AEAD.expect("freebl: AES_AEAD"),
            chacha_create: v
                .p_ChaCha20Poly1305_CreateContext
                .expect("freebl: ChaCha20Poly1305_CreateContext"),
            chacha_destroy: v
                .p_ChaCha20Poly1305_DestroyContext
                .expect("freebl: ChaCha20Poly1305_DestroyContext"),
            chacha_encrypt: v
                .p_ChaCha20Poly1305_Encrypt
                .expect("freebl: ChaCha20Poly1305_Encrypt"),
            chacha_decrypt: v
                .p_ChaCha20Poly1305_Decrypt
                .expect("freebl: ChaCha20Poly1305_Decrypt"),
            chacha_xor: v.p_ChaCha20_Xor.expect("freebl: ChaCha20_Xor"),
        }
    })
}

#[expect(non_snake_case, reason = "Matches the freebl C API.")]
unsafe fn AES_CreateContext(
    key: *const c_uchar,
    iv: *const c_uchar,
    mode: c_int,
    encrypt: c_int,
    keylen: c_uint,
    blocklen: c_uint,
) -> *mut AESContext {
    unsafe { (freebl().aes_create)(key, iv, mode, encrypt, keylen, blocklen) }
}

/// Create an `AesCtx` for the given AES `mode` and `encrypt` direction.
///
/// `key` supplies both the key bytes and the key length via its slice length.
/// The IV is always `null` — ECB needs none, and GCM supplies the IV
/// per-operation via the params struct passed to `AES_AEAD`.
pub fn aes_context(key: &[u8], mode: c_int, encrypt: bool) -> Res<AesCtx> {
    debug_assert!(
        key.len() == 16 || key.len() == 32,
        "AES key must be 16 or 32 bytes, got {}",
        key.len()
    );
    AesCtx::from_ptr(unsafe {
        AES_CreateContext(
            key.as_ptr(),
            std::ptr::null(),
            mode,
            c_int::from(encrypt),
            c_uint::try_from(key.len())?,
            AES_BLOCK_SIZE,
        )
    })
}

#[expect(non_snake_case, reason = "Matches the freebl C API.")]
pub unsafe fn AES_Encrypt(
    cx: *mut AESContext,
    output: *mut c_uchar,
    output_len: *mut c_uint,
    max_output_len: c_uint,
    input: *const c_uchar,
    input_len: c_uint,
) -> c_int {
    unsafe { (freebl().aes_encrypt)(cx, output, output_len, max_output_len, input, input_len) }
}

#[expect(
    clippy::too_many_arguments,
    non_snake_case,
    reason = "Matches the 10-argument freebl C API."
)]
pub unsafe fn AES_AEAD(
    cx: *mut AESContext,
    output: *mut c_uchar,
    outputLen: *mut c_uint,
    maxOutputLen: c_uint,
    input: *const c_uchar,
    inputLen: c_uint,
    params: *mut c_void,
    paramsLen: c_uint,
    aad: *const c_uchar,
    aadLen: c_uint,
) -> c_int {
    unsafe {
        (freebl().aes_aead)(
            cx,
            output,
            outputLen,
            maxOutputLen,
            input,
            inputLen,
            params,
            paramsLen,
            aad,
            aadLen,
        )
    }
}

#[expect(non_snake_case, reason = "Matches the freebl C API.")]
pub unsafe fn ChaCha20Poly1305_CreateContext(
    key: *const c_uchar,
    keyLen: c_uint,
    tagLen: c_uint,
) -> *mut ChaCha20Poly1305Context {
    unsafe { (freebl().chacha_create)(key, keyLen, tagLen) }
}

#[expect(non_snake_case, reason = "Matches the freebl C API.")]
pub unsafe fn ChaCha20_Xor(
    output: *mut c_uchar,
    block: *const c_uchar,
    len: c_uint,
    k: *const c_uchar,
    nonce: *const c_uchar,
    ctr: u32,
) -> c_int {
    unsafe { (freebl().chacha_xor)(output, block, len, k, nonce, ctr) }
}

/// Returns the encrypt or decrypt function pointer for ChaCha20-Poly1305.
/// The caller stores this at construction time to bake in the direction.
pub fn chacha20_poly1305_op(mode: Mode) -> ChaChaOpFn {
    let f = freebl();
    match mode {
        Mode::Encrypt => f.chacha_encrypt,
        Mode::Decrypt => f.chacha_decrypt,
    }
}

unsafe fn destroy_aes_context(cx: *mut AESContext) {
    unsafe {
        (freebl().aes_destroy)(cx, 1 /* PR_TRUE */);
    }
}

unsafe fn destroy_chacha20_context(ctx: *mut ChaCha20Poly1305Context) {
    unsafe {
        (freebl().chacha_destroy)(ctx, 1 /* PR_TRUE */);
    }
}

scoped_ptr!(AesCtx, AESContext, destroy_aes_context);
scoped_ptr!(
    ChaCha20Ctx,
    ChaCha20Poly1305Context,
    destroy_chacha20_context
);
