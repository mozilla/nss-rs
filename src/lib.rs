// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]
// Bindgen auto generated code
// won't adhere to the clippy rules below
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::unseparated_literal_suffix)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_safety_doc)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[cfg(feature = "disable-encryption")]
pub mod aead_null;
pub mod agent;
mod agentio;
mod auth;
mod cert;
pub mod constants;
mod ech;
#[macro_use]
mod util;
#[macro_use]
mod err;
#[macro_use]
mod exp;
pub mod ext;
pub mod hkdf;
pub mod hp;

pub mod aead;
pub mod der;
pub mod ec;
pub mod hash;
pub mod hmac;
pub mod p11;
mod prio;
mod replay;
mod secrets;
pub mod selfencrypt;
mod ssl;
pub mod time;

use std::{
    convert::TryFrom,
    env,
    ffi::CString,
    path::{Path, PathBuf},
    ptr::null,
};

use log::error;
use once_cell::sync::OnceCell;

#[cfg(not(feature = "disable-encryption"))]
pub use self::aead::RealAead as Aead;
#[cfg(feature = "disable-encryption")]
pub use self::aead::RealAead;
#[cfg(feature = "disable-encryption")]
pub use self::aead_null::AeadNull as Aead;
pub use self::{
    agent::{
        Agent, AllowZeroRtt, Client, HandshakeState, Record, RecordList, ResumptionToken,
        SecretAgent, SecretAgentInfo, SecretAgentPreInfo, Server, ZeroRttCheckResult,
        ZeroRttChecker,
    },
    auth::AuthenticationStatus,
    constants::*,
    ech::{
        encode_config as encode_ech_config, generate_keys as generate_ech_keys, AeadId, KdfId,
        KemId, SymmetricSuite,
    },
    err::{secstatus_to_res, Error, IntoResult, PRErrorCode, Res},
    ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult},
    p11::{random, randomize, PrivateKey, PublicKey, SymKey},
    replay::AntiReplay,
    secrets::SecretDirection,
    ssl::Opt,
    util::*,
};

mod min_version;
use min_version::MINIMUM_NSS_VERSION;

#[expect(non_snake_case)]
#[expect(non_upper_case_globals)]
pub mod nss_prelude {
    pub use _SECStatus::*;

    pub use crate::prtypes::*;
    include!(concat!(env!("OUT_DIR"), "/nss_prelude.rs"));
}
pub use nss_prelude::{SECItem, SECItemArray, SECItemType, SECStatus};

#[expect(non_upper_case_globals, reason = "Code is bindgen-generated.")]
mod nss {
    use crate::nss_prelude::*;
    include!(concat!(env!("OUT_DIR"), "/nss_init.rs"));
}

pub mod prtypes;
pub use prtypes::*;

// Shadow these bindgen created values to correct their type.
#[expect(clippy::cast_possible_wrap)]
pub const PR_FALSE: PRBool = prtypes::PR_FALSE as PRBool;
#[expect(clippy::cast_possible_wrap)]
pub const PR_TRUE: PRBool = prtypes::PR_TRUE as PRBool;

enum NssLoaded {
    External,
    NoDb,
    #[expect(dead_code)]
    Db(Box<Path>),
}

impl Drop for NssLoaded {
    fn drop(&mut self) {
        if !matches!(self, Self::External) {
            unsafe {
                secstatus_to_res(nss::NSS_Shutdown()).expect("NSS Shutdown failed");
            }
        }
    }
}

static INITIALIZED: OnceCell<Res<NssLoaded>> = OnceCell::new();

fn version_check() -> Res<()> {
    let min_ver = CString::new(MINIMUM_NSS_VERSION)?;
    if unsafe { nss::NSS_VersionCheck(min_ver.as_ptr()) } == 0 {
        error!("Minimum NSS version of {MINIMUM_NSS_VERSION} not supported");
        return Err(Error::UnsupportedVersion);
    }
    Ok(())
}

/// This enables SSLTRACE by calling a simple, harmless function to trigger its
/// side effects.  SSLTRACE is not enabled in NSS until a socket is made or
/// global options are accessed.  Reading an option is the least impact approach.
/// This allows us to use SSLTRACE in all of our unit tests and programs.
#[cfg(debug_assertions)]
fn enable_ssl_trace() -> Res<()> {
    let opt = Opt::Locking.as_int();
    let mut v: ::std::os::raw::c_int = 0;
    secstatus_to_res(unsafe { ssl::SSL_OptionGetDefault(opt, &mut v) })
}

fn init_once(db: Option<PathBuf>) -> Res<NssLoaded> {
    // Set time zero.
    time::init();
    version_check()?;
    if unsafe { nss::NSS_IsInitialized() != 0 } {
        return Ok(NssLoaded::External);
    }

    let state = if let Some(path) = db {
        if !path.is_dir() {
            return Err(Error::Internal);
        }
        let pathstr = path.to_str().ok_or(Error::Internal)?;
        let dircstr = CString::new(pathstr)?;
        let empty = CString::new("")?;
        secstatus_to_res(unsafe {
            nss::NSS_Initialize(
                dircstr.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
                nss::SECMOD_DB.as_ptr().cast(),
                nss::NSS_INIT_READONLY,
            )
        })?;

        secstatus_to_res(unsafe {
            ssl::SSL_ConfigServerSessionIDCache(1024, 0, 0, dircstr.as_ptr())
        })?;
        NssLoaded::Db(path.into_boxed_path())
    } else {
        secstatus_to_res(unsafe { nss::NSS_NoDB_Init(null()) })?;
        NssLoaded::NoDb
    };

    secstatus_to_res(unsafe { nss::NSS_SetDomesticPolicy() })?;

    #[cfg(debug_assertions)]
    enable_ssl_trace()?;

    Ok(state)
}

/// Initialize NSS.  This only executes the initialization routines once, so if there is any chance
/// that this is invoked twice, that's OK.
///
/// # Errors
///
/// When NSS initialization fails.
pub fn init() -> Res<()> {
    let res = INITIALIZED.get_or_init(|| init_once(None));
    res.as_ref().map(|_| ()).map_err(Clone::clone)
}

/// Initialize with a database.
///
/// # Errors
///
/// If NSS cannot be initialized.
pub fn init_db<P: Into<PathBuf>>(dir: P) -> Res<()> {
    // Allow overriding the NSS database path with an environment variable.
    let dir =
        env::var("NSS_DB_PATH").unwrap_or(dir.into().to_str().ok_or(Error::Internal)?.to_string());
    let res = INITIALIZED.get_or_init(|| init_once(Some(dir.into())));
    res.as_ref().map(|_| ()).map_err(Clone::clone)
}

/// # Panics
///
/// If NSS isn't initialized.
pub fn assert_initialized() {
    INITIALIZED
        .get()
        .expect("NSS not initialized with init or init_db");
}

/// NSS tends to return empty "slices" with a null pointer, which will cause
/// `std::slice::from_raw_parts` to panic if passed directly.  This wrapper avoids
/// that issue.  It also performs conversion for lengths, as a convenience.
///
/// # Panics
/// If the provided length doesn't fit into a `usize`.
///
/// # Safety
/// The caller must adhere to the safety constraints of `std::slice::from_raw_parts`,
/// except that this will accept a null value for `data`.
unsafe fn null_safe_slice<'a, T, L>(data: *const T, len: L) -> &'a [T]
where
    usize: TryFrom<L>,
{
    let len = usize::try_from(len).unwrap_or_else(|_| panic!("null_safe_slice: size overflow"));
    if data.is_null() || len == 0 {
        &[]
    } else {
        #[expect(clippy::disallowed_methods, reason = "This is non-null.")]
        std::slice::from_raw_parts(data, len)
    }
}
