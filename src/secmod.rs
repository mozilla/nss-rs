// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Runtime PKCS#11 module loading.
//!
//! `SECMOD_LoadUserModule` registers an external PKCS#11 module with NSS at
//! runtime, without going through the user's `secmod.db`. The returned
//! [`SecmodModule`] handle keeps the module loaded for the lifetime of the
//! value; dropping it unloads via `SECMOD_UnloadUserModule` + frees the
//! `SECMODModule` reference.

use std::{ffi::CString, path::Path};

use crate::{
    err::{Error, Res},
    p11::{SECMODModule, SECMOD_DestroyModule, SECMOD_LoadUserModule, SECMOD_UnloadUserModule},
};

unsafe fn destroy_secmod_module(module: *mut SECMODModule) {
    // SECMOD_UnloadUserModule does the actual unload of the dlopen'd
    // library; SECMOD_DestroyModule decrements the ref-count and frees the
    // SECMODModule structure when it reaches zero. Both are needed for a
    // user-loaded module; calling one without the other leaks either the
    // library or the structure.
    unsafe {
        let _ = SECMOD_UnloadUserModule(module);
        SECMOD_DestroyModule(module);
    }
}

scoped_ptr!(SecmodModule, SECMODModule, destroy_secmod_module);

impl SecmodModule {
    /// Load an external PKCS#11 module into NSS at runtime.
    ///
    /// `name` is the human-readable module name (e.g. `"YubiKey PIV"`);
    /// `library_path` is the absolute path to the shared library (e.g.
    /// `/opt/homebrew/lib/libykcs11.dylib`). NSS internally builds the
    /// module-spec string `library="<path>" name="<name>"` and dlopen's
    /// the library.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `name` or `library_path` contain
    ///   characters that cannot be passed to NSS (interior NULs).
    /// - [`Error::Internal`] if `SECMOD_LoadUserModule` rejects the spec.
    pub fn load_user(name: &str, library_path: &Path) -> Res<Self> {
        let path_str = library_path
            .to_str()
            .ok_or(Error::InvalidInput)?;
        // The C string must not contain a `"` because we embed it
        // unquoted in the module spec; bail early on the rare case.
        if name.contains('"') || path_str.contains('"') {
            return Err(Error::InvalidInput);
        }
        let spec = format!("library=\"{path_str}\" name=\"{name}\"");
        let c_spec = CString::new(spec).map_err(|_| Error::InvalidInput)?;
        // `parent = null` (top-level user module), `recursive = false`.
        let ptr = unsafe {
            SECMOD_LoadUserModule(
                c_spec.as_ptr().cast_mut(),
                std::ptr::null_mut(),
                0, // PR_FALSE
            )
        };
        if ptr.is_null() {
            return Err(Error::Internal);
        }
        // `SECMOD_LoadUserModule` always returns a `SECMODModule*` —
        // a non-null pointer doesn't necessarily mean loadSuccess. We have to
        // check the `loaded` field on the struct. Doing so requires the
        // `SECMODModule` struct to be visible in the bindgen output (it is,
        // via the `SECMODModuleStr` allowlist entry).
        if unsafe { (*ptr).loaded } == 0 {
            // The module was registered but failed to load. Unload + free.
            unsafe {
                let _ = SECMOD_UnloadUserModule(ptr);
                SECMOD_DestroyModule(ptr);
            }
            return Err(Error::Internal);
        }
        Self::from_ptr(ptr)
    }

    /// Returns the module's human-readable name as registered with NSS.
    #[must_use]
    pub fn name(&self) -> String {
        let name_ptr = unsafe { (*self.ptr).commonName };
        if name_ptr.is_null() {
            return String::new();
        }
        unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_string_lossy()
            .into_owned()
    }

    /// Returns the number of slots exposed by this module.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        let n = unsafe { (*self.ptr).slotCount };
        usize::try_from(n).unwrap_or(0)
    }
}

// `SECMODModule` is internally synchronised by NSS; the handle can move
// across threads safely once loaded.
unsafe impl Send for SecmodModule {}
unsafe impl Sync for SecmodModule {}
