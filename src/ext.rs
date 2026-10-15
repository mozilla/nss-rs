// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::unwrap_used,
    reason = "Let's assume the use of `unwrap` was checked when the use of `unsafe` was reviewed."
)]

use std::{
    cell::RefCell,
    fmt::{self, Debug, Formatter},
    os::raw::{c_uint, c_void},
    pin::Pin,
    rc::Rc,
};

use crate::{
    SECStatus,
    agentio::as_c_void,
    constants::{Extension, HandshakeMessage, TLS_HS_CLIENT_HELLO, TLS_HS_ENCRYPTED_EXTENSIONS},
    err::{Error, Res},
    nss_prelude::PRBool,
    null_safe_slice,
    prio::PRFileDesc,
    ssl::{
        SECFailure, SECSuccess, SSLAlertDescription, SSLExtensionHandler, SSLExtensionWriter,
        SSLHandshakeType,
    },
};

experimental_api! {
    SSL_InstallExtensionHooks(
        fd: *mut PRFileDesc,
        extension: u16,
        writer: SSLExtensionWriter,
        writer_arg: *mut c_void,
        handler: SSLExtensionHandler,
        handler_arg: *mut c_void,
    );
    SSL_CallExtensionWriterOnEchInner(
        fd: *mut PRFileDesc,
        enabled: PRBool,
    );
}

pub enum ExtensionWriterResult {
    Write,
    Skip,
}

/// The buffer that NSS provides for writing an extension.
///
/// This owns the write cursor, so the number of bytes NSS is told about is
/// always the number of bytes that were actually written.
pub struct ExtensionWriter<'a> {
    buf: &'a mut [u8],
    written: usize,
}

impl<'a> ExtensionWriter<'a> {
    const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, written: 0 }
    }

    /// How much space is left.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.written
    }

    /// Append `data` to the extension.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when `data` is larger than [`Self::remaining`],
    /// in which case nothing is written and the cursor does not move.
    pub fn write(&mut self, data: &[u8]) -> Res<()> {
        let end = self
            .written
            .checked_add(data.len())
            .ok_or(Error::InvalidInput)?;
        let dst = self
            .buf
            .get_mut(self.written..end)
            .ok_or(Error::InvalidInput)?;
        dst.copy_from_slice(data);
        self.written = end;
        Ok(())
    }

    /// The number of bytes written, for reporting back to NSS.
    fn written(&self) -> c_uint {
        // `write` bounds this by the length of the buffer, which NSS gave us
        // as a `c_uint`.
        c_uint::try_from(self.written).unwrap_or_else(|_| unreachable!("bounded by max_len"))
    }
}

pub enum ExtensionHandlerResult {
    Ok,
    Alert(crate::constants::Alert),
}

pub trait ExtensionHandler {
    /// Write an extension using the given writer.
    /// NSS will call back when it needs an extension.
    /// Supply the bytes of the extension (without a type and length);
    /// the default implementation writes a zero-length extension
    /// to both the `ClientHello` and `EncryptedExtensions` message.
    ///
    /// The value of `ch_outer` is only relevant when ECH is enabled;
    /// it will be `false` when ECH is disabled or for the inner `ClientHello`.
    /// For ECH, where `msg == TLS_HS_CLIENT_HELLO`,
    /// you can write different values to the inner and outer extensions;
    /// if they are different, NSS won't compress them.
    fn write(
        &mut self,
        msg: HandshakeMessage,
        _ch_outer: bool,
        _w: &mut ExtensionWriter<'_>,
    ) -> ExtensionWriterResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => ExtensionWriterResult::Write,
            _ => ExtensionWriterResult::Skip,
        }
    }

    fn handle(&mut self, msg: HandshakeMessage, _d: &[u8]) -> ExtensionHandlerResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => ExtensionHandlerResult::Ok,
            _ => ExtensionHandlerResult::Alert(110), // unsupported_extension
        }
    }
}

type BoxedExtensionHandler = Box<Rc<RefCell<dyn ExtensionHandler>>>;

pub struct ExtensionTracker {
    extension: Extension,
    handler: Pin<Box<BoxedExtensionHandler>>,
}

impl ExtensionTracker {
    // Technically the as_mut() call here is the only unsafe bit,
    // but don't call this function lightly.
    unsafe fn wrap_handler_call<F, T>(arg: *mut c_void, f: F) -> T
    where
        F: FnOnce(&mut dyn ExtensionHandler) -> T,
    {
        let rc = unsafe { arg.cast::<BoxedExtensionHandler>().as_mut().unwrap() };
        f(&mut *rc.borrow_mut())
    }

    unsafe extern "C" fn extension_writer(
        _fd: *mut PRFileDesc,
        message: SSLHandshakeType::Type,
        data: *mut u8,
        len: *mut c_uint,
        max_len: c_uint,
        arg: *mut c_void,
    ) -> PRBool {
        // The input message type is larger than the `u8` range of `SSLHandshakeType`.
        // The only valid value outside that range is for ECH outer ClientHello,
        // which we need to have special handling for.
        let (msg, ch_outer) = HandshakeMessage::try_from(message).map_or_else(
            |_| {
                debug_assert_eq!(message, SSLHandshakeType::ssl_hs_ech_outer_client_hello);
                (TLS_HS_CLIENT_HELLO, true)
            },
            |msg| (msg, false),
        );
        let d = unsafe { std::slice::from_raw_parts_mut(data, max_len as usize) };
        let mut w = ExtensionWriter::new(d);
        // provided by NSS for writing the output length.
        unsafe {
            Self::wrap_handler_call(arg, |handler| match handler.write(msg, ch_outer, &mut w) {
                ExtensionWriterResult::Write => {
                    *len = w.written();
                    1
                }
                ExtensionWriterResult::Skip => 0,
            })
        }
    }

    unsafe extern "C" fn extension_handler(
        _fd: *mut PRFileDesc,
        message: SSLHandshakeType::Type,
        data: *const u8,
        len: c_uint,
        alert: *mut SSLAlertDescription,
        arg: *mut c_void,
    ) -> SECStatus {
        let d = unsafe { null_safe_slice(data, len) };
        // provided by NSS for writing the alert description.
        unsafe {
            Self::wrap_handler_call(arg, |handler| {
                // Cast is safe here because the message type is always part of the enum
                #[allow(
                    clippy::allow_attributes,
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "Cast is safe here because the message type is always part of the enum."
                )]
                match handler.handle(message as HandshakeMessage, d) {
                    ExtensionHandlerResult::Ok => SECSuccess,
                    ExtensionHandlerResult::Alert(a) => {
                        *alert = a;
                        SECFailure
                    }
                }
            })
        }
    }

    /// Use the provided handler to manage an extension.  This is quite unsafe.
    ///
    /// # Safety
    ///
    /// The holder of this `ExtensionTracker` needs to ensure that it lives at
    /// least as long as the file descriptor, as NSS provides no way to remove
    /// an extension handler once it is configured.
    ///
    /// # Errors
    ///
    /// If the underlying NSS API fails to register a handler.
    pub unsafe fn new(
        fd: *mut PRFileDesc,
        extension: Extension,
        handler: Rc<RefCell<dyn ExtensionHandler>>,
    ) -> Res<Self> {
        unsafe {
            // The ergonomics here aren't great for users of this API, but it's
            // horrific here. The pinned outer box gives us a stable pointer to the inner
            // box.  This is the pointer that is passed to NSS.
            //
            // The inner box points to the reference-counted object.  This inner box is
            // what we end up with a reference to in callbacks.  That extra wrapper around
            // the Rc avoid any touching of reference counts in callbacks, which would
            // inevitably lead to leaks as we don't control how many times the callback
            // is invoked.
            //
            // This way, only this "outer" code deals with the reference count.
            let mut tracker = Self {
                extension,
                handler: Box::pin(Box::new(handler)),
            };
            SSL_InstallExtensionHooks(
                fd,
                extension,
                Some(Self::extension_writer),
                as_c_void(&mut tracker.handler),
                Some(Self::extension_handler),
                as_c_void(&mut tracker.handler),
            )?;
            Ok(tracker)
        }
    }
}

impl Debug for ExtensionTracker {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ExtensionTracker: {:?}", self.extension)
    }
}
