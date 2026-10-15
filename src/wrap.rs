// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Implement a smart pointer for NSS objects.
///
/// Most of the time the pointer is like a `Box`, but there are exceptions (e.g.
/// `PK11SymKey` is internally reference counted so its pointer is like an `Arc`.)
///
/// Named "scoped" because that is what NSS calls its `unique_ptr` typedefs.
#[macro_export]
macro_rules! scoped_ptr {
    ($name:ident, $target:ty, $dtor:path) => {
        pub struct $name {
            ptr: *mut $target,
        }

        impl $name {
            /// Create a new instance of `$name` from a pointer.
            ///
            /// # Errors
            /// When passed a null pointer generates an error.
            pub fn from_ptr(raw: *mut $target) -> Result<Self, $crate::err::Error> {
                let ptr = $crate::err::into_result(raw)?;
                Ok(Self { ptr })
            }
        }

        impl $crate::err::IntoResult for *mut $target {
            type Ok = $name;

            fn into_result(self) -> Result<Self::Ok, $crate::err::Error> {
                $name::from_ptr(self)
            }
        }

        impl std::ops::Deref for $name {
            type Target = *mut $target;

            fn deref(&self) -> &*mut $target {
                &self.ptr
            }
        }

        // Original implements DerefMut, but is that really a good idea?

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { _ = $dtor(self.ptr) };
            }
        }
    };
}

macro_rules! impl_clone {
    ($name:ty, $nss_fn:path) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                let ptr = unsafe { $nss_fn(self.ptr) };
                assert!(!ptr.is_null());
                Self { ptr }
            }
        }
    };
}
