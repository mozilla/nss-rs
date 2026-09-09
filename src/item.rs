// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{marker::PhantomData, os::raw::c_uint, ptr::null_mut, slice::Iter};

pub use crate::nss_prelude::{SECItem, SECItemArray, SECItemType};
use crate::{
    nss_prelude::{PRBool, SECITEM_FreeArray, SECITEM_FreeItem},
    null_safe_slice,
};

impl SECItem {
    /// Return contents as a slice.
    ///
    /// Unsafe due to calling `from_raw_parts`, or if 'a outlives &self. This
    /// unsafety is encapsulated by the `as_slice` method of `SECItemBorrowed`
    /// and `SECItemMut`.
    ///
    /// Note that safe code can construct a `SECItem` pointing to anything. The
    /// same is not true of the safe wrappers `SECItemMut` and `SECItemBorrowed`
    /// because their inner `SECItem` is private.
    #[must_use]
    pub unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        // Sanity check the type, as some types don't count bytes in `Item::len`.
        assert_eq!(self.type_, SECItemType::siBuffer);
        // Note: `from_raw_parts` requires non-null `data` even for zero-length
        // slices.
        if self.len != 0 {
            unsafe {
                null_safe_slice(
                    self.data,
                    usize::try_from(self.len).expect("Buffer too long"),
                )
            }
        } else {
            &[]
        }
    }
}

unsafe fn destroy_secitem(item: *mut SECItem) {
    unsafe {
        SECITEM_FreeItem(item, PRBool::from(true));
    }
}
scoped_ptr!(ScopedSECItem, SECItem, destroy_secitem);

impl ScopedSECItem {
    /// This dereferences the pointer held by the item and makes a copy of the
    /// content that is referenced there.
    ///
    /// # Safety
    /// This dereferences two pointers.  It doesn't get much less safe.
    #[must_use]
    pub unsafe fn into_vec(self) -> Vec<u8> {
        let b = unsafe { self.ptr.as_ref().expect("Null pointer") };
        // Sanity check the type, as some types don't count bytes in `Item::len`.
        assert_eq!(b.type_, SECItemType::siBuffer);
        let slc =
            unsafe { null_safe_slice(b.data, usize::try_from(b.len).expect("Buffer too long")) };
        Vec::from(slc)
    }
}

unsafe fn destroy_secitem_array(array: *mut SECItemArray) {
    unsafe {
        SECITEM_FreeArray(array, PRBool::from(true));
    }
}
scoped_ptr!(ScopedSECItemArray, SECItemArray, destroy_secitem_array);

impl ScopedSECItemArray {
    #[must_use]
    pub fn iter(&self) -> ScopedSECItemArrayIterator<'_> {
        ScopedSECItemArrayIterator {
            iter: AsRef::<[SECItem]>::as_ref(self).iter(),
        }
    }
}

impl<'a> IntoIterator for &'a ScopedSECItemArray {
    type Item = &'a [u8];
    type IntoIter = ScopedSECItemArrayIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl AsRef<[SECItem]> for ScopedSECItemArray {
    fn as_ref(&self) -> &[SECItem] {
        unsafe { null_safe_slice((*self.ptr).items, (*self.ptr).len) }
    }
}

pub struct ScopedSECItemArrayIterator<'a> {
    iter: Iter<'a, SECItem>,
}

impl<'a> Iterator for ScopedSECItemArrayIterator<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let item = self.iter.next()?;
        unsafe { Some(item.as_slice()) }
    }
}

/// An owned `SECItem`.
///
/// The `SECItem` structure is allocated by Rust. The buffer referenced by the
/// `SECItem` is allocated by NSS. `SECITEM_FreeItem` will be called to free the
/// buffer when the `SECItemMut` is dropped.
///
/// This is used with NSS functions that return a variable amount of data.
#[repr(transparent)]
#[derive(derive_more::AsRef, derive_more::AsMut)]
pub struct SECItemMut {
    #[as_ref]
    #[as_mut]
    inner: SECItem,
}

impl Drop for SECItemMut {
    fn drop(&mut self) {
        // FreeItem unconditionally frees the buffer referenced by the SECItem.
        // If the second argument is true, it also frees the SECItem itself,
        // which we don't want to do, because rust owns that memory.
        unsafe {
            SECITEM_FreeItem(&raw mut self.inner, PRBool::from(false));
        }
    }
}

impl SECItemMut {
    /// Return contents as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { self.inner.as_slice() }
    }

    /// Make an empty `SECItemMut` for passing as a mutable `*SECItem` argument.
    #[must_use]
    pub const fn make_empty() -> Self {
        Self {
            inner: SECItem {
                type_: SECItemType::siBuffer,
                data: null_mut(),
                len: 0,
            },
        }
    }
}

/// A borrowed `SECItem`.
///
/// The `SECItem` structure is allocated by Rust. The buffer referenced by the
/// `SECItem` may be allocated either by Rust or NSS. The `SECItem` does not own the
/// buffer and will not free it when dropped.
///
/// This can be used to pass a reference to some borrowed rust memory to NSS.
///
/// Warning: avoid the following pattern:
///
/// ```ignore
/// let ptr = SECItemBorrowed::wrap(&buf).as_ptr();
/// unsafe { NSS_Function(ptr) };
/// ```
///
/// The borrowed item is dropped on the first line, with the pointer now referencing
/// reclaimed stack space. This can succeed silently, because the buffer remains,
/// but it is a latent bug.
///
/// Either hold the wrapper while the pointer is used:
/// ```ignore
/// let wrapper = SECItemBorrowed::wrap(&buf);
/// unsafe { NSS_Function(ptr.as_ptr()) }
/// ```
///
/// Or, put everything on the one line:
/// ```ignore
/// unsafe { NSS_Function(SECItemBorrowed::wrap(&buf).as_ptr()) }
/// ```
///
/// Many NSS functions are not const-safe, so you might need to cast the pointer
/// to turn it into `*mut SECItem` or, worse, `*mut c_void`:
/// ```ignore
/// let wrapper = SECItemBorrowed::wrap(&buf);
/// unsafe { NSS_ConstUnsafeFn(wrapper.as_ptr().cast_mut()) };   // const_cast
/// unsafe { NSS_VoidStar(wrapper.as_ptr().cast_mut().cast()) }; // `void*` arg
/// ```
#[repr(transparent)]
pub struct SECItemBorrowed<T> {
    inner: SECItem,
    phantom_data: PhantomData<T>,
}

impl<T: AsRef<[u8]>> SECItemBorrowed<T> {
    /// Return contents as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { self.inner.as_slice() }
    }

    /// Get a raw const pointer to the item.
    #[must_use]
    pub const fn as_ptr(&self) -> *const SECItem {
        &raw const self.inner
    }
}

impl<'a> SECItemBorrowed<&'a [u8]> {
    /// Create an empty `SECItemBorrowed`.
    ///
    /// This can be used to pass an empty, read-only item as an argument.
    ///
    /// It is safe to let the caller specify any lifetime here because no
    /// borrowing is actually taking place.  However, it is not safe to pass the
    /// resulting struct to functions that modify this: the lifetime will not
    /// be updated to match.
    #[must_use]
    pub const fn make_empty() -> Self {
        SECItemBorrowed {
            inner: SECItem {
                type_: SECItemType::siBuffer,
                data: null_mut(),
                len: 0,
            },
            phantom_data: PhantomData,
        }
    }

    /// Create a `SECItemBorrowed` wrapping a slice.
    ///
    /// Creating this object is technically safe, but using it is extremely dangerous.
    /// More dangerous even than [`wrap_mut`], which at least borrows the slice mutably.
    ///
    /// This can be passed as a `const SECItem*` argument to functions, but it is only
    /// safe if those functions also treat the data that the `SECItem` points to as
    /// const also, something that the C code does not ensure, because `SECItem.data`
    /// is a plain `unsigned char*` rather than a `const unsigned char*`.
    ///
    /// # Panics
    /// If the slice is so large that it is longer than a `c_uint` can handle.
    ///
    /// [`wrap_mut`]: Self::wrap_mut
    #[must_use]
    pub fn wrap(buf: &'a [u8]) -> Self {
        Self {
            inner: SECItem {
                type_: SECItemType::siBuffer,
                data: if buf.is_empty() {
                    null_mut()
                } else {
                    buf.as_ptr().cast_mut().cast()
                },
                len: c_uint::try_from(buf.len()).expect("slice is crazy big"),
            },
            phantom_data: PhantomData,
        }
    }
}

impl<'a> SECItemBorrowed<&'a mut [u8]> {
    /// Get a raw mut pointer to the item.
    pub const fn as_mut_ptr(&mut self) -> *mut SECItem {
        &raw mut self.inner
    }

    /// Create a `SECItemBorrowed` wrapping a mutable slice.
    ///
    /// Creating this object is technically safe, but using it is extremely dangerous.
    /// The resulting object can be passed as a `SECItem*` argument to functions,
    /// but this is not safe if those functions free or reallocate the memory.
    /// This has to be restricted to those functions that limit their actions to
    /// writing to the memory they are provided.
    ///
    /// # Panics
    /// If the slice is so large that it is longer than a `c_uint` can handle.
    #[must_use]
    pub fn wrap_mut(buf: &'a mut [u8]) -> Self {
        Self {
            inner: SECItem {
                type_: SECItemType::siBuffer,
                data: buf.as_mut_ptr().cast(),
                len: c_uint::try_from(buf.len()).expect("slice is crazy big"),
            },
            phantom_data: PhantomData,
        }
    }
}

/// A `SECItem` that borrows a struct, for passing PKCS#11 mechanism parameters.
///
/// Creating this object is safe, but using it is dangerous in the same way as
/// [`SECItemBorrowed::wrap`]: the resulting `SECItem` can only be passed to
/// functions that treat the referenced struct as `const`.  Writing through the
/// pointer is undefined behaviour, because the struct is only shared-borrowed.
///
/// Note that NSS has a habit of taking `SECItem*` or `void*` as parameter
/// arguments.  In those cases, this will need a call to `as_ptr().cast_mut()`,
/// possibly chained to `.cast()`.
#[repr(transparent)]
pub struct ParamItem<'a, T> {
    inner: SECItem,
    marker: PhantomData<&'a T>,
}

impl<'a, T: Sized + 'a> ParamItem<'a, T> {
    /// Wrap a struct in a `SECItem` for use as a parameter.
    #[must_use]
    pub fn wrap(v: &'a T) -> Self {
        let p: *const T = &raw const *v;
        Self {
            inner: SECItem {
                type_: SECItemType::siBuffer,
                data: p.cast_mut().cast(),
                len: c_uint::try_from(size_of::<T>()).expect("struct is crazy big"),
            },
            marker: PhantomData,
        }
    }

    /// Get a raw const pointer to the item.
    #[must_use]
    pub const fn as_ptr(&self) -> *const SECItem {
        &raw const self.inner
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ParamItem, SECItemBorrowed};

    const DATA: &[u8] = &[1, 2, 3, 4, 5];

    #[test]
    fn wrap_roundtrip() {
        assert_eq!(SECItemBorrowed::wrap(DATA).as_slice(), DATA);
        assert!(SECItemBorrowed::wrap(&[]).as_slice().is_empty());
        assert!(SECItemBorrowed::make_empty().as_slice().is_empty());
    }

    #[test]
    fn wrap_mut_roundtrip() {
        let mut buf = DATA.to_owned();
        let mut item = SECItemBorrowed::wrap_mut(&mut buf);
        assert_eq!(item.as_slice(), DATA);

        // Simulate an NSS in/out buffer: overwrite a prefix, then shorten `len`
        // to the number of bytes actually written.
        unsafe {
            let raw = item.as_mut_ptr();
            assert_eq!(usize::try_from((*raw).len).unwrap(), DATA.len());
            (*raw).data.write(0xff);
            (*raw).len = 1;
        }
        assert_eq!(item.as_slice(), &[0xff]);
        drop(item);
        assert_eq!(buf, [0xff, 2, 3, 4, 5]);
    }

    #[test]
    fn param_len_is_size_of() {
        let v = 0x1234_5678_u32;
        assert_eq!(
            usize::try_from(unsafe { (*ParamItem::wrap(&v).as_ptr()).len }).unwrap(),
            size_of::<u32>()
        );
    }
}
