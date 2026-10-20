// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{ffi::c_void, marker::PhantomData, os::raw::c_uint, ptr, slice::Iter};

pub use crate::nss_prelude::{SECItem, SECItemArray, SECItemType};
use crate::{
    Res,
    nss_prelude::{PRBool, SECITEM_FreeArray, SECITEM_FreeItem},
    null_safe_slice,
};

impl SECItem {
    #[expect(clippy::cast_possible_truncation, reason = "input explicitly checked")]
    const fn raw(data: *mut u8, len: usize) -> Self {
        assert!(len <= c_uint::MAX as usize, "item is crazy big");
        SECItem {
            type_: SECItemType::siBuffer,
            data,
            len: len as c_uint,
        }
    }

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
        unsafe { null_safe_slice(self.data, self.len) }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        usize::try_from(self.len).expect("Buffer too long")
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
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
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        // SAFETY: `scoped_ptr!` rejects null, and the pointer comes from NSS,
        // which guarantees a well-formed `SECItem`.
        Vec::from(unsafe { (*self.ptr).as_slice() })
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

/// An owned `SECItem` for memory allocated by NSS.
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
            inner: SECItem::raw(ptr::null_mut(), 0),
        }
    }
}

/// A borrowed `SECItem` that references a Rust-allocated slice.
///
/// This can be used to pass a reference to some borrowed rust memory to NSS.
/// Both `const` and `mut` slices can be wrapped using
/// [`SECItemBorrowed::wrap`] and [`SECItemBorrowed::wrap_mut`] respectively.
/// Only the latter exposes [`SECItemBorrowed::as_mut_ptr`]. This follows the
/// convention in NSS to take a `*mut SECItem` when the item is written to
/// and a `*const SECItem` for read-only inputs
/// (despite the `SECItem.data` pointer not being `const`).
///
/// This convention is imperfect, as some NSS functions allocate or reallocate
/// when provided with a `*mut SECItem`.  This type is NOT safe to use in that case;
/// use [`SECItemMut`] instead.
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
/// unsafe { NSS_Function(wrapper.as_ptr()) }
/// ```
///
/// Or, create the wrapper as a temporary inside the same statement as the call:
/// ```ignore
/// unsafe { NSS_Function(SECItemBorrowed::wrap(&buf).as_ptr()) }
/// ```
///
/// Many NSS functions are not const-safe, so you might need to cast the pointer
/// to turn it into `*mut SECItem`:
/// ```ignore
/// let wrapper = SECItemBorrowed::wrap(&buf);
/// unsafe { NSS_ConstUnsafe(wrapper.as_ptr().cast_mut()) };   // const_cast
/// ```
///
/// For functions that take `*mut c_void`, there is a helper.
/// ```ignore
/// let wrapper = SECItemBorrowed::wrap(&buf);
/// unsafe { NSS_VoidStar(wrapper.as_void_ptr()) };
/// ```
#[repr(transparent)]
pub struct SECItemBorrowed<T> {
    inner: SECItem,
    phantom_data: PhantomData<T>,
}

impl<T: AsRef<[u8]>> SECItemBorrowed<T> {
    /// Return contents as a slice.
    #[must_use]
    #[cfg_attr(not(test), deprecated)] // TODO: switch back to `cfg(test)`
    pub fn as_slice(&self) -> &[u8] {
        unsafe { self.inner.as_slice() }
    }

    #[must_use]
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Get a raw const pointer to the item.
    #[must_use]
    pub const fn as_ptr(&self) -> *const SECItem {
        &raw const self.inner
    }

    /// Get a mutable `void*` pointer to the item,
    /// as needed by some PKCS#11 functions.
    #[must_use]
    pub const fn as_void_ptr(&self) -> *mut c_void {
        self.as_ptr().cast_mut().cast()
    }
}

impl<'a> SECItemBorrowed<&'a [u8]> {
    /// Create an empty `SECItemBorrowed`.
    ///
    /// This can be used to pass an empty, read-only item as an argument.
    #[must_use]
    pub const fn make_empty() -> Self {
        SECItemBorrowed {
            inner: SECItem::raw(ptr::null_mut(), 0),
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
    pub const fn wrap(buf: &'a [u8]) -> Self {
        let data = if buf.is_empty() {
            ptr::null_mut()
        } else {
            buf.as_ptr().cast_mut().cast()
        };
        Self {
            inner: SECItem::raw(data, buf.len()),
            phantom_data: PhantomData,
        }
    }

    #[deprecated(note = "use ParamItem::wrap")]
    #[expect(clippy::unnecessary_wraps, reason = "semver")]
    pub const fn wrap_struct<T>(v: &'a T) -> Res<Self> {
        let data = &raw const *v;
        Ok(Self {
            inner: SECItem::raw(data.cast_mut().cast(), size_of::<T>()),
            phantom_data: PhantomData,
        })
    }
}

impl<'a> SECItemBorrowed<&'a mut [u8]> {
    /// Get a raw mut pointer to the item.
    #[must_use]
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
    pub const fn wrap_mut(buf: &'a mut [u8]) -> Self {
        let data = if buf.is_empty() {
            ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        Self {
            inner: SECItem::raw(data, buf.len()),
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
    pub const fn wrap(v: &'a T) -> Self {
        let p = &raw const *v;
        Self {
            inner: SECItem::raw(p.cast_mut().cast(), size_of::<T>()),
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

    const DATA: &[u8] = &[1, 2, 3];

    #[test]
    fn wrap_roundtrip() {
        let item = SECItemBorrowed::wrap(DATA);
        assert_eq!(item.as_slice(), DATA);
        assert_eq!(item.len(), DATA.len());
        assert_eq!(unsafe { (*item.as_ptr()).data }.cast_const(), DATA.as_ptr());
        assert_eq!(item.as_void_ptr().cast_const().cast(), item.as_ptr());
    }

    #[test]
    fn wrap_mut_roundtrip() {
        let mut buf = DATA.to_owned();
        let mut item = SECItemBorrowed::wrap_mut(&mut buf);
        assert_eq!(item.len(), DATA.len());
        assert_eq!(item.as_slice(), DATA);

        // Simulate writing to the SECItem and then truncating it.
        unsafe {
            (*item.as_mut_ptr()).data.write(0xff);
            (*item.as_mut_ptr()).len = 2;
        };
        assert_eq!(item.len(), 2);
        assert_eq!(item.as_slice(), &[0xff, 2]);
        assert_eq!(&buf, &[0xff, 2, 3], "buf receives only the write");
    }

    /// An empty slice is null, no matter how it is created.
    #[test]
    fn wrap_empty() {
        assert!(SECItemBorrowed::wrap(&[]).as_slice().is_empty());
        assert!(SECItemBorrowed::make_empty().as_slice().is_empty());

        assert!(unsafe { (*SECItemBorrowed::make_empty().as_ptr()).data }.is_null());
        assert!(unsafe { (*SECItemBorrowed::wrap(&[]).as_ptr()).data }.is_null());
        assert!(unsafe { (*SECItemBorrowed::wrap_mut(&mut []).as_mut_ptr()).data }.is_null());
    }

    #[test]
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "pointer round trip should retain alignment"
    )]
    fn param_item() {
        let v = 0x1234_5678_u32;
        let item = ParamItem::wrap(&v);
        assert_eq!(
            usize::try_from(unsafe { (*item.as_ptr()).len }).unwrap(),
            size_of::<u32>()
        );
        assert_eq!(
            unsafe { (*item.as_ptr()).data }.cast_const().cast::<u32>(),
            &raw const v
        );
    }
}
