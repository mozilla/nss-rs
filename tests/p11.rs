// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use nss_rs::{
    PrivateKey, PublicKey,
    p11::{SECKEYPrivateKeyStr, SECKEYPublicKeyStr},
};
use std::{mem::transmute, ptr::null_mut};
use test_fixture::fixture_init;

/// Check `key_type` using null pointers.
#[test]
fn key_type_null() {
    fixture_init();

    let pubkey_ptr = null_mut::<SECKEYPublicKeyStr>();
    let pubkey: PublicKey = unsafe { transmute(pubkey_ptr) };
    assert!(pubkey.key_type().is_none());

    let privkey_ptr = null_mut::<SECKEYPrivateKeyStr>();
    let privkey: PrivateKey = unsafe { transmute(privkey_ptr) };
    assert!(privkey.key_type().is_none());
}
