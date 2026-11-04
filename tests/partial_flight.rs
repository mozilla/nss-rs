// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tests for a client that accepts the server certificate before it has the
//! rest of the server's first flight.
//!
//! These protect records for `Client::handshake`, which NSS checks with real
//! keys, so they can't work with the null AEAD.

#![cfg(not(feature = "disable-encryption"))]

use nss_rs::{
    AuthenticationStatus, Client, Epoch, HandshakeState, Mode, Record, RecordProtection,
    RecordProtectionOps as _, Server, TLS_CT_APPLICATION_DATA, TLS_CT_HANDSHAKE,
    TLS_HS_CERTIFICATE, TLS_VERSION_1_3,
};
use test_fixture::{fixture_init, now};

fn tls_record(ct: u8, data: &[u8]) -> Vec<u8> {
    let mut record = vec![ct, 3, 3];
    let len = u16::try_from(data.len()).expect("record fits");
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(data);
    record
}

/// Protect `data` as a TLS 1.3 handshake record.
fn protected_record(aead: &RecordProtection, seq: u64, data: &[u8]) -> Vec<u8> {
    let mut inner = data.to_vec();
    inner.push(TLS_CT_HANDSHAKE);
    let mut ct = vec![0; inner.len() + aead.expansion()];
    let [len_hi, len_lo] = u16::try_from(ct.len()).expect("fits").to_be_bytes();
    let header = [TLS_CT_APPLICATION_DATA, 3, 3, len_hi, len_lo];
    aead.encrypt(seq, &header, &inner, &mut ct)
        .expect("encrypt");
    tls_record(TLS_CT_APPLICATION_DATA, &ct)
}

/// Where the `Certificate` message ends in a run of handshake messages.
fn certificate_end(messages: &[u8]) -> usize {
    let mut offset = 0;
    loop {
        let header: [u8; 4] = messages[offset..offset + 4].try_into().expect("header");
        let len = u32::from_be_bytes(header) & 0x00ff_ffff;
        offset += header.len() + usize::try_from(len).expect("fits");
        if header[0] == TLS_HS_CERTIFICATE {
            return offset;
        }
    }
}

/// Give a client a server flight that stops after the `Certificate` message.
/// Returns the client, the messages that were held back, and the protection
/// for sending them with the next record sequence number.
fn client_with_certificate_only() -> (Client, Vec<u8>, RecordProtection) {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    let hello = client.handshake(now(), &[]).expect("send CH");
    let hello = Record::new(Epoch::Initial, TLS_CT_HANDSHAKE, &hello[5..]);
    let records = server.handshake_raw(now(), Some(hello)).expect("read CH");
    let mut records = records.into_iter();
    let server_hello = records.next().expect("server hello");
    let flight = records.next().expect("rest of the flight");

    let cipher = server.preinfo().expect("preinfo").cipher_suite();
    let secret = server.write_secret(Epoch::Handshake).expect("secret");
    let aead = RecordProtection::new(
        TLS_VERSION_1_3,
        cipher.expect("cipher"),
        &secret,
        "",
        Mode::Encrypt,
    )
    .expect("protection");

    let (certificate, rest) = flight.data.split_at(certificate_end(&flight.data));
    let mut input = tls_record(TLS_CT_HANDSHAKE, &server_hello.data);
    input.extend_from_slice(&protected_record(&aead, 0, certificate));
    client.handshake(now(), &input).expect("read certificate");
    assert_eq!(*client.state(), HandshakeState::AuthenticationPending);

    (client, rest.to_vec(), aead)
}

/// A server that only has the public certificate stops after sending it. The
/// certificate checks out, but nothing has shown that the server has the key.
#[test]
fn certificate_without_proof_of_possession() {
    let (mut client, _, _) = client_with_certificate_only();

    client.authenticated(AuthenticationStatus::Ok);
    let output = client.handshake(now(), &[]).expect("still waiting");
    assert!(output.is_empty());
    assert_eq!(*client.state(), HandshakeState::InProgress);
    assert!(client.info().is_none());
}

/// The rest of the server flight can arrive with the call that accepts the
/// certificate.
#[test]
fn authenticated_before_server_finished() {
    let (mut client, rest, aead) = client_with_certificate_only();

    client.authenticated(AuthenticationStatus::Ok);
    let input = protected_record(&aead, 1, &rest);
    let output = client.handshake(now(), &input).expect("read finished");
    assert!(!output.is_empty());
    assert!(client.state().is_connected());
    assert_eq!(client.info().expect("info").version(), TLS_VERSION_1_3);
}
