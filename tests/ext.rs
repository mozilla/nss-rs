// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, rc::Rc};

use handshake::forward_records;
use nss_rs::{
    AuthenticationStatus, Client, Error, HandshakeState, Server,
    constants::{
        HandshakeMessage, TLS_ALERT_DECODE_ERROR, TLS_ALERT_ECH_REQUIRED,
        TLS_ALERT_ILLEGAL_PARAMETER, TLS_ALERT_UNSUPPORTED_EXTENSION, TLS_HS_CLIENT_HELLO,
        TLS_HS_ENCRYPTED_EXTENSIONS,
    },
    ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult},
    generate_ech_keys,
};
use test_fixture::{damage_ech_config, fixture_init, now};

mod handshake;
use crate::handshake::connect;

const ECH_CONFIG_ID: u8 = 7;
const ECH_PUBLIC_NAME: &str = "public.example";

struct NoopExtensionHandler;
impl ExtensionHandler for NoopExtensionHandler {}

// This test just handshakes.  It doesn't really do anything about capturing the
#[test]
fn noop_extension_handler() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .extension_handler(0xffff, Rc::new(RefCell::new(NoopExtensionHandler)))
        .expect("installed");
    server
        .extension_handler(0xffff, Rc::new(RefCell::new(NoopExtensionHandler)))
        .expect("installed");

    connect(&mut client, &mut server);
}

#[derive(Debug, Default)]
struct SimpleExtensionHandler {
    written: bool,
    handled: bool,
}

impl SimpleExtensionHandler {
    pub const fn negotiated(&self) -> bool {
        self.written && self.handled
    }
}

impl ExtensionHandler for SimpleExtensionHandler {
    fn write(
        &mut self,
        msg: HandshakeMessage,
        _ch_outer: bool,
        d: &mut [u8],
    ) -> ExtensionWriterResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                self.written = true;
                d[0] = 77;
                ExtensionWriterResult::Write(1)
            }
            _ => ExtensionWriterResult::Skip,
        }
    }

    fn handle(&mut self, msg: HandshakeMessage, d: &[u8]) -> ExtensionHandlerResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                self.handled = true;
                if d.len() != 1 {
                    ExtensionHandlerResult::Alert(TLS_ALERT_DECODE_ERROR)
                } else if d[0] == 77 {
                    ExtensionHandlerResult::Ok
                } else {
                    ExtensionHandlerResult::Alert(TLS_ALERT_ILLEGAL_PARAMETER)
                }
            }
            _ => ExtensionHandlerResult::Alert(TLS_ALERT_UNSUPPORTED_EXTENSION),
        }
    }
}

#[test]
fn simple_extension() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    let client_handler = Rc::new(RefCell::new(SimpleExtensionHandler::default()));
    let ch = Rc::clone(&client_handler);
    client
        .extension_handler(0xffff, ch)
        .expect("client handler installed");
    let server_handler = Rc::new(RefCell::new(SimpleExtensionHandler::default()));
    let sh = Rc::clone(&server_handler);
    server
        .extension_handler(0xffff, sh)
        .expect("server handler installed");

    connect(&mut client, &mut server);

    assert!(client_handler.borrow().negotiated());
    assert!(server_handler.borrow().negotiated());
}

#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "These are all very different things, so it is OK"
)]
struct EchExtensionHandler {
    expect_outer: bool,
    written_inner: bool,
    written_outer: bool,
    handled: bool,
}

impl EchExtensionHandler {
    const INNER: &[u8] = b"inner is longer";
    const OUTER: &[u8] = b"outer";

    pub const fn negotiated(&self, outer_written: bool) -> bool {
        self.written_inner && self.written_outer == outer_written && self.handled
    }
}

impl ExtensionHandler for EchExtensionHandler {
    fn write(
        &mut self,
        msg: HandshakeMessage,
        ch_outer: bool,
        d: &mut [u8],
    ) -> ExtensionWriterResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                let v = if ch_outer {
                    self.written_outer = true;
                    Self::OUTER
                } else {
                    self.written_inner = true;
                    Self::INNER
                };
                d[..v.len()].copy_from_slice(v);
                ExtensionWriterResult::Write(v.len())
            }
            _ => ExtensionWriterResult::Skip,
        }
    }

    fn handle(&mut self, msg: HandshakeMessage, d: &[u8]) -> ExtensionHandlerResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                self.handled = true;
                let expected = if self.expect_outer {
                    Self::OUTER
                } else {
                    Self::INNER
                };
                if d == expected {
                    ExtensionHandlerResult::Ok
                } else {
                    ExtensionHandlerResult::Alert(TLS_ALERT_ILLEGAL_PARAMETER)
                }
            }
            _ => ExtensionHandlerResult::Alert(TLS_ALERT_UNSUPPORTED_EXTENSION),
        }
    }
}

#[test]
fn ech_extension() {
    fixture_init();
    let (sk, pk) = generate_ech_keys().expect("ECH keygen works");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .enable_ech(ECH_CONFIG_ID, ECH_PUBLIC_NAME, &sk, &pk)
        .expect("ECH server setup works");

    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .enable_ech(server.ech_config())
        .expect("ECH client setup works");

    let client_handler = Rc::new(RefCell::new(EchExtensionHandler::default()));
    let ch = Rc::clone(&client_handler);
    client
        .extension_handler(0xffff, ch)
        .expect("client handler installed");
    let server_handler = Rc::new(RefCell::new(EchExtensionHandler::default()));
    let sh = Rc::clone(&server_handler);
    server
        .extension_handler(0xffff, sh)
        .expect("server handler installed");

    connect(&mut client, &mut server);

    assert!(client_handler.borrow().negotiated(true));
    assert!(server_handler.borrow().negotiated(false));

    assert!(client.info().unwrap().ech_accepted());
    assert!(server.info().unwrap().ech_accepted());
    assert!(client.preinfo().unwrap().ech_accepted().unwrap());
    assert!(server.preinfo().unwrap().ech_accepted().unwrap());
}

#[test]
fn ech_retry() {
    fixture_init();
    let (sk, pk) = generate_ech_keys().expect("ECH keygen works");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .enable_ech(ECH_CONFIG_ID, ECH_PUBLIC_NAME, &sk, &pk)
        .expect("ECH server setup works");

    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .enable_ech(damage_ech_config(server.ech_config()))
        .expect("ECH client setup works");

    let client_handler = Rc::new(RefCell::new(EchExtensionHandler::default()));
    let ch = Rc::clone(&client_handler);
    client
        .extension_handler(0xffff, ch)
        .expect("client handler installed");
    let server_handler = Rc::new(RefCell::new(EchExtensionHandler {
        expect_outer: true,
        ..EchExtensionHandler::default()
    }));
    let sh = Rc::clone(&server_handler);
    server
        .extension_handler(0xffff, sh)
        .expect("server handler installed");

    let client_hello = client.handshake_raw(now(), None).expect("send ClientHello");
    let server_hello =
        forward_records(now(), &mut server, client_hello).expect("ClientHello > ServerHello");

    let client_finished =
        forward_records(now(), &mut client, server_hello).expect("ServerHello > client");
    assert!(client_finished.is_empty());
    let HandshakeState::EchFallbackAuthenticationPending(server_name) = client.state() else {
        panic!("no ECH retry configuration provided");
    };
    assert_eq!(server_name, ECH_PUBLIC_NAME);
    client.authenticated(AuthenticationStatus::Ok);
    let client_error = client
        .handshake_raw(now(), None)
        .expect_err("now the client sends a Finished and errors out");
    let Error::EchRetry(retry_cfg) = client_error else {
        panic!("no ECH retry configuration provided");
    };
    assert_eq!(server.ech_config(), retry_cfg);
    assert_eq!(client.alert(), Some(TLS_ALERT_ECH_REQUIRED));

    // Note that we don't have a means of signaling the error to the server in this code.
}

/// Writes `PAYLOAD` and reports the length that `report` computes from the buffer size.
struct LengthExtensionHandler {
    report: fn(usize) -> usize,
    zeroed: bool,
}

impl LengthExtensionHandler {
    const PAYLOAD: &[u8] = b"abcdefghij";
}

impl ExtensionHandler for LengthExtensionHandler {
    fn write(
        &mut self,
        msg: HandshakeMessage,
        _ch_outer: bool,
        d: &mut [u8],
    ) -> ExtensionWriterResult {
        if msg != TLS_HS_CLIENT_HELLO {
            return ExtensionWriterResult::Skip;
        }
        self.zeroed = d.iter().all(|&b| b == 0);
        d[..Self::PAYLOAD.len()].copy_from_slice(Self::PAYLOAD);
        ExtensionWriterResult::Write((self.report)(d.len()))
    }
}

/// Fills the buffer and skips, so NSS hands the same dirty bytes to the next writer.
struct DirtyingExtensionHandler;

impl ExtensionHandler for DirtyingExtensionHandler {
    fn write(
        &mut self,
        _msg: HandshakeMessage,
        _ch_outer: bool,
        d: &mut [u8],
    ) -> ExtensionWriterResult {
        d.fill(0xaa);
        ExtensionWriterResult::Skip
    }
}

fn client_with_length_handler(
    report: fn(usize) -> usize,
) -> (Client, Rc<RefCell<LengthExtensionHandler>>) {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    // Installed first, so NSS hands its dirty buffer to the next writer.
    client
        .extension_handler(0xfffe, Rc::new(RefCell::new(DirtyingExtensionHandler)))
        .expect("dirtying handler installed");
    let handler = Rc::new(RefCell::new(LengthExtensionHandler {
        report,
        zeroed: false,
    }));
    client
        .extension_handler(0xffff, Rc::clone(&handler) as _)
        .expect("client handler installed");
    (client, handler)
}

/// Bytes the handler reports but doesn't write go out as zeros, never as
/// stale contents of NSS's buffer.
#[test]
fn extension_overreported_length_sends_zeros() {
    const PAD: usize = 4;
    let (mut client, handler) =
        client_with_length_handler(|_| LengthExtensionHandler::PAYLOAD.len() + PAD);

    let records = client.handshake_raw(now(), None).expect("send ClientHello");
    assert!(handler.borrow().zeroed);

    let ch = &records.into_iter().next().expect("one record").data;
    let payload = LengthExtensionHandler::PAYLOAD;
    let len = u16::try_from(payload.len() + PAD).expect("length fits");
    let ext: Vec<u8> = [0xff, 0xff]
        .into_iter()
        .chain(len.to_be_bytes())
        .chain(payload.iter().copied())
        .chain([0; PAD])
        .collect();
    assert!(ch.windows(ext.len()).any(|w| w == ext));
}

fn assert_extension_length_rejected(report: fn(usize) -> usize) {
    let (mut client, _) = client_with_length_handler(report);

    let res = client.handshake_raw(now(), None);
    let Err(Error::Nss { name, .. }) = res else {
        panic!("expected SEC_ERROR_APPLICATION_CALLBACK_ERROR, got {res:?}");
    };
    assert_eq!(name, "SEC_ERROR_APPLICATION_CALLBACK_ERROR");
}

#[test]
fn extension_length_past_buffer_fails_handshake() {
    assert_extension_length_rejected(|max_len| max_len + 1);
}

#[test]
fn extension_length_overflow_fails_handshake() {
    assert_extension_length_rejected(|_| usize::MAX);
}
