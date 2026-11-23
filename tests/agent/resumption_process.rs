// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::Duration,
};

use nss_rs::{AuthenticationStatus, Client, HandshakeState, ResumptionToken, SecretAgent, Server};
use test_fixture::{fixture_init, now};

const CHILD_ADDR: &str = "NSS_RS_TEST_RESUME_CHILD_ADDR";

/// Kills the child if the parent panics before it exits.
struct ClientProcess(Child);

impl Drop for ClientProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            _ = self.0.kill();
            _ = self.0.wait();
        }
    }
}

/// Resumes with `token` from a client in a fresh process, against a server in this one,
/// so that the server keeps the keys that protect its ticket. Returns whether the server resumed.
pub fn resume_in_fresh_process(token: &ResumptionToken) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").expect("should bind");
    let mut child = ClientProcess(
        Command::new(std::env::current_exe().expect("should find test binary"))
            .args(["--exact", "agent::resumption_process::resume_in_child"])
            .env(
                CHILD_ADDR,
                listener.local_addr().expect("has address").to_string(),
            )
            .spawn()
            .expect("should start child"),
    );
    let (mut stream, _) = listener.accept().expect("child should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("should set timeout");

    write_frame(&mut stream, token.as_ref());
    let mut server = Server::new(&["key"]).expect("should create server");
    let hello = read_frame(&mut stream);
    let resumed = handshake_over(&mut server, &mut stream, hello);
    assert!(
        child.0.wait().expect("child runs").success(),
        "child failed"
    );
    resumed
}

/// The client half of `resume_in_fresh_process`. Does nothing unless started by it.
#[test]
fn resume_in_child() {
    let Ok(addr) = std::env::var(CHILD_ADDR) else {
        return;
    };
    fixture_init();
    let mut stream = TcpStream::connect(addr).expect("should connect to parent");
    let token = read_frame(&mut stream);
    let mut client = Client::new("server.example", true).expect("should create client");
    // A wrapped token may be refused here; the server then reports a full handshake.
    _ = client.enable_resumption(&token);
    handshake_over(&mut client, &mut stream, Vec::new());
}

/// Runs one side of a handshake over `stream`, starting from `input`.
/// Returns whether the handshake resumed.
fn handshake_over(agent: &mut SecretAgent, stream: &mut TcpStream, mut input: Vec<u8>) -> bool {
    loop {
        let out = agent.handshake(now(), &input).expect("handshake");
        let out = if *agent.state() == HandshakeState::AuthenticationPending {
            agent.authenticated(AuthenticationStatus::Ok);
            agent.handshake(now(), &[]).expect("handshake")
        } else {
            out
        };
        if !out.is_empty() {
            write_frame(stream, &out);
        }
        if agent.state().is_final() {
            return agent.info().expect("handshake completed").resumed();
        }
        input = read_frame(stream);
    }
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) {
    let len = u32::try_from(data.len()).expect("frame length fits");
    stream.write_all(&len.to_be_bytes()).expect("should write");
    stream.write_all(data).expect("should write");
}

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0; 4];
    stream.read_exact(&mut len).expect("should read");
    let mut data = vec![0; usize::try_from(u32::from_be_bytes(len)).expect("frame length fits")];
    stream.read_exact(&mut data).expect("should read");
    data
}
