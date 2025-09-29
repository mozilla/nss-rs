// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is test code.")]

use std::{
    cell::OnceCell,
    time::{Duration, Instant},
};

use nss_rs::{init_db, AntiReplay};

/// The path for the database used in tests.
///
/// Initialized via the `NSS_DB_PATH` environment variable. If that is not set,
/// it defaults to the `db` directory in the current crate. If the environment
/// variable is set to `$ARGV0`, it will be initialized to the directory of the
/// current executable.
pub const NSS_DB_PATH: &str = if let Some(dir) = option_env!("NSS_DB_PATH") {
    dir
} else {
    concat!(env!("CARGO_MANIFEST_DIR"), "/db")
};

/// Initialize the test fixture.  Only call this if you aren't also calling a
/// fixture function that depends on setup.  Other functions in the fixture
/// that depend on this setup call the function for you.
///
/// # Panics
///
/// When the NSS initialization fails.
#[allow(dead_code)]
pub fn fixture_init() {
    if NSS_DB_PATH == "$ARGV0" {
        let mut current_exe = std::env::current_exe().unwrap();
        current_exe.pop();
        let nss_db_path = current_exe.to_str().unwrap();
        init_db(nss_db_path).unwrap();
    } else {
        init_db(NSS_DB_PATH).unwrap();
    }
}

// This needs to be > 2ms to avoid it being rounded to zero.
// NSS operates in milliseconds and halves any value it is provided.
// But make it a second, so that tests with reasonable RTTs don't fail.
pub const ANTI_REPLAY_WINDOW: Duration = Duration::from_millis(1000);

/// A baseline time for all tests.  This needs to be earlier than what `now()` produces
/// because of the need to have a span of time elapse for anti-replay purposes.
fn earlier() -> Instant {
    // Note: It is only OK to have a different base time for each thread because our tests are
    // single-threaded.
    thread_local!(static EARLIER: OnceCell<Instant> = const { OnceCell::new() });
    fixture_init();
    EARLIER.with(|b| *b.get_or_init(Instant::now))
}

/// The current time for the test.  Which is in the future,
/// because 0-RTT tests need to run at least `ANTI_REPLAY_WINDOW` in the past.
///
/// # Panics
///
/// When the setup fails.
#[must_use]
pub fn now() -> Instant {
    earlier().checked_add(ANTI_REPLAY_WINDOW).unwrap()
}

/// Create a default anti-replay context.
///
/// # Panics
///
/// When the setup fails.
#[must_use]
pub fn anti_replay() -> AntiReplay {
    AntiReplay::new(earlier(), ANTI_REPLAY_WINDOW, 1, 3).expect("setup anti-replay")
}

/// Take a valid ECH config (as bytes) and produce a damaged version of the same.
///
/// This will appear valid, but it will contain a different ECH config ID.
/// If given to a client, this should trigger an ECH retry.
/// This only damages the config ID, which works as we only support one on our server.
///
/// # Panics
/// When the provided `config` has the wrong version.
#[must_use]
pub fn damage_ech_config(config: &[u8]) -> Vec<u8> {
    let mut cfg = config.to_owned();
    // Ensure that the version is correct.
    assert_eq!(cfg[2], 0xfe);
    assert_eq!(cfg[3], 0x0d);
    // Change the config_id so that the server doesn't recognize it.
    cfg[6] ^= 0x94;
    cfg
}
