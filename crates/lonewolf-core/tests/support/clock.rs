// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use lonewolf_core::test_support::ManualClock;

const ADVANCE: u8 = 1;
const WAIT_TIMERS: u8 = 2;
const SET_WALL: u8 = 3;
const WAIT_HEADERS: u8 = 4;

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
}

pub fn with_clock<T>(start: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            ENABLED.set(self.0);
        }
    }
    let _reset = Reset(ENABLED.replace(true));
    start()
}

pub fn prepare(directory: &Path) -> io::Result<bool> {
    let marker = directory.join("manual-clock");
    if ENABLED.get() {
        fs::write(&marker, [])?;
    }
    marker.try_exists()
}

pub fn serve() -> io::Result<()> {
    if !Path::new("manual-clock").try_exists()? {
        return Ok(());
    }
    let path = Path::new("clock.sock");
    if path.try_exists()? {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    let clock = ManualClock::install();
    std::thread::Builder::new()
        .name("fixture-clock".into())
        .spawn(move || {
            for connection in listener.incoming() {
                let Ok(mut socket) = connection else { break };
                let mut command = [0; 13];
                if socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .is_err()
                    || socket.read_exact(&mut command).is_err()
                {
                    continue;
                }
                let millis = u64::from_be_bytes(command[1..9].try_into().unwrap());
                let duration = Duration::from_millis(millis);
                let count = u32::from_be_bytes(command[9..].try_into().unwrap());
                let result = match command[0] {
                    ADVANCE => {
                        clock.advance(duration);
                        Ok(())
                    }
                    WAIT_TIMERS => clock.wait_for_timers(duration, count, Duration::from_secs(10)),
                    SET_WALL => {
                        clock.set_wall_before_handshake(std::time::UNIX_EPOCH + duration);
                        Ok(())
                    }
                    WAIT_HEADERS => {
                        clock.wait_for_protected_headers(count, Duration::from_secs(10))
                    }
                    _ => Err(io::ErrorKind::InvalidInput.into()),
                };
                let _ = match result {
                    Ok(()) => socket.write_all(&[0]),
                    Err(error) => socket.write_all(format!("!{error}").as_bytes()),
                };
            }
        })?;
    Ok(())
}

pub struct Clock(PathBuf);

impl Clock {
    pub fn at(directory: &Path) -> Self {
        Self(directory.join("clock.sock"))
    }

    fn command(&self, operation: u8, millis: u64, count: u32) -> io::Result<()> {
        let mut socket = UnixStream::connect(&self.0)?;
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut command = [0; 13];
        command[0] = operation;
        command[1..9].copy_from_slice(&millis.to_be_bytes());
        command[9..].copy_from_slice(&count.to_be_bytes());
        socket.write_all(&command)?;
        let mut reply = Vec::new();
        socket.read_to_end(&mut reply)?;
        if reply == [0] {
            Ok(())
        } else {
            Err(io::Error::other(String::from_utf8_lossy(&reply)))
        }
    }

    pub fn set_wall_before_handshake(&self, time: std::time::SystemTime) -> io::Result<()> {
        let millis = time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .try_into()
            .map_err(io::Error::other)?;
        self.command(SET_WALL, millis, 0)
    }

    pub fn wait_protected_headers(&self, count: u32) -> io::Result<()> {
        self.command(WAIT_HEADERS, 0, count)
    }

    pub fn advance_ms(&self, millis: u64) -> io::Result<()> {
        self.command(ADVANCE, millis, 0)
    }

    pub fn wait_timers(&self, remaining_ms: u64, count: u32) -> io::Result<()> {
        self.command(WAIT_TIMERS, remaining_ms, count)
    }

    pub fn expire_ms(&self, remaining_ms: u64) -> io::Result<()> {
        self.wait_timers(remaining_ms, 1)?;
        self.advance_ms(remaining_ms)
    }
}
