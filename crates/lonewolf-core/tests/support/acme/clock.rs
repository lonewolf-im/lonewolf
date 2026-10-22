// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lonewolf_acme::test_support::{ClockMode, ClockSnapshot, Parked, TestClock};

use super::{TIMEOUT, TestResult};

const INIT: u8 = 1;
const FREEZE: u8 = 2;
const ADVANCE: u8 = 3;
const PARKED: u8 = 4;
const RESUME: u8 = 5;
const FRAME_SIZE: usize = 48;

struct Frame([u8; FRAME_SIZE]);

impl Frame {
    fn new(operation: u8) -> Self {
        let mut frame = Self([0; FRAME_SIZE]);
        frame.0[0] = operation;
        frame
    }

    fn generation(&self) -> u64 {
        u64::from_be_bytes(std::array::from_fn(|index| self.0[8 + index]))
    }

    fn set_generation(&mut self, generation: u64) {
        self.0[8..16].copy_from_slice(&generation.to_be_bytes());
    }

    fn time(&self, offset: usize) -> io::Result<SystemTime> {
        let seconds = u64::from_be_bytes(std::array::from_fn(|index| self.0[offset + index]));
        let nanos = u32::from_be_bytes(std::array::from_fn(|index| self.0[offset + 8 + index]));
        if nanos >= 1_000_000_000 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    fn set_time(&mut self, offset: usize, now: SystemTime) -> io::Result<()> {
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        self.0[offset..offset + 8].copy_from_slice(&now.as_secs().to_be_bytes());
        self.0[offset + 8..offset + 12].copy_from_slice(&now.subsec_nanos().to_be_bytes());
        Ok(())
    }
}

pub struct ClockControl {
    socket: UnixStream,
}

impl ClockControl {
    fn exchange(&mut self, request: Frame) -> io::Result<Frame> {
        self.socket.write_all(&request.0)?;
        let mut response = Frame::new(0);
        self.socket.read_exact(&mut response.0)?;
        if response.0[0] != request.0[0] | 0x80 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid clock response",
            ));
        }
        if response.0[1] != 0 {
            return Err(io::Error::new(
                match response.0[1] {
                    1 => io::ErrorKind::InvalidInput,
                    2 => io::ErrorKind::TimedOut,
                    3 => io::ErrorKind::Interrupted,
                    _ => io::ErrorKind::Other,
                },
                "clock command failed",
            ));
        }
        Ok(response)
    }

    pub fn freeze(&mut self) -> io::Result<ClockSnapshot> {
        let frame = self.exchange(Frame::new(FREEZE))?;
        Ok(ClockSnapshot {
            generation: frame.generation(),
            now: frame.time(16)?,
        })
    }

    pub fn advance_to(&mut self, now: SystemTime) -> io::Result<u64> {
        let mut frame = Frame::new(ADVANCE);
        frame.set_time(16, now)?;
        Ok(self.exchange(frame)?.generation())
    }

    pub fn resume(&mut self) -> io::Result<u64> {
        Ok(self.exchange(Frame::new(RESUME))?.generation())
    }

    pub fn wait_parked(&mut self, generation: u64) -> io::Result<Parked> {
        let mut request = Frame::new(PARKED);
        request.set_generation(generation);
        let frame = self.exchange(request)?;
        let parked = Parked {
            generation: frame.generation(),
            now: frame.time(16)?,
            deadline: frame.time(32)?,
        };
        if parked.generation != generation || parked.now >= parked.deadline {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid parked clock response",
            ));
        }
        Ok(parked)
    }
}

impl Drop for ClockControl {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

pub fn spawn(
    directory: &Path,
    now: SystemTime,
    mode: ClockMode,
) -> io::Result<(Child, ClockControl)> {
    let (parent, child) = UnixStream::pair()?;
    parent.set_read_timeout(Some(TIMEOUT))?;
    parent.set_write_timeout(Some(TIMEOUT))?;
    let mut process = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "support::clock::server_process",
            "--ignored",
            "--nocapture",
        ])
        .env("LONEWOLF_ACME_CLOCK_CHILD", "1")
        .env("LONEWOLF_WORKER_COUNT", "2")
        .current_dir(directory)
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null())
        .stderr(fs::File::create(directory.join("server.log"))?)
        .spawn()?;
    let mut control = ClockControl { socket: parent };
    let initialized = (|| {
        let mut frame = Frame::new(INIT);
        frame.0[1] = u8::from(mode == ClockMode::Frozen);
        frame.set_time(16, now)?;
        control.exchange(frame)?;
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = initialized {
        drop(control);
        let _ = process.kill();
        let _ = process.wait();
        return Err(error);
    }
    Ok((process, control))
}

fn serve(socket: &mut UnixStream, clock: &TestClock) -> io::Result<()> {
    loop {
        let mut request = Frame::new(0);
        match socket.read_exact(&mut request.0) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let mut response = Frame::new(request.0[0] | 0x80);
        let result = (|| {
            match request.0[0] {
                FREEZE => {
                    let snapshot = clock.freeze()?;
                    response.set_generation(snapshot.generation);
                    response.set_time(16, snapshot.now)?;
                }
                ADVANCE => response.set_generation(clock.advance_to(request.time(16)?)?),
                RESUME => response.set_generation(clock.resume()?),
                PARKED => {
                    let parked =
                        clock.wait_parked(request.generation(), Instant::now() + TIMEOUT)?;
                    response.set_generation(parked.generation);
                    response.set_time(16, parked.now)?;
                    response.set_time(32, parked.deadline)?;
                }
                _ => return Err(io::ErrorKind::InvalidInput.into()),
            }
            Ok::<_, io::Error>(())
        })();
        if let Err(error) = &result {
            response.0[1] = match error.kind() {
                io::ErrorKind::InvalidInput => 1,
                io::ErrorKind::TimedOut => 2,
                io::ErrorKind::Interrupted => 3,
                _ => 4,
            };
        }
        socket.write_all(&response.0)?;
        result?;
    }
}

#[test]
#[ignore = "subprocess entry point for the ACME clock fixture"]
fn server_process() -> TestResult {
    if std::env::var_os("LONEWOLF_ACME_CLOCK_CHILD").is_none() {
        return Ok(());
    }
    let mut socket = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let mut init = Frame::new(0);
    socket.read_exact(&mut init.0)?;
    if init.0[0] != INIT || init.0[1] > 1 {
        return Err("invalid clock initialization".into());
    }
    let clock = TestClock::new(
        init.time(16)?,
        if init.0[1] == 1 {
            ClockMode::Frozen
        } else {
            ClockMode::Running
        },
    )?;
    let mut response = Frame::new(INIT | 0x80);
    response.set_time(16, init.time(16)?)?;
    socket.write_all(&response.0)?;
    let mut controller_socket = socket.try_clone()?;
    let controller_clock = clock.clone();
    let controller = thread::Builder::new()
        .name("acme-test-clock".into())
        .spawn(move || {
            let result = serve(&mut controller_socket, &controller_clock);
            controller_clock.cancel_waits();
            result
        })?;
    let result = lonewolf_core::run_with_acme_clock(
        None,
        lonewolf_core::BuildInfo {
            version: "integration-test",
            branch: "test",
            commit: "test",
        },
        clock.clone(),
    );
    clock.cancel_waits();
    let shutdown = socket.shutdown(std::net::Shutdown::Both);
    let controller_result = controller.join().map_err(|_| "clock controller panicked")?;
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
    shutdown?;
    controller_result?;
    Ok(())
}
