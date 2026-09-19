//! Flashing the module through the controller, with no wire on it (F-038).
//!
//! Board A has no USB or programming header on the module; the controller
//! sits on its UART0 and holds its `EN`. So the firmware is asked, through
//! the mailbox, to reset the module and knock inside its download window
//! (KM43 L-190 to L-192), and then to hold the UART at the ROM's rate with
//! its bytes on the mailbox's two rings. This end serves those rings on a
//! local socket and runs `esptool` against it, which speaks the ROM's
//! protocol; when it is done the firmware is asked to reset the module
//! normally, and the next thing on the controller's log is the module's
//! `LinkUp`. Nothing here speaks the ROM's protocol itself: `esptool` is
//! the reference implementation, and a second one would be a second
//! opinion about a flash layout.

use o89_core::mailbox::DownloadEntry;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::link::Link;

/// `download_reason` as the registry numbers `bench`.
const REASON_BENCH: u8 = 1;
/// Bytes from the socket held for the module before the socket stops
/// being read.
const PENDING_MAX: usize = 64 * 1024;
/// A pass that moved nothing rests this long before the next.
const IDLE: Duration = Duration::from_millis(2);
/// How long `esptool` may take for the whole image: a 176 KB merged image
/// at 115 200 baud with the stub is well under a minute.
const ESPTOOL_DEADLINE: Duration = Duration::from_mins(10);
/// How long after `esptool` exits the bytes still on the rings are moved
/// before the bridge is closed.
const DRAIN: Duration = Duration::from_millis(500);

/// The image, merged with the bootloader and the partition table by
/// `espflash`, without the padding to the flash's end.
pub fn merge(elf: &Path, partitions: &Path, out: &Path) -> Result<()> {
    let status = Command::new("espflash")
        .args([
            "save-image",
            "--chip",
            "esp32c6",
            "--merge",
            "--skip-padding",
        ])
        .args(["--flash-size", "8mb", "--partition-table"])
        .arg(partitions)
        .arg(elf)
        .arg(out)
        .status()
        .context("running espflash save-image (install with `cargo install espflash --locked`)")?;
    if !status.success() {
        bail!("espflash save-image failed: {status}");
    }
    Ok(())
}

/// Flash `merged` onto the module through the controller. With `knock`
/// the firmware asks the module's own window; without it the module is
/// through its window, or with the strap held for a module that runs
/// nothing that answers.
pub fn flash(link: &mut Link, merged: &Path, entry: DownloadEntry) -> Result<()> {
    link.download(REASON_BENCH, entry)?;
    println!("module in download mode; the bridge is up");
    let outcome = run_esptool(link, merged);
    // The module goes back whatever esptool did: a half-written image is
    // the bootloader's to refuse, and a module left in the ROM is a
    // module nobody can reach.
    let back = link.normal();
    both(outcome, back)?;
    println!("module reset normally");
    Ok(())
}

/// An operation's outcome and the module's return to normal after it,
/// neither hidden by the other: a return that failed leaves the module in
/// its ROM, which is the one thing the operator must hear about.
fn both(outcome: Result<()>, back: Result<()>) -> Result<()> {
    match (outcome, back) {
        (Err(outcome), Err(back)) => Err(outcome.context(format!(
            "returning the module to normal also failed: {back:#}"
        ))),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// The module reset and its UART0 read for `seconds`, printed as text with
/// the bytes that are not text in hex, then the module reset normally, or,
/// with `leave_open`, the bridge left open as a host that died would leave
/// it: the next download reclaims it, or the firmware closes it once
/// nothing has moved on it for a minute.
pub fn listen(link: &mut Link, seconds: u64, entry: DownloadEntry, leave_open: bool) -> Result<()> {
    link.download(REASON_BENCH, entry)?;
    println!("the bridge is up; listening for {seconds} s");
    let until = Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .context("the deadline fits the clock")?;
    let mut buf = Vec::new();
    let mut total: usize = 0;
    let mut text = String::new();
    while Instant::now() < until {
        buf.clear();
        let outcome = link.bridge_read(&mut buf);
        match outcome {
            Ok(0) => std::thread::sleep(IDLE),
            Ok(count) => {
                total = total.saturating_add(count);
                for byte in &buf {
                    match byte {
                        b'\n' => {
                            println!("  {text}");
                            text.clear();
                        }
                        b'\r' => {}
                        0x20..=0x7e => text.push(char::from(*byte)),
                        other => {
                            use std::fmt::Write as _;
                            let _ = write!(text, "<{other:02x}>");
                        }
                    }
                }
            }
            Err(error) => return both(Err(error), link.normal()),
        }
    }
    if !text.is_empty() {
        println!("  {text}");
    }
    println!("{total} bytes in {seconds} s");
    if leave_open {
        println!("the bridge is left open, as a host that died would leave it");
        return Ok(());
    }
    link.normal()?;
    println!("module reset normally");
    Ok(())
}

fn run_esptool(link: &mut Link, merged: &Path) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("opening the relay socket")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let (mut esptool, from_esptool) = spawn_esptool(port, merged)?;
    let mut relay = Relay {
        listener,
        client: None,
        pending: Vec::new(),
        outbound: Vec::new(),
        buf: vec![0u8; 8192],
    };
    let started = Instant::now();
    let mut exited = None;
    // Bounded by esptool's deadline; every pass moves bytes or rests.
    loop {
        for line in from_esptool.try_iter() {
            // esptool asks the port for a USB identity a socket does not
            // have, on every open; the line says nothing about the flash.
            if !line.contains("Failed to get VID/PID") && !line.trim().is_empty() {
                println!("esptool: {line}");
            }
        }
        if exited.is_none()
            && let Some(status) = esptool.0.try_wait().context("waiting for esptool")?
        {
            exited = Some((status, Instant::now()));
        }
        let busy = relay.pass(link)?;
        if let Some((status, at)) = exited
            && relay.pending.is_empty()
            && at.elapsed() >= DRAIN
        {
            if !status.success() {
                bail!("esptool failed: {status}");
            }
            return Ok(());
        }
        if started.elapsed() > ESPTOOL_DEADLINE {
            // Killed and reaped as the guard drops.
            bail!("esptool did not finish within {ESPTOOL_DEADLINE:?}");
        }
        if !busy {
            thread::sleep(IDLE);
        }
    }
}

/// The esptool lines that may wait for the relay's next pass.
const ESPTOOL_LINES: usize = 256;

/// A running esptool, killed and reaped when this drops, on every way out
/// of the flash: a relay that failed, a deadline passed, or the flash done.
/// The module is given back only after, so nothing is still writing to it
/// while the controller resets it, and the readers of its pipes end at the
/// pipes' close.
struct Esptool(Child);

impl Drop for Esptool {
    fn drop(&mut self) {
        // Either may fail on a process that has already gone; both are
        // tried, and a drop has nobody to report to.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `esptool` against the socket, its output lines on a channel.
fn spawn_esptool(port: u16, merged: &Path) -> Result<(Esptool, mpsc::Receiver<String>)> {
    let esptool = std::env::var("O89_ESPTOOL").unwrap_or_else(|_| "uvx esptool".to_owned());
    let mut words = esptool.split_whitespace();
    let program = words.next().context("an esptool command")?;
    let mut child = Command::new(program)
        .args(words)
        .args(["--chip", "esp32c6", "--port"])
        .arg(format!("socket://127.0.0.1:{port}"))
        .args([
            "--baud", "115200", "--before", "no-reset", "--after", "no-reset",
        ])
        // The ROM's own loader: the stub would be one more image to move over
        // the bridge, and the 176 KB take under a minute without it.
        .args(["--no-stub", "write-flash", "0x0"])
        .arg(merged)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {esptool}"))?;
    // Bounded: a reader thread that gets ahead of the relay blocks on the
    // pipe, which holds esptool back, rather than growing the queue.
    let (lines, from_esptool) = mpsc::sync_channel::<String>(ESPTOOL_LINES);
    for pipe in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let lines = lines.clone();
        thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
    }
    Ok((Esptool(child), from_esptool))
}

/// The socket esptool talks to and the bytes in flight either way.
struct Relay {
    listener: TcpListener,
    client: Option<TcpStream>,
    /// From esptool, waiting for room on the ring.
    pending: Vec<u8>,
    /// From the module, waiting for esptool to take it.
    outbound: Vec<u8>,
    buf: Vec<u8>,
}

impl Relay {
    /// One pass: accept, move what the module said to the socket, take
    /// what esptool sent, and put what fits on the ring. Whether anything
    /// moved.
    fn pass(&mut self, link: &mut Link) -> Result<bool> {
        let mut busy = false;
        if self.client.is_none() {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    stream.set_nodelay(true)?;
                    self.client = Some(stream);
                    busy = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e).context("accepting esptool"),
            }
        }
        if link.bridge_read(&mut self.outbound)? > 0 {
            busy = true;
        }
        if !self.outbound.is_empty()
            && let Some(stream) = self.client.as_mut()
        {
            // Non-blocking: what the socket takes now goes, the rest waits
            // for the next pass; a socket that errors is a client gone.
            match stream.write(&self.outbound) {
                Ok(0) => {}
                Ok(n) => {
                    self.outbound.drain(..n.min(self.outbound.len()));
                    busy = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => self.client = None,
            }
        }
        if let Some(stream) = self.client.as_mut() {
            let room = PENDING_MAX
                .saturating_sub(self.pending.len())
                .min(self.buf.len());
            if room > 0 {
                match stream.read(self.buf.get_mut(..room).unwrap_or(&mut [])) {
                    Ok(0) => self.client = None,
                    Ok(n) => {
                        self.pending
                            .extend_from_slice(self.buf.get(..n).unwrap_or(&[]));
                        busy = true;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => self.client = None,
                }
            }
        }
        if !self.pending.is_empty() {
            let written = link.bridge_write(&self.pending)?;
            if written > 0 {
                self.pending.drain(..written.min(self.pending.len()));
                busy = true;
            }
        }
        Ok(busy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a process with this id is still there, a zombie included.
    fn exists(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .expect("kill runs")
            .success()
    }

    #[test]
    fn an_esptool_left_running_is_killed_and_reaped_when_its_guard_drops() {
        let child = Command::new("sleep").arg("30").spawn().expect("sleep runs");
        let pid = child.id();
        assert!(exists(pid));
        drop(Esptool(child));
        assert!(!exists(pid), "still there after the guard dropped");
    }

    #[test]
    fn an_esptool_that_already_exited_is_reaped_without_complaint() {
        let child = Command::new("true").spawn().expect("true runs");
        let pid = child.id();
        // Exited, not yet waited on: a zombie until someone reaps it.
        thread::sleep(Duration::from_millis(200));
        assert!(exists(pid), "a zombie until reaped");
        drop(Esptool(child));
        assert!(!exists(pid), "reaped as the guard dropped");
    }
}
