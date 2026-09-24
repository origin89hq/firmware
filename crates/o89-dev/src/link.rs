//! The mailbox from the host's side: a probe, a session, and the sequence
//! pair `o89_core::mailbox` describes.
//!
//! A request is the arguments and the data, then the sequence last; the
//! answer is the firmware landing the same sequence as its response,
//! polled here until a deadline. The firmware's recorder looks every
//! hundred milliseconds, an erase takes a few hundred more and the head
//! search after one a few hundred again, so the deadline is seconds.
//!
//! The [`Fram`] seam is implemented over the link so that `o89-core`'s own
//! records and tables write themselves through it, which is how an epoch
//! written from the bench is byte for byte one the firmware would write.

use std::fmt::Write as _;
use std::future::{Future, ready};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use o89_core::mailbox::{
    DATA_BYTES, DownloadEntry, DropAnswer, MAGIC, MAILBOX_ADDRESS, Op, RING_BYTES, Ring, RingPage,
    Status, VERSION, offset,
};
use o89_core::{Address, Dropped, FRAM_BYTES, Fram, Refused};
use probe_rs::probe::list::Lister;
use probe_rs::{MemoryInterface, Permissions, Session};

/// The controller, as probe-rs names it.
const TARGET: &str = "STM32G0B1RETx";
/// How long the firmware has to answer one request.
const DEADLINE: Duration = Duration::from_secs(10);
/// How often the answer is looked for.
const POLL: Duration = Duration::from_millis(5);

/// A probe attached to a controller whose firmware serves the mailbox.
pub struct Link {
    session: Session,
    /// The sequence of the last request, which the answer carries.
    seq: u32,
    /// The lease on the bridge, as last written, and when.
    lease: u32,
    renewed: Option<Instant>,
}

/// How often the lease on the bridge is renewed while it is read; the
/// firmware lets it lapse after a minute unrenewed.
const LEASE_RENEW: Duration = Duration::from_secs(1);

/// What the firmware answered.
struct Answer {
    status: Status,
    data: Vec<u8>,
}

impl Answer {
    /// The answer's data, if the status was good.
    fn ok(self, what: &str) -> Result<Vec<u8>> {
        match self.status {
            Status::Ok => Ok(self.data),
            Status::UnknownOp => bail!("{what}: the firmware does not know this operation"),
            Status::OutOfRange => bail!("{what}: out of range for the part or the mailbox"),
            Status::SupplyFalling => bail!("{what}: refused, the supply is falling"),
            Status::Bus => bail!("{what}: the bus refused"),
            Status::NoNor => bail!("{what}: the ring did not open; the NOR is not there"),
            Status::NoModuleAnswer => {
                bail!("{what}: the module did not answer EnterDownload inside its window")
            }
            Status::LinkBusy => bail!("{what}: the link task did not take the request"),
            Status::NoStore => bail!(
                "{what}: the controller booted without its store, so its link is down (F-039); the FRAM comes first"
            ),
            Status::BridgeRefused => bail!(
                "{what}: the controller's USART1 refused the ROM's configuration; the module was reset normally"
            ),
            Status::ModuleRefused => bail!(
                "{what}: the module answered refused_outside_window: it runs an image whose window had closed when the knock arrived"
            ),
            Status::InsideTheRing => bail!(
                "{what}: the block is the ring's; only the oldest goes, with `drop-ring` (#78)"
            ),
        }
    }
}

/// The address of a field.
fn field(at: u32) -> u64 {
    u64::from(MAILBOX_ADDRESS).saturating_add(u64::from(at))
}

impl Link {
    /// Every probe plugged in, one line each.
    pub fn probes() -> Vec<String> {
        Lister::new()
            .list_all()
            .iter()
            .map(|probe| {
                let mut line = probe.identifier.clone();
                if let Some(serial) = &probe.serial_number {
                    let _ = write!(line, " serial {serial}");
                }
                line
            })
            .collect()
    }

    /// Open the one probe, or the one with `serial`, attach it to the
    /// controller and check that a mailbox of this version is there.
    pub fn attach(serial: Option<&str>) -> Result<Self> {
        let probes = Lister::new().list_all();
        let info = match serial {
            Some(serial) => probes
                .iter()
                .find(|probe| probe.serial_number.as_deref() == Some(serial))
                .with_context(|| format!("no probe with serial {serial}"))?,
            None => match probes.as_slice() {
                [one] => one,
                [] => bail!("no probe plugged in"),
                [_, ..] => bail!("more than one probe plugged in: pick one with --probe"),
            },
        };
        let probe = info.open().context("opening the probe")?;
        let session = probe
            .attach(TARGET, Permissions::default())
            .context("attaching to the controller")?;
        let mut link = Self {
            session,
            seq: 0,
            lease: 0,
            renewed: None,
        };
        link.check()?;
        Ok(link)
    }

    fn check(&mut self) -> Result<()> {
        let mut core = self.session.core(0)?;
        let magic = core.read_word_32(field(offset::MAGIC))?;
        if magic != MAGIC {
            bail!(
                "no mailbox at {MAILBOX_ADDRESS:#010x}: read {magic:#010x}; is a firmware with one running?"
            );
        }
        let version = core.read_word_32(field(offset::VERSION))?;
        if version != VERSION {
            bail!("the firmware's mailbox is version {version}, this tool speaks {VERSION}");
        }
        self.seq = core.read_word_32(field(offset::RESPONSE_SEQ))?;
        Ok(())
    }

    /// One word of the part's memory, read straight from the bus.
    pub fn read_word(&mut self, at: u64) -> Result<u32> {
        let mut core = self.session.core(0)?;
        Ok(core.read_word_32(at)?)
    }

    /// Land one request and wait for its answer.
    fn request(&mut self, op: Op, arg0: u32, arg1: u32, data: &[u8]) -> Result<Answer> {
        if data.len() > DATA_BYTES {
            bail!("{} bytes do not fit the mailbox's {DATA_BYTES}", data.len());
        }
        let seq = self.seq.checked_add(1).unwrap_or(1);
        let mut core = self.session.core(0)?;
        if !data.is_empty() {
            core.write_8(field(offset::DATA), data)?;
        }
        core.write_word_32(field(offset::OP), op.code())?;
        core.write_word_32(field(offset::ARG0), arg0)?;
        core.write_word_32(field(offset::ARG1), arg1)?;
        core.write_word_32(field(offset::REQUEST_SEQ), seq)?;
        self.seq = seq;
        let started = Instant::now();
        // Bounded by the deadline: every turn sleeps.
        loop {
            if core.read_word_32(field(offset::RESPONSE_SEQ))? == seq {
                break;
            }
            if started.elapsed() > DEADLINE {
                bail!(
                    "the firmware did not answer {op:?} within {DEADLINE:?}: is the recorder task running?"
                );
            }
            sleep(POLL);
        }
        let status = core.read_word_32(field(offset::STATUS))?;
        let status = Status::of(status)
            .with_context(|| format!("a status word nobody defined: {status}"))?;
        let length = core.read_word_32(field(offset::LENGTH))?;
        let length = usize::try_from(length)
            .ok()
            .filter(|length| *length <= DATA_BYTES)
            .with_context(|| format!("an answer of {length} bytes, past the mailbox"))?;
        let mut data = vec![0u8; length];
        if length > 0 {
            core.read_8(field(offset::DATA), &mut data)?;
        }
        Ok(Answer { status, data })
    }

    /// The firmware's boot count.
    pub fn ping(&mut self) -> Result<u32> {
        let data = self.request(Op::Ping, 0, 0, &[])?.ok("ping")?;
        let bytes: [u8; 4] = data
            .get(..4)
            .and_then(|four| four.try_into().ok())
            .context("a ping answers four bytes")?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// `into.len()` bytes of the FRAM from `at`, a mailbox at a time.
    pub fn read_fram(&mut self, at: u16, into: &mut [u8]) -> Result<()> {
        let end = usize::from(at)
            .checked_add(into.len())
            .filter(|end| *end <= FRAM_BYTES)
            .context("past the end of the FRAM")?;
        let _ = end;
        let mut from = u32::from(at);
        for chunk in into.chunks_mut(DATA_BYTES) {
            let len = u32::try_from(chunk.len()).context("a length that fits")?;
            let data = self
                .request(Op::ReadFram, from, len, &[])?
                .ok("reading the FRAM")?;
            if data.len() != chunk.len() {
                bail!(
                    "asked the FRAM for {} bytes, got {}",
                    chunk.len(),
                    data.len()
                );
            }
            chunk.copy_from_slice(&data);
            from = from.saturating_add(len);
        }
        Ok(())
    }

    /// `bytes` into the FRAM at `at`, as the one transaction the seam
    /// promises: more than the mailbox carries is refused, never split.
    pub fn write_fram(&mut self, at: u16, bytes: &[u8]) -> Result<(), Refused<anyhow::Error>> {
        let len = u32::try_from(bytes.len())
            .ok()
            .filter(|_| bytes.len() <= DATA_BYTES)
            .ok_or_else(|| {
                Refused::Bus(anyhow!("{} bytes are not one transaction", bytes.len()))
            })?;
        let answer = self
            .request(Op::WriteFram, u32::from(at), len, bytes)
            .map_err(Refused::Bus)?;
        match answer.status {
            Status::Ok => Ok(()),
            Status::SupplyFalling => Err(Refused::SupplyFalling),
            Status::UnknownOp
            | Status::OutOfRange
            | Status::Bus
            | Status::NoNor
            | Status::NoModuleAnswer
            | Status::LinkBusy
            | Status::NoStore
            | Status::BridgeRefused
            | Status::ModuleRefused
            | Status::InsideTheRing => Err(Refused::Bus(anyhow!(
                "writing the FRAM: {:?}",
                answer.status
            ))),
        }
    }

    /// `into.len()` bytes of the NOR from `at`, a mailbox at a time.
    pub fn read_nor(&mut self, at: u32, into: &mut [u8]) -> Result<()> {
        let mut from = at;
        for chunk in into.chunks_mut(DATA_BYTES) {
            let len = u32::try_from(chunk.len()).context("a length that fits")?;
            let data = self
                .request(Op::ReadNor, from, len, &[])?
                .ok("reading the NOR")?;
            if data.len() != chunk.len() {
                bail!(
                    "asked the NOR for {} bytes, got {}",
                    chunk.len(),
                    data.len()
                );
            }
            chunk.copy_from_slice(&data);
            from = from.saturating_add(len);
        }
        Ok(())
    }

    /// One page of the ring's records from `from`, walked by the firmware's
    /// own reader and laid out as `o89_core::mailbox::RingPage`.
    pub fn read_ring(&mut self, from: u64) -> Result<Vec<u8>> {
        let (lo, hi) = RingPage::args(from);
        self.request(Op::ReadRing, lo, hi, &[])?
            .ok("reading the ring")
    }

    /// Erase the ring's oldest block, and say what that left.
    pub fn drop_oldest(&mut self) -> Result<Dropped> {
        let data = self
            .request(Op::DropOldest, 0, 0, &[])?
            .ok("dropping the oldest block")?;
        DropAnswer::decode(&data)
            .with_context(|| format!("a drop answered in {} bytes", data.len()))
    }

    /// Erase one 4 KiB block of the NOR outside the ring, counted from the
    /// part's start.
    pub fn erase_nor_block(&mut self, block: u32) -> Result<()> {
        self.request(Op::EraseNorBlock, block, 0, &[])?
            .ok("erasing a block")?;
        Ok(())
    }

    /// Put the module into its ROM's download mode through the link, the
    /// firmware performing the reset and the knock (KM43 L-192), and bridge
    /// its UART to the rings. `reason` is `download_reason` as the registry
    /// numbers it.
    pub fn download(&mut self, reason: u8, entry: DownloadEntry) -> Result<()> {
        self.request(Op::Download, u32::from(reason), entry.code(), &[])?
            .ok("entering download mode")?;
        Ok(())
    }

    /// End the bridge: the module reset normally, the link back.
    pub fn normal(&mut self) -> Result<()> {
        self.request(Op::Normal, 0, 0, &[])?
            .ok("returning the module to normal")?;
        Ok(())
    }

    /// Bytes for the module, as many as the ring has room for; how many
    /// were taken. The rest is the caller's to offer again.
    pub fn bridge_write(&mut self, bytes: &[u8]) -> Result<usize> {
        let mut core = self.session.core(0)?;
        let write = core.read_word_32(field(offset::TO_MODULE_WRITE))?;
        let read = core.read_word_32(field(offset::TO_MODULE_READ))?;
        let count = Ring::room(write, read).min(bytes.len());
        let mut index = write;
        let mut rest = bytes.get(..count).unwrap_or(&[]);
        // Bounded by the count: at most two runs, one either side of the wrap.
        while !rest.is_empty() {
            let run = Ring::contiguous(index, rest.len());
            let (chunk, after) = rest.split_at(run.min(rest.len()));
            let at = field(offset::TO_MODULE_DATA)
                .saturating_add(u64::try_from(Ring::index(index)).unwrap_or(0));
            core.write_8(at, chunk)?;
            index = Ring::advanced(index, chunk.len());
            rest = after;
        }
        if count > 0 {
            core.write_word_32(field(offset::TO_MODULE_WRITE), index)?;
        }
        Ok(count)
    }

    /// Bytes from the module, appended to `into`; how many.
    pub fn bridge_read(&mut self, into: &mut Vec<u8>) -> Result<usize> {
        let mut core = self.session.core(0)?;
        let write = core.read_word_32(field(offset::FROM_MODULE_WRITE))?;
        let read = core.read_word_32(field(offset::FROM_MODULE_READ))?;
        let count = Ring::available(write, read);
        let mut index = read;
        let mut left = count;
        let mut chunk = [0u8; RING_BYTES];
        // Bounded by the count: at most two runs, one either side of the wrap.
        while left > 0 {
            let run = Ring::contiguous(index, left);
            let room = chunk.get_mut(..run).context("a run inside the ring")?;
            let at = field(offset::FROM_MODULE_DATA)
                .saturating_add(u64::try_from(Ring::index(index)).unwrap_or(0));
            core.read_8(at, room)?;
            into.extend_from_slice(room);
            index = Ring::advanced(index, run);
            left = left.saturating_sub(run);
        }
        if count > 0 {
            core.write_word_32(field(offset::FROM_MODULE_READ), index)?;
        }
        // Every reader of the bridge renews the lease, so a host holds the
        // bridge exactly as long as it keeps reading it.
        if self.renewed.is_none_or(|at| at.elapsed() >= LEASE_RENEW) {
            self.lease = self.lease.wrapping_add(1);
            core.write_word_32(field(offset::BRIDGE_LEASE), self.lease)?;
            self.renewed = Some(Instant::now());
        }
        Ok(count)
    }

    /// Stage a secret in one firmware request and reboot to apply it before
    /// sessions can use it. The caller reads it back before printing the label.
    pub fn write_secret(&mut self, bytes: &[u8], replace: bool) -> Result<()> {
        let len = u32::try_from(bytes.len()).context("secret length")?;
        self.request(Op::WriteSecret, u32::from(replace), len, bytes)?
            .ok("stage secret replacement")?;
        self.reboot()
    }

    /// Ask the firmware to reset the part. The answer lands a moment
    /// before the reset, and may be lost to it; the boot count afterwards
    /// says whether the part came back.
    pub fn reboot(&mut self) -> Result<()> {
        let before = self.ping()?;
        match self.request(Op::Reboot, 0, 0, &[]) {
            Ok(answer) => answer.ok("reboot").map(|_| ())?,
            Err(error) => tracing::debug!(%error, "the reset took the answer with it"),
        }
        sleep(Duration::from_secs(2));
        self.check()
            .context("the part did not come back with a mailbox")?;
        let after = self.ping()?;
        if after <= before {
            bail!("the boot count went from {before} to {after}: the part did not reboot");
        }
        println!("rebooted: boot {before} to {after}");
        Ok(())
    }
}

impl Fram for Link {
    type Error = anyhow::Error;

    fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<()>> {
        ready(self.read_fram(at.0, into))
    }

    fn write(
        &mut self,
        at: Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), Refused<anyhow::Error>>> {
        ready(self.write_fram(at.0, bytes))
    }
}
