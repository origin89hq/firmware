//! 1-Wire over the [`OneWire`] line seam: bytes, ROM codes and the search.
//!
//! The board has no peripheral free for 1-Wire on `PC4`, so the controller
//! bit-bangs it with CPU delay loops. A loop's length depends on the core
//! clock, so the adapter counts how long a known number of loops takes when
//! it builds the line, and [`Calibration`] turns that count into the loops
//! each slot of [`STANDARD`] needs. The arithmetic is here, where a host test
//! can reach it; the pin and the timer are the adapter's.
//!
//! Every ROM code carries a CRC-8/MAXIM, checked before a [`Rom`] exists, and
//! the search collects at most [`MAX_DEVICES`] of them: a line with more is
//! refused as a whole rather than read in part.
//!
//! Taken from the self-test (`origin89hq/origin89`,
//! `firmwares/o89-selftest/src/onewire.rs` and `crc.rs`): the slot timings it
//! ran on board A, the calibration, and the binary search, rewritten to the
//! seam.

use crc::{CRC_8_MAXIM_DOW, Crc};

use crate::port::{OneWire, Presence};

/// The CRC a 1-Wire device puts on its ROM code and a DS18B20 on its
/// scratchpad: CRC-8/MAXIM, polynomial `x^8 + x^5 + x^4 + 1`.
const CRC8: Crc<u8> = Crc::<u8>::new(&CRC_8_MAXIM_DOW);

/// The CRC-8/MAXIM of `bytes`. Over a block and its own CRC, it is zero.
#[must_use]
pub fn crc8(bytes: &[u8]) -> u8 {
    CRC8.checksum(bytes)
}

/// The number of delay loops the adapter times to calibrate its delays.
///
/// Long enough that the timer's resolution is a small part of it: 6.25 ms
/// at the fastest clock [`Calibration`] accepts, against a 1 µs tick.
pub const CALIBRATION_LOOPS: u32 = 400_000;

/// How long each phase of a standard-speed slot lasts, in microseconds, or
/// in delay loops once a [`Calibration`] has converted it.
///
/// Every value is inside the bounds of Maxim's application note 126 and was
/// run on board A by the self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Slots {
    /// The reset pulse: the line held low.
    pub reset_low: u32,
    /// From releasing the reset to sampling for a presence pulse.
    pub presence_sample: u32,
    /// From the presence sample to the end of the reset slot.
    pub reset_rest: u32,
    /// A one: the line held low.
    pub one_low: u32,
    /// A one: released, to the end of the slot.
    pub one_rest: u32,
    /// A zero: the line held low.
    pub zero_low: u32,
    /// A zero: released, to the end of the slot.
    pub zero_rest: u32,
    /// A read: the line held low to open the slot.
    pub read_low: u32,
    /// A read: released, to sampling the line, inside the 15 µs a device
    /// holds it.
    pub read_sample: u32,
    /// A read: from the sample to the end of the slot.
    pub read_rest: u32,
}

/// The standard-speed slots, in microseconds.
pub const STANDARD: Slots = Slots {
    reset_low: 480,
    presence_sample: 70,
    reset_rest: 410,
    one_low: 6,
    one_rest: 64,
    zero_low: 60,
    zero_rest: 10,
    read_low: 3,
    read_sample: 10,
    read_rest: 57,
};

/// Delay loops per microsecond, as the timed count itself.
///
/// Built only from a count inside what the part can do, so a timer that did
/// not run or a clock that is not the one configured is refused at
/// construction rather than turned into slots of the wrong length. The
/// ratio is kept whole, and each delay is rounded up from it, so a slot is
/// never shorter than asked, by the calibration's own measure, and never
/// longer by more than one loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Calibration {
    loops: u32,
    elapsed_us: u32,
}

/// Why a count was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused calibration is a line with no timing"]
pub enum CalibrationError {
    /// The loops took no measurable time: the timer did not run.
    NoTime,
    /// Fewer than [`Calibration::SLOWEST`] loops per microsecond: one loop
    /// is too coarse to place the read sample inside its window.
    TooSlow,
    /// More than [`Calibration::FASTEST`] loops per microsecond, which the
    /// core cannot run: the timer is slow or the count is wrong.
    TooFast,
}

impl Calibration {
    /// The fewest loops per microsecond accepted. At four, a delay is at
    /// most a quarter of a microsecond longer than its target, and the read
    /// slot's 3 µs and 10 µs keep the sample well inside the device's 15 µs.
    pub const SLOWEST: u32 = 4;

    /// The most loops per microsecond accepted. A loop takes at least one
    /// cycle and the STM32G0B1 runs at most 64 MHz; the two extra allow for
    /// the timer's resolution over the count.
    pub const FASTEST: u32 = 66;

    /// The calibration from `loops` delay loops that took `elapsed_us`
    /// microseconds, or why not. Both bounds are inclusive and compared
    /// without rounding.
    pub fn from_count(loops: u32, elapsed_us: u32) -> Result<Self, CalibrationError> {
        if elapsed_us == 0 {
            return Err(CalibrationError::NoTime);
        }
        let (count, time) = (u64::from(loops), u64::from(elapsed_us));
        if count < u64::from(Self::SLOWEST).saturating_mul(time) {
            return Err(CalibrationError::TooSlow);
        }
        if count > u64::from(Self::FASTEST).saturating_mul(time) {
            return Err(CalibrationError::TooFast);
        }
        Ok(Self { loops, elapsed_us })
    }

    /// The loops that take at least `us` microseconds at the measured rate:
    /// rounded up, at least one, and `u32::MAX` past what a `u32` holds.
    #[must_use]
    pub fn loops(self, us: u32) -> u32 {
        let wanted = u64::from(us).saturating_mul(u64::from(self.loops));
        let time = u64::from(self.elapsed_us);
        let whole = wanted.checked_div(time).unwrap_or(u64::MAX);
        let loops = if wanted.checked_rem(time).unwrap_or(0) == 0 {
            whole
        } else {
            whole.saturating_add(1)
        };
        u32::try_from(loops.max(1)).unwrap_or(u32::MAX)
    }

    /// Each phase of `slots`, given in microseconds, in loops.
    #[must_use]
    pub fn delays(self, slots: &Slots) -> Slots {
        Slots {
            reset_low: self.loops(slots.reset_low),
            presence_sample: self.loops(slots.presence_sample),
            reset_rest: self.loops(slots.reset_rest),
            one_low: self.loops(slots.one_low),
            one_rest: self.loops(slots.one_rest),
            zero_low: self.loops(slots.zero_low),
            zero_rest: self.loops(slots.zero_rest),
            read_low: self.loops(slots.read_low),
            read_sample: self.loops(slots.read_sample),
            read_rest: self.loops(slots.read_rest),
        }
    }
}

/// A 64-bit ROM code whose CRC holds: family, serial, CRC.
///
/// ```compile_fail
/// use o89_drivers::onewire::Rom;
///
/// let unchecked = Rom([0x28, 0, 0, 0, 0, 0, 0, 0]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Rom([u8; 8]);

/// Why eight bytes are not a ROM code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refused ROM code is a device that was not recognised"]
pub enum RomError {
    /// The last byte is not the CRC of the first seven.
    Crc,
    /// Family code zero, which no device carries and whose CRC holds over
    /// all zeros: what a line held low reads as.
    Zero,
}

impl Rom {
    /// `bytes` as sent, family first, or why not.
    pub fn new(bytes: [u8; 8]) -> Result<Self, RomError> {
        if crc8(&bytes) != 0 {
            return Err(RomError::Crc);
        }
        if bytes.first() == Some(&0) {
            return Err(RomError::Zero);
        }
        Ok(Self(bytes))
    }

    /// The family code: what kind of device it is.
    #[must_use]
    pub const fn family(&self) -> u8 {
        let [family, ..] = self.0;
        family
    }

    /// The eight bytes, family first, as sent on the line.
    #[must_use]
    pub const fn bytes(&self) -> [u8; 8] {
        self.0
    }
}

/// The most devices [`search`] collects from one line. Eight probes is what
/// the store's site is sized for (`o89_core::SIGNAL_SLOTS`).
pub const MAX_DEVICES: usize = 8;

/// The ROM codes on one line, in the order the search found them, at most
/// [`MAX_DEVICES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Roms {
    found: [Option<Rom>; MAX_DEVICES],
}

impl Roms {
    const EMPTY: Self = Self {
        found: [None; MAX_DEVICES],
    };

    /// Every ROM found.
    pub fn iter(&self) -> impl Iterator<Item = &Rom> {
        self.found.iter().flatten()
    }

    /// How many were found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether nothing answered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add `rom`, or `false` when every place is taken.
    fn push(&mut self, rom: Rom) -> bool {
        match self.found.iter_mut().find(|place| place.is_none()) {
            Some(place) => {
                *place = Some(rom);
                true
            }
            None => false,
        }
    }
}

/// Why a search found nothing it could vouch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a failed search is a line whose devices are unknown"]
pub enum SearchError<E> {
    /// The line reported a fault.
    Line(E),
    /// A bit and its complement both read one, every device having dropped
    /// out mid-search, or a pass found a device an earlier pass had found,
    /// the device it was heading for having left between passes. Either way
    /// the line changed under the search.
    Lost,
    /// A ROM code the search assembled was refused.
    Rom(RomError),
    /// More than [`MAX_DEVICES`] devices answered. The whole search is
    /// refused rather than a subset kept, so no device is silently left out.
    TooMany,
}

const SEARCH_ROM: u8 = 0xF0;

/// Write `byte`, least significant bit first.
pub async fn write_byte<W: OneWire>(line: &mut W, byte: u8) -> Result<(), W::Error> {
    for bit in 0..8u8 {
        line.write_bit((byte >> bit) & 1 == 1).await?;
    }
    Ok(())
}

/// Read a byte, least significant bit first.
pub async fn read_byte<W: OneWire>(line: &mut W) -> Result<u8, W::Error> {
    let mut byte = 0u8;
    for bit in 0..8u8 {
        if line.read_bit().await? {
            byte |= 1 << bit;
        }
    }
    Ok(byte)
}

/// Every device on the line, by Maxim's binary search (application note
/// 187), at most [`MAX_DEVICES`] of them.
///
/// Nothing answering the reset is an empty line, not an error. Each pass
/// finds one device, so the search makes at most `MAX_DEVICES + 1` passes of
/// 64 bits each.
pub async fn search<W: OneWire>(line: &mut W) -> Result<Roms, SearchError<W::Error>> {
    let mut roms = Roms::EMPTY;
    let mut rom = [0u8; 8];
    let mut last_fork: Option<u8> = None;
    for _ in 0..=MAX_DEVICES {
        match line.reset().await.map_err(SearchError::Line)? {
            Presence::Present => {}
            Presence::Absent => return Ok(roms),
        }
        write_byte(line, SEARCH_ROM)
            .await
            .map_err(SearchError::Line)?;
        let mut fork: Option<u8> = None;
        for bit in 0..64u8 {
            let at = usize::from(bit / 8);
            let mask = 1u8 << (bit % 8);
            let one = line.read_bit().await.map_err(SearchError::Line)?;
            let complement = line.read_bit().await.map_err(SearchError::Line)?;
            let go_one = match (one, complement) {
                (true, true) => return Err(SearchError::Lost),
                (true, false) => true,
                (false, true) => false,
                (false, false) => {
                    // Devices differ here: take the branch the last pass did
                    // not finish, and remember the last zero taken.
                    let choose = match last_fork {
                        Some(last) if bit == last => true,
                        Some(last) if bit > last => false,
                        None => false,
                        Some(_) => rom.get(at).is_some_and(|byte| byte & mask != 0),
                    };
                    if !choose {
                        fork = Some(bit);
                    }
                    choose
                }
            };
            if let Some(byte) = rom.get_mut(at) {
                if go_one {
                    *byte |= mask;
                } else {
                    *byte &= !mask;
                }
            }
            line.write_bit(go_one).await.map_err(SearchError::Line)?;
        }
        let found = Rom::new(rom).map_err(SearchError::Rom)?;
        if roms.iter().any(|seen| *seen == found) {
            return Err(SearchError::Lost);
        }
        if !roms.push(found) {
            return Err(SearchError::TooMany);
        }
        last_fork = fork;
        if last_fork.is_none() {
            return Ok(roms);
        }
    }
    Err(SearchError::TooMany)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::future::{Future, ready};
    use embassy_futures::block_on;

    /// A simulated line of devices, wired-AND, driven slot by slot through
    /// the seam. Built by hand from the 1-Wire protocol; not a bench capture.
    pub(crate) struct Line<'a> {
        pub devices: &'a [Device],
        state: State,
        /// Which devices are still taking part: in a search, or selected
        /// by a match or a skip.
        active: [bool; MAX_DEVICES + 2],
        command: u8,
        bits: u8,
        /// Bits a device has left to send, least significant first.
        out: [u8; 9],
        out_len: u8,
        rom_in: [u8; 8],
        search_bit: u8,
        search_phase: u8,
        /// Every command byte the master sent after a reset.
        pub resets: usize,
        pub converts: usize,
        /// Makes the line report its fault on the next slot.
        pub fault: bool,
        /// When set, every slot moves this clock on by a millisecond, so a
        /// test sees time pass while the master talks.
        pub clock: Option<&'a core::cell::Cell<u64>>,
    }

    /// One simulated device.
    #[derive(Clone, Copy)]
    pub(crate) struct Device {
        pub rom: [u8; 8],
        pub pad: [u8; 9],
        /// When set, the device drops out of every search after this bit.
        pub vanish_at: Option<u8>,
        /// When set, the device is unplugged once the line has seen this
        /// many resets.
        pub leaves_after: Option<usize>,
        /// The device ignores a conversion command and never holds the line
        /// busy.
        pub ignores_convert: bool,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum State {
        Idle,
        Rom,
        Search,
        Match,
        Function,
        Send,
        Converting,
    }

    /// The fault the simulated line reports.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct HeldLow;

    impl<'a> Line<'a> {
        pub(crate) fn new(devices: &'a [Device]) -> Self {
            Self {
                devices,
                state: State::Idle,
                active: [false; MAX_DEVICES + 2],
                command: 0,
                bits: 0,
                out: [0; 9],
                out_len: 0,
                rom_in: [0; 8],
                search_bit: 0,
                search_phase: 0,
                resets: 0,
                converts: 0,
                fault: false,
                clock: None,
            }
        }

        fn bit_of(bytes: &[u8], bit: u8) -> bool {
            bytes[usize::from(bit / 8)] >> (bit % 8) & 1 == 1
        }

        fn on_command(&mut self, command: u8) {
            match (self.state, command) {
                (State::Rom, 0xF0) => {
                    self.state = State::Search;
                    self.search_bit = 0;
                    self.search_phase = 0;
                }
                (State::Rom, 0x55) => {
                    self.state = State::Match;
                    self.bits = 0;
                }
                (State::Rom, 0xCC) => self.state = State::Function,
                (State::Function, 0x44) => {
                    self.converts = self.converts.checked_add(1).unwrap();
                    self.state = State::Converting;
                }
                (State::Function, 0xBE) => {
                    // Wired-AND of every selected device's scratchpad.
                    let mut pad = [0xFFu8; 9];
                    for (i, device) in self.devices.iter().enumerate() {
                        if self.active[i] {
                            for (out, byte) in pad.iter_mut().zip(device.pad) {
                                *out &= byte;
                            }
                        }
                    }
                    self.out = pad;
                    self.out_len = 72;
                    self.bits = 0;
                    self.state = State::Send;
                }
                _ => self.state = State::Idle,
            }
        }
    }

    impl OneWire for Line<'_> {
        type Error = HeldLow;

        fn reset(&mut self) -> impl Future<Output = Result<Presence, HeldLow>> {
            ready(self.reset_now())
        }

        fn write_bit(&mut self, bit: bool) -> impl Future<Output = Result<(), HeldLow>> {
            ready(self.write_now(bit))
        }

        fn read_bit(&mut self) -> impl Future<Output = Result<bool, HeldLow>> {
            ready(self.read_now())
        }
    }

    impl Line<'_> {
        fn slot(&self) {
            if let Some(clock) = self.clock {
                clock.set(clock.get().checked_add(1).unwrap());
            }
        }

        fn reset_now(&mut self) -> Result<Presence, HeldLow> {
            self.slot();
            if self.fault {
                return Err(HeldLow);
            }
            self.resets = self.resets.checked_add(1).unwrap();
            self.state = State::Rom;
            self.command = 0;
            self.bits = 0;
            let resets = self.resets;
            for (i, active) in self.active.iter_mut().enumerate() {
                *active = self
                    .devices
                    .get(i)
                    .is_some_and(|device| device.leaves_after.is_none_or(|n| resets <= n));
            }
            Ok(if self.active.contains(&true) {
                Presence::Present
            } else {
                Presence::Absent
            })
        }

        fn write_now(&mut self, bit: bool) -> Result<(), HeldLow> {
            self.slot();
            if self.fault {
                return Err(HeldLow);
            }
            match self.state {
                State::Rom | State::Function => {
                    if bit {
                        self.command |= 1 << self.bits;
                    }
                    self.bits = self.bits.checked_add(1).unwrap();
                    if self.bits == 8 {
                        let command = self.command;
                        self.command = 0;
                        self.bits = 0;
                        self.on_command(command);
                    }
                }
                State::Match => {
                    let at = usize::from(self.bits / 8);
                    if bit {
                        self.rom_in[at] |= 1 << (self.bits % 8);
                    } else {
                        self.rom_in[at] &= !(1 << (self.bits % 8));
                    }
                    self.bits = self.bits.checked_add(1).unwrap();
                    if self.bits == 64 {
                        for (i, device) in self.devices.iter().enumerate() {
                            self.active[i] = device.rom == self.rom_in;
                        }
                        self.bits = 0;
                        self.state = State::Function;
                    }
                }
                State::Search => {
                    // The master's direction: devices that disagree drop out.
                    let bit_at = self.search_bit;
                    for (i, device) in self.devices.iter().enumerate() {
                        if self.active[i] && Self::bit_of(&device.rom, bit_at) != bit {
                            self.active[i] = false;
                        }
                    }
                    self.search_bit = self.search_bit.checked_add(1).unwrap();
                    self.search_phase = 0;
                    if self.search_bit == 64 {
                        self.state = State::Idle;
                    }
                }
                State::Idle | State::Send | State::Converting => {}
            }
            Ok(())
        }

        fn read_now(&mut self) -> Result<bool, HeldLow> {
            self.slot();
            if self.fault {
                return Err(HeldLow);
            }
            match self.state {
                State::Search => {
                    let bit_at = self.search_bit;
                    let complement = self.search_phase == 1;
                    self.search_phase = u8::from(self.search_phase == 0);
                    let mut line = true;
                    for (i, device) in self.devices.iter().enumerate() {
                        let gone = device.vanish_at.is_some_and(|at| bit_at >= at);
                        if self.active[i] && !gone {
                            line &= Self::bit_of(&device.rom, bit_at) != complement;
                        }
                    }
                    Ok(line)
                }
                State::Send if self.bits < self.out_len => {
                    let bit = Self::bit_of(&self.out, self.bits);
                    self.bits = self.bits.checked_add(1).unwrap();
                    Ok(bit)
                }
                // A converting device holds the line low.
                State::Converting => Ok(!self
                    .devices
                    .iter()
                    .zip(self.active)
                    .any(|(device, active)| active && !device.ignores_convert)),
                State::Idle | State::Rom | State::Match | State::Function | State::Send => Ok(true),
            }
        }
    }

    /// A ROM code with its CRC appended by the function under test's
    /// sibling; `crc8` itself is held to the catalogue's check value below.
    pub(crate) fn rom(family: u8, serial: [u8; 6]) -> [u8; 8] {
        let mut rom = [family, 0, 0, 0, 0, 0, 0, 0];
        rom[1..7].copy_from_slice(&serial);
        rom[7] = crc8(&rom[..7]);
        rom
    }

    pub(crate) fn device(rom: [u8; 8]) -> Device {
        Device {
            rom,
            pad: [0xFF; 9],
            vanish_at: None,
            leaves_after: None,
            ignores_convert: false,
        }
    }

    #[test]
    fn crc8_is_the_catalogue_s_crc_8_maxim_and_the_application_note_s_rom() {
        // The CRC catalogue's check value for CRC-8/MAXIM-DOW.
        assert_eq!(crc8(b"123456789"), 0xA1);
        // Maxim application note 27's worked ROM code, family 0x02, CRC 0xA2.
        let an27 = [0x02, 0x1C, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xA2];
        assert_eq!(crc8(&an27[..7]), 0xA2);
        assert_eq!(crc8(&an27), 0);
        assert_eq!(crc8(&[]), 0);
    }

    #[test]
    fn a_rom_is_built_only_when_its_crc_holds_and_its_family_is_not_zero() {
        let an27 = [0x02, 0x1C, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xA2];
        let good = Rom::new(an27).unwrap();
        assert_eq!((good.family(), good.bytes()), (0x02, an27));

        let mut flipped = an27;
        flipped[3] ^= 0x10;
        assert_eq!(Rom::new(flipped), Err(RomError::Crc));
        // A line held low reads all zeros, whose CRC is zero.
        assert_eq!(Rom::new([0; 8]), Err(RomError::Zero));
        // A line nobody pulls down reads all ones.
        assert_eq!(Rom::new([0xFF; 8]), Err(RomError::Crc));
    }

    #[test]
    fn every_single_bit_flip_of_a_rom_is_refused() {
        let an27 = [0x02, 0x1C, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xA2];
        for bit in 0..64 {
            let mut flipped = an27;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(Rom::new(flipped), Err(RomError::Crc), "bit {bit}");
        }
    }

    /// Every phase of the standard slots, in microseconds.
    fn phases(slots: &Slots) -> [u32; 10] {
        [
            slots.reset_low,
            slots.presence_sample,
            slots.reset_rest,
            slots.one_low,
            slots.one_rest,
            slots.zero_low,
            slots.zero_rest,
            slots.read_low,
            slots.read_sample,
            slots.read_rest,
        ]
    }

    #[test]
    fn a_calibration_from_a_normal_count_gives_each_slot_its_loops() {
        // 400 000 loops in 6 250 µs is 64 loops per microsecond: the core at
        // 64 MHz, one cycle a loop.
        let cal = Calibration::from_count(CALIBRATION_LOOPS, 6_250).unwrap();
        assert_eq!(cal.loops(480), 30_720);
        assert_eq!(cal.loops(3), 192);
        let delays = cal.delays(&STANDARD);
        assert_eq!(delays.reset_low, 30_720);
        assert_eq!(delays.read_sample, 640);
        assert_eq!(delays.one_low, 384);
        // Nothing rounds to no delay at all.
        let slow = Calibration::from_count(CALIBRATION_LOOPS, 100_000).unwrap();
        assert_eq!(slow.loops(0), 1);
        assert_eq!(cal.loops(u32::MAX), u32::MAX);
    }

    #[test]
    fn a_non_integral_rate_never_shortens_a_slot_and_lengthens_it_by_under_a_loop() {
        // 400 000 loops in 93 751 µs is 4.2666 loops a microsecond.
        let cal = Calibration::from_count(CALIBRATION_LOOPS, 93_751).unwrap();
        // 480 µs is 2047.98 loops, so 2048, which the count says is 480.0005 µs.
        assert_eq!(cal.loops(480), 2048);
        assert_eq!(cal.loops(60), 256);
        for (loops, elapsed) in [
            (400_000u32, 93_751u32),
            (400_000, 6_061),
            (400_000, 7_001),
            (399_999, 99_999),
        ] {
            let cal = Calibration::from_count(loops, elapsed).unwrap();
            for (us, got) in phases(&STANDARD)
                .into_iter()
                .zip(phases(&cal.delays(&STANDARD)))
            {
                // The delay in microseconds, by the count: `got × elapsed / loops`.
                let (count, time) = (u64::from(loops), u64::from(elapsed));
                let at_least = u64::from(got) * time >= u64::from(us) * count;
                let under_a_loop = (u64::from(got) - 1) * time < u64::from(us) * count;
                assert!(
                    at_least && under_a_loop,
                    "{us} µs as {got} loops at {loops}/{elapsed}"
                );
            }
        }
    }

    #[test]
    fn a_calibration_accepts_the_slowest_and_fastest_counts_and_refuses_past_them() {
        // Four loops per microsecond: 400 000 loops in 100 000 µs.
        let slowest = Calibration::from_count(CALIBRATION_LOOPS, 100_000).unwrap();
        assert_eq!(slowest.loops(3), 12);
        assert_eq!(
            Calibration::from_count(CALIBRATION_LOOPS, 100_001),
            Err(CalibrationError::TooSlow)
        );
        // Sixty-six loops per microsecond: 400 000 in 6 061 µs is 65.995,
        // and in 6 060 µs is 66.007.
        let fastest = Calibration::from_count(CALIBRATION_LOOPS, 6_061).unwrap();
        assert_eq!(fastest.loops(1), 66);
        assert_eq!(
            Calibration::from_count(CALIBRATION_LOOPS, 6_060),
            Err(CalibrationError::TooFast)
        );
        // Exactly sixty-six is inside.
        assert!(Calibration::from_count(66 * 6_000, 6_000).is_ok());
        assert_eq!(
            Calibration::from_count(CALIBRATION_LOOPS, 0),
            Err(CalibrationError::NoTime)
        );
        assert_eq!(
            Calibration::from_count(u32::MAX, 1),
            Err(CalibrationError::TooFast)
        );
        assert_eq!(
            Calibration::from_count(0, 1),
            Err(CalibrationError::TooSlow)
        );
    }

    #[test]
    fn bytes_go_out_and_come_back_least_significant_bit_first() {
        let an27 = [0x02, 0x1C, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xA2];
        let mut pad = [0u8; 9];
        pad[0] = 0b1000_0001;
        pad[1] = 0x5A;
        let devices = [Device {
            pad,
            ..device(an27)
        }];
        let mut line = Line::new(&devices);
        block_on(async {
            assert_eq!(line.reset().await, Ok(Presence::Present));
            write_byte(&mut line, 0xCC).await.unwrap();
            write_byte(&mut line, 0xBE).await.unwrap();
            assert_eq!(read_byte(&mut line).await, Ok(0b1000_0001));
            assert_eq!(read_byte(&mut line).await, Ok(0x5A));
        });
        // A byte written in the wrong order is a command the line ignores.
        let mut line = Line::new(&devices);
        block_on(async {
            line.reset().await.unwrap();
            write_byte(&mut line, 0x33).await.unwrap();
            write_byte(&mut line, 0x7D).await.unwrap();
            assert_eq!(read_byte(&mut line).await, Ok(0xFF));
        });
    }

    #[test]
    fn a_search_finds_every_device_on_the_line_once() {
        let devices = [
            device(rom(0x28, [0x01, 0, 0, 0, 0, 0])),
            device(rom(0x28, [0x02, 0, 0, 0, 0, 0])),
            device(rom(0x28, [0x03, 0x80, 0, 0, 0, 0x7F])),
            device(rom(0x10, [0xFF, 0xFF, 0, 0, 0, 0])),
        ];
        let mut line = Line::new(&devices);
        let roms = block_on(search(&mut line)).unwrap();
        assert_eq!(roms.len(), 4);
        for device in &devices {
            let hits = roms.iter().filter(|rom| rom.bytes() == device.rom).count();
            assert_eq!(hits, 1, "{:02x?}", device.rom);
        }
        assert_eq!(line.resets, 4);
    }

    #[test]
    fn a_search_of_one_device_and_of_an_empty_line() {
        let one = [device(rom(0x28, [9, 8, 7, 6, 5, 4]))];
        let mut line = Line::new(&one);
        let roms = block_on(search(&mut line)).unwrap();
        assert_eq!(roms.len(), 1);
        assert_eq!(roms.iter().next().map(Rom::bytes), Some(one[0].rom));

        let mut line = Line::new(&[]);
        let roms = block_on(search(&mut line)).unwrap();
        assert!(roms.is_empty());
        assert_eq!(roms.len(), 0);
    }

    #[test]
    fn a_search_takes_the_full_capacity_and_refuses_one_more() {
        let full: [Device; MAX_DEVICES] = core::array::from_fn(|n| {
            device(rom(
                0x28,
                [
                    u8::try_from(n).unwrap().checked_add(1).unwrap(),
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            ))
        });
        let mut line = Line::new(&full);
        assert_eq!(block_on(search(&mut line)).unwrap().len(), MAX_DEVICES);

        let over: [Device; MAX_DEVICES + 1] = core::array::from_fn(|n| {
            device(rom(
                0x28,
                [
                    u8::try_from(n).unwrap().checked_add(1).unwrap(),
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            ))
        });
        let mut line = Line::new(&over);
        assert_eq!(block_on(search(&mut line)), Err(SearchError::TooMany));
    }

    #[test]
    fn a_device_unplugged_between_passes_is_lost_not_a_second_copy_of_another() {
        // The two differ first at bit 8, where the first pass takes the
        // zero and finds `kept`; `leaving` is gone before the second pass,
        // which then walks back down to `kept`.
        let kept = rom(0x28, [0x10, 0, 0, 0, 0, 0]);
        let leaving = rom(0x28, [0x11, 0, 0, 0, 0, 0]);
        let devices = [
            device(kept),
            Device {
                leaves_after: Some(1),
                ..device(leaving)
            },
        ];
        let mut line = Line::new(&devices);
        assert_eq!(block_on(search(&mut line)), Err(SearchError::Lost));
        assert_eq!(line.resets, 2);
        // With both staying, the same line finds both.
        let both = [device(kept), device(leaving)];
        assert_eq!(
            block_on(search(&mut Line::new(&both))).map(|roms| roms.len()),
            Ok(2)
        );
    }

    #[test]
    fn a_device_that_vanishes_mid_search_is_lost_not_a_rom() {
        let devices = [Device {
            vanish_at: Some(20),
            ..device(rom(0x28, [1, 2, 3, 4, 5, 6]))
        }];
        let mut line = Line::new(&devices);
        assert_eq!(block_on(search(&mut line)), Err(SearchError::Lost));
    }

    #[test]
    fn a_search_that_assembles_a_bad_rom_or_hits_a_line_fault_is_refused() {
        let mut bad = rom(0x28, [1, 2, 3, 4, 5, 6]);
        bad[7] ^= 1;
        let devices = [device(bad)];
        let mut line = Line::new(&devices);
        assert_eq!(
            block_on(search(&mut line)),
            Err(SearchError::Rom(RomError::Crc))
        );

        let devices = [device(rom(0x28, [1, 2, 3, 4, 5, 6]))];
        let mut line = Line::new(&devices);
        line.fault = true;
        assert_eq!(block_on(search(&mut line)), Err(SearchError::Line(HeldLow)));
    }
}
