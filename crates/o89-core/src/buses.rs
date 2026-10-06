//! `0x0003 buses and devices`, as the controller keeps it: the section a
//! client wrote, in its canonical encoding, beside the next device id it
//! will give, in one A/B record (P-102, P-262).
//!
//! Decoding the body checks what the bytes can say and km43's
//! [`BusesAndDevicesWrite::accept`] what the board and the dialect table
//! can; what only the drivers know, such as whether a site's signals fit
//! the store, is a check the firmware hands in as a [`BusesCheck`], because
//! the dialects are `o89-drivers`', which depends on this crate and not the
//! other way round. Without one the section is not served at all.
//!
//! cites: P-100, P-102, P-262, P-265

use km43::{
    BusesAndDevicesKey, BusesAndDevicesRead, BusesAndDevicesWrite, ConfigError, DevAllocator,
    DevId, MAX_BUSES_AND_DEVICES_BYTES, SectionKey, SiteRules,
};

use crate::body::{Reader, Writer};
use crate::{Body, Malformed};

/// The record's layout. A record of another layout is not read.
const FORMAT: u8 = 1;

pub use crate::map::BUSES_RECORD_BYTES;

/// What the firmware checks a section against beyond what km43 can.
#[derive(Debug, Clone, Copy)]
pub struct BusesCheck {
    /// The board's buses, the dialects the firmware drives and the caps it
    /// reports.
    pub rules: &'static SiteRules<'static>,
    /// Everything else the firmware would refuse when it builds the site
    /// from the section: run on the section a write would store, so a
    /// section that is accepted is one the next boot can build.
    pub plan: fn(&BusesAndDevicesRead<'_>) -> Result<(), ConfigError>,
}

/// The section as the FRAM keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusesRecord {
    version: u32,
    next: Option<DevId>,
    len: u16,
    bytes: [u8; MAX_BUSES_AND_DEVICES_BYTES],
}

impl BusesRecord {
    /// A section accepted at `version`, with the allocator after it.
    fn new(
        version: u32,
        section: &BusesAndDevicesRead<'_>,
        allocator: DevAllocator,
    ) -> Result<Self, ConfigError> {
        let mut bytes = [0; MAX_BUSES_AND_DEVICES_BYTES];
        let len = section.encode(&mut bytes)?;
        Ok(Self {
            version,
            next: allocator.next(),
            len: u16::try_from(len).map_err(|_| ConfigError::Length {
                key: SectionKey::BusesAndDevices(BusesAndDevicesKey::Devices),
                len,
            })?,
            bytes,
        })
    }

    /// Its version, never 0.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The body, as a `Config` answer carries it.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The section it holds.
    pub fn section(&self) -> Result<BusesAndDevicesRead<'_>, ConfigError> {
        BusesAndDevicesRead::decode(self.body())
    }

    /// Where the next device id comes from.
    #[must_use]
    pub const fn allocator(&self) -> DevAllocator {
        DevAllocator::resume(self.next)
    }
}

impl Body<BUSES_RECORD_BYTES> for BusesRecord {
    fn encode(&self) -> [u8; BUSES_RECORD_BYTES] {
        let mut bytes = [0; BUSES_RECORD_BYTES];
        let mut writer = Writer::over(&mut bytes);
        writer.u8(FORMAT);
        writer.u32(self.version);
        writer.put(&self.next.map_or(0, DevId::get).to_le_bytes());
        writer.put(&self.len.to_le_bytes());
        writer.put(&self.bytes);
        bytes
    }

    /// Refuses another layout, version 0, a length past the body, and a
    /// body km43 does not read as a section: a record nobody can serve is
    /// not served.
    fn decode(bytes: &[u8; BUSES_RECORD_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        if reader.u8()? != FORMAT {
            return Err(Malformed { at: 0 });
        }
        let version = reader.u32()?;
        let next = DevId::new(u16::from_le_bytes(reader.take()?)).ok();
        let len = u16::from_le_bytes(reader.take()?);
        let record = Self {
            version,
            next,
            len,
            bytes: reader.take()?,
        };
        if version == 0 || usize::from(len) > MAX_BUSES_AND_DEVICES_BYTES {
            return Err(Malformed { at: 1 });
        }
        record.section().map_err(|_| Malformed { at: 9 })?;
        Ok(record)
    }
}

/// The record a write of `body` over `held` stores at `version`, or why it
/// is refused and nothing is stored.
///
/// `held` is `None` when no readable section is held. An absent record
/// gives ids from 1; a damaged one has no knowable next id, so a write that
/// adds a device is refused rather than handed an id the lost section may
/// have given (P-262).
pub(crate) fn change(
    check: &BusesCheck,
    held: Held<'_>,
    version: u32,
    body: &[u8],
) -> Result<BusesRecord, ConfigError> {
    let write = BusesAndDevicesWrite::decode(body)?;
    let (section, allocator) = match held {
        Held::Absent => (BusesAndDevicesRead::EMPTY, DevAllocator::FIRST),
        Held::Damaged => (BusesAndDevicesRead::EMPTY, DevAllocator::resume(None)),
        Held::Present(record) => (record.section()?, record.allocator()),
    };
    let accepted = write.accept(check.rules, &section, allocator)?;
    (check.plan)(&accepted.section)?;
    BusesRecord::new(version, &accepted.section, accepted.allocator)
}

/// What the controller holds of the section before a write.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Held<'a> {
    /// Never written.
    Absent,
    /// Written, and unreadable now.
    Damaged,
    /// This.
    Present(&'a BusesRecord),
}

#[cfg(test)]
mod tests {
    use super::*;
    use km43::{
        BoardBus, DeviceEntry, DeviceOptions, DeviceRole, Dialect, DialectRule, Product, Transport,
    };

    const BUSES: [BoardBus; 2] = [
        BoardBus {
            bus: 0,
            transport: Transport::LocalIo,
        },
        BoardBus {
            bus: 2,
            transport: Transport::Rs485,
        },
    ];
    const DIALECTS: [DialectRule<'static>; 1] = [DialectRule {
        dialect: Dialect::PZEM_DC,
        transports: &[Transport::Rs485],
        options: &[],
        min_poll_ms: 0,
    }];
    static RULES: SiteRules<'static> = SiteRules {
        buses: &BUSES,
        dialects: &DIALECTS,
        max_devices: 2,
        max_topology_depth: 4,
    };

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the check's signature, which a refusing check needs"
    )]
    fn accept_all(_: &BusesAndDevicesRead<'_>) -> Result<(), ConfigError> {
        Ok(())
    }

    fn refuse_all(_: &BusesAndDevicesRead<'_>) -> Result<(), ConfigError> {
        Err(ConfigError::DevsExhausted)
    }

    const CHECK: BusesCheck = BusesCheck {
        rules: &RULES,
        plan: accept_all,
    };

    fn meter(dev: Option<DevId>, addr: &[u8]) -> DeviceEntry<'_, Option<DevId>> {
        DeviceEntry {
            dev,
            bus: 2,
            addr: Some(km43::Addr::new(addr).expect("an address")),
            product: Product::PZEM_017,
            dialect: Dialect::PZEM_DC,
            role: DeviceRole::ENERGY_METER,
            parent: None,
            options: DeviceOptions::NONE,
        }
    }

    fn body(devices: &[DeviceEntry<'_, Option<DevId>>], out: &mut [u8]) -> usize {
        let mut write = BusesAndDevicesWrite::EMPTY;
        for device in devices {
            write.push_device(*device).expect("room");
        }
        write.encode(out).expect("encodes")
    }

    #[test]
    fn p_262_a_first_write_gives_ids_from_one_and_stores_the_next() {
        let mut out = [0; MAX_BUSES_AND_DEVICES_BYTES];
        let len = body(&[meter(None, &[1]), meter(None, &[2])], &mut out);
        let record = change(&CHECK, Held::Absent, 1, &out[..len]).expect("stored");
        assert_eq!(record.version(), 1);
        let devs: [Option<u16>; 2] = {
            let section = record.section().expect("readable");
            let mut devs = [None; 2];
            for (slot, device) in devs.iter_mut().zip(section.devices()) {
                *slot = Some(device.dev.get());
            }
            devs
        };
        assert_eq!(devs, [Some(1), Some(2)]);
        assert_eq!(record.allocator().next(), DevId::new(3).ok());
        let encoded = record.encode();
        assert_eq!(BusesRecord::decode(&encoded), Ok(record));
    }

    #[test]
    fn p_262_a_damaged_section_refuses_an_added_device_and_keeps_an_empty_one() {
        let mut out = [0; MAX_BUSES_AND_DEVICES_BYTES];
        let len = body(&[meter(None, &[1])], &mut out);
        assert_eq!(
            change(&CHECK, Held::Damaged, 1, &out[..len]),
            Err(ConfigError::DevsExhausted)
        );
        let len = body(&[], &mut out);
        let record = change(&CHECK, Held::Damaged, 1, &out[..len]).expect("stored");
        assert_eq!(record.allocator().next(), None);
    }

    #[test]
    fn p_265_the_firmware_s_own_check_refuses_what_km43_accepts() {
        let mut out = [0; MAX_BUSES_AND_DEVICES_BYTES];
        let len = body(&[meter(None, &[1])], &mut out);
        let refusing = BusesCheck {
            rules: &RULES,
            plan: refuse_all,
        };
        assert_eq!(
            change(&refusing, Held::Absent, 1, &out[..len]),
            Err(ConfigError::DevsExhausted)
        );
        // A device on a bus the board does not have is km43's refusal.
        let mut stray = meter(None, &[1]);
        stray.bus = 3;
        let len = body(&[stray], &mut out);
        assert_eq!(
            change(&CHECK, Held::Absent, 1, &out[..len]),
            Err(ConfigError::UnknownBus(3))
        );
    }

    #[test]
    fn p_262_an_edit_keeps_its_id_and_an_unknown_one_is_refused() {
        let mut out = [0; MAX_BUSES_AND_DEVICES_BYTES];
        let len = body(&[meter(None, &[1])], &mut out);
        let first = change(&CHECK, Held::Absent, 1, &out[..len]).expect("stored");
        let one = DevId::new(1).ok();
        let len = body(&[meter(one, &[5]), meter(None, &[6])], &mut out);
        let second = change(&CHECK, Held::Present(&first), 2, &out[..len]).expect("stored");
        assert_eq!(second.allocator().next(), DevId::new(3).ok());
        let len = body(&[meter(DevId::new(9).ok(), &[5])], &mut out);
        assert_eq!(
            change(&CHECK, Held::Present(&second), 3, &out[..len]),
            Err(ConfigError::UnknownDev(9))
        );
    }

    #[test]
    fn a_record_of_another_layout_or_version_zero_is_not_read() {
        let mut out = [0; MAX_BUSES_AND_DEVICES_BYTES];
        let len = body(&[meter(None, &[1])], &mut out);
        let record = change(&CHECK, Held::Absent, 1, &out[..len]).expect("stored");
        let mut bytes = record.encode();
        bytes[0] = FORMAT + 1;
        assert_eq!(BusesRecord::decode(&bytes), Err(Malformed { at: 0 }));
        let mut bytes = record.encode();
        bytes[1..5].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(BusesRecord::decode(&bytes), Err(Malformed { at: 1 }));
        let mut bytes = record.encode();
        bytes[9] ^= 0xFF;
        assert_eq!(BusesRecord::decode(&bytes), Err(Malformed { at: 9 }));
    }
}
