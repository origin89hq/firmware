//! Versioned configuration sections. Every accepted write commits its inactive
//! slot before publishing the new RAM value (P-100 to P-103).
use crate::body::{Reader, Writer};
use crate::buses::{self, BUSES_RECORD_BYTES, BusesCheck, BusesRecord};
use crate::{Body, Fram, Generator, Held, Kept, Malformed, NETWORK_BYTES, Network, map};
use km43::{
    BehaviourSection, ConfigAnswer, ConfigSection, ErrorCode, IdentitySection, SectionRefusal,
    SetConfig, SetConfigAck, SetConfigOperation,
};

/// Version and length followed by the protocol's maximum identity body.
pub const IDENTITY_RECORD_BYTES: usize = 5 + km43::MAX_IDENTITY_BYTES;
/// Version and length followed by the protocol's maximum behaviour body.
pub const BEHAVIOUR_RECORD_BYTES: usize = 5 + km43::MAX_BEHAVIOUR_BYTES;

/// The widest body any section answers with: the network's or the buses
/// and devices'.
pub const MAX_SECTION_READ_BYTES: usize =
    if km43::MAX_NETWORK_READ_BYTES > km43::MAX_BUSES_AND_DEVICES_BYTES {
        km43::MAX_NETWORK_READ_BYTES
    } else {
        km43::MAX_BUSES_AND_DEVICES_BYTES
    };

/// Canonical CBOR, bounded by its section schema; oversized bodies are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Section<const N: usize> {
    version: u32,
    len: u8,
    bytes: [u8; N],
}
impl<const N: usize, const M: usize> Body<M> for Section<N> {
    fn encode(&self) -> [u8; M] {
        let mut bytes = [0; M];
        let mut writer = Writer::over(&mut bytes);
        writer.u32(self.version);
        writer.u8(self.len);
        writer.put(&self.bytes);
        bytes
    }
    fn decode(bytes: &[u8; M]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let version = reader.u32()?;
        let len = reader.u8()?;
        if version == 0 || usize::from(len) > N {
            return Err(Malformed { at: 0 });
        }
        Ok(Self {
            version,
            len,
            bytes: reader.take()?,
        })
    }
}
impl<const N: usize> Section<N> {
    fn body(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

type Identity = Kept<Section<{ km43::MAX_IDENTITY_BYTES }>, IDENTITY_RECORD_BYTES>;
type Behaviour = Kept<Section<{ km43::MAX_BEHAVIOUR_BYTES }>, BEHAVIOUR_RECORD_BYTES>;

/// The buses and devices record.
pub type Buses = Kept<BusesRecord, BUSES_RECORD_BYTES>;

/// The currently implemented section records; the network stays the master copy.
pub struct Configuration {
    identity: Identity,
    generator: Behaviour,
    frost: Behaviour,
    schedule: Behaviour,
    load_shed: Behaviour,
    buses: Buses,
    /// What a buses and devices write is checked against; none, and the
    /// section is not served.
    buses_check: Option<BusesCheck>,
}

impl Configuration {
    /// Read each schema's prefix without allocating its whole FRAM reservation.
    pub async fn read<F: Fram>(fram: &mut F) -> Result<Self, F::Error> {
        Ok(Self {
            identity: Kept::read(map::SITE_CONFIG.prefix(), fram).await?,
            generator: Kept::read(map::GENERATOR_CONFIG.prefix(), fram).await?,
            frost: Kept::read(map::FROST_CONFIG.prefix(), fram).await?,
            schedule: Kept::read(map::SCHEDULE_CONFIG.prefix(), fram).await?,
            load_shed: Kept::read(map::LOAD_SHED_CONFIG.prefix(), fram).await?,
            buses: Kept::read(map::BUSES_CONFIG, fram).await?,
            buses_check: None,
        })
    }

    /// Serve `0x0003 buses and devices`, checking every write against
    /// `check` as well as against km43's rules.
    pub fn check_buses_with(&mut self, check: BusesCheck) {
        self.buses_check = Some(check);
    }

    /// The buses and devices section as the boot read it, or as the last
    /// accepted write left it.
    #[must_use]
    pub const fn buses(&self) -> &Buses {
        &self.buses
    }

    /// Encode the read shape; unreadable records answer as unwritten (P-108).
    pub fn answer(
        &self,
        section: ConfigSection,
        network: &Kept<Network, NETWORK_BYTES>,
        dst: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let mut bytes = [0; km43::MAX_NETWORK_READ_BYTES];
        let (version, body) = match section {
            ConfigSection::IdentityAndSite => shown(&self.identity),
            ConfigSection::GeneratorBehaviour => shown(&self.generator),
            ConfigSection::FrostBehaviour => shown(&self.frost),
            ConfigSection::ScheduleBehaviour => shown(&self.schedule),
            ConfigSection::LoadShedBehaviour => shown(&self.load_shed),
            ConfigSection::Network => match network.held() {
                Held::Absent | Held::Corrupt | Held::Malformed(_) => (0, None),
                Held::Present(value) => {
                    let len = value
                        .read_body()
                        .and_then(|body| body.encode(&mut bytes))
                        .map_err(|_| ErrorCode::BusyRetry)?;
                    (
                        value.version(),
                        Some(bytes.get(..len).ok_or(ErrorCode::BusyRetry)?),
                    )
                }
            },
            ConfigSection::BusesAndDevices => {
                if self.buses_check.is_none() {
                    return Err(ErrorCode::UnknownSection);
                }
                match self.buses.held() {
                    Held::Absent | Held::Corrupt | Held::Malformed(_) => (0, None),
                    Held::Present(record) => (record.version(), Some(record.body())),
                }
            }
            ConfigSection::Channels | ConfigSection::Cloud => {
                return Err(ErrorCode::UnknownSection);
            }
        };
        ConfigAnswer::new(section, version, body)
            .and_then(|answer| answer.encode(dst))
            .map_err(|_| ErrorCode::BusyRetry)
    }

    /// Known version for a refused write; zero when no version can be read.
    pub(crate) fn version(
        &self,
        section: ConfigSection,
        network: &Kept<Network, NETWORK_BYTES>,
    ) -> u32 {
        match section {
            ConfigSection::IdentityAndSite => {
                self.identity.present().map_or(0, |value| value.version)
            }
            ConfigSection::GeneratorBehaviour => {
                self.generator.present().map_or(0, |value| value.version)
            }
            ConfigSection::FrostBehaviour => self.frost.present().map_or(0, |value| value.version),
            ConfigSection::ScheduleBehaviour => {
                self.schedule.present().map_or(0, |value| value.version)
            }
            ConfigSection::LoadShedBehaviour => {
                self.load_shed.present().map_or(0, |value| value.version)
            }
            ConfigSection::Network => network.present().map_or(0, Network::version),
            ConfigSection::BusesAndDevices => self.buses.present().map_or(0, BusesRecord::version),
            ConfigSection::Channels | ConfigSection::Cloud => 0,
        }
    }

    /// Apply an operation only after request admission has persisted its counter.
    /// Version comparison precedes every section decoder (P-100). A network
    /// write that creates the section, from nothing or over a damaged one,
    /// draws its origin token from `generator` once it is valid, and a draw
    /// that fails writes nothing and answers `BusyRetry` (L-138).
    pub async fn set<F: Fram>(
        &mut self,
        operation: SetConfigOperation<'_>,
        network: &mut Kept<Network, NETWORK_BYTES>,
        generator: &mut Generator,
        fram: &mut F,
    ) -> Result<SetConfigAck, ErrorCode> {
        match operation.section {
            ConfigSection::IdentityAndSite => {
                save(&mut self.identity, operation, fram, |body, dst| {
                    IdentitySection::decode(body)?.encode(dst)
                })
                .await
            }
            ConfigSection::GeneratorBehaviour => {
                save_behaviour(&mut self.generator, operation, fram).await
            }
            ConfigSection::FrostBehaviour => save_behaviour(&mut self.frost, operation, fram).await,
            ConfigSection::ScheduleBehaviour => {
                save_behaviour(&mut self.schedule, operation, fram).await
            }
            ConfigSection::LoadShedBehaviour => {
                save_behaviour(&mut self.load_shed, operation, fram).await
            }
            ConfigSection::Network => {
                let current = match network.held() {
                    Held::Present(value) => *value,
                    Held::Absent | Held::Corrupt | Held::Malformed(_) => Network::NONE,
                };
                let version = current.version();
                if let Err(outcome) = operation.check_version(version) {
                    return Ok(ack(operation, version, outcome));
                }
                if version == u32::MAX {
                    return Ok(ack(operation, version, SetConfig::ExceedsCap));
                }
                let next = match km43::NetworkWrite::decode(operation.body)
                    .map_err(crate::NetworkChangeError::Invalid)
                    .and_then(|write| current.changed(write))
                {
                    Ok(crate::NetworkChange::Edit(next)) => next,
                    Ok(crate::NetworkChange::Create(created)) => created.originate(
                        generator
                            .origin(fram)
                            .await
                            .map_err(|crate::Unavailable| ErrorCode::BusyRetry)?,
                    ),
                    Err(crate::NetworkChangeError::Invalid(why)) => {
                        return invalid(operation, version, why);
                    }
                    Err(crate::NetworkChangeError::VersionCeiling) => {
                        return Ok(ack(operation, version, SetConfig::ExceedsCap));
                    }
                };
                network
                    .write(fram, next)
                    .await
                    .map_err(|_| ErrorCode::BusyRetry)?;
                Ok(ack(operation, next.version(), SetConfig::Accepted))
            }
            ConfigSection::BusesAndDevices => self.set_buses(operation, fram).await,
            ConfigSection::Channels | ConfigSection::Cloud => Err(ErrorCode::UnknownSection),
        }
    }

    /// A buses and devices write: the version first (P-100), then km43's
    /// checks and the firmware's, then the record with the next device id
    /// in it, or nothing (P-102, P-262).
    async fn set_buses<F: Fram>(
        &mut self,
        operation: SetConfigOperation<'_>,
        fram: &mut F,
    ) -> Result<SetConfigAck, ErrorCode> {
        let check = self.buses_check.ok_or(ErrorCode::UnknownSection)?;
        let (version, held) = match self.buses.held() {
            Held::Absent => (0, buses::Held::Absent),
            Held::Corrupt | Held::Malformed(_) => (0, buses::Held::Damaged),
            Held::Present(record) => (record.version(), buses::Held::Present(record)),
        };
        if let Err(outcome) = operation.check_version(version) {
            return Ok(ack(operation, version, outcome));
        }
        let Some(next) = version.checked_add(1) else {
            return Ok(ack(operation, version, SetConfig::ExceedsCap));
        };
        let record = match buses::change(&check, held, next, operation.body) {
            Ok(record) => record,
            Err(why) => return invalid(operation, version, why),
        };
        self.buses
            .write(fram, record)
            .await
            .map_err(|_| ErrorCode::BusyRetry)?;
        Ok(ack(operation, next, SetConfig::Accepted))
    }
}
fn shown<const N: usize, const M: usize>(record: &Kept<Section<N>, M>) -> (u32, Option<&[u8]>) {
    match record.held() {
        Held::Absent | Held::Corrupt | Held::Malformed(_) => (0, None),
        Held::Present(value) => (value.version, Some(value.body())),
    }
}
fn ack(operation: SetConfigOperation<'_>, version: u32, outcome: SetConfig) -> SetConfigAck {
    SetConfigAck {
        section: operation.section,
        version,
        outcome,
    }
}
fn invalid(
    operation: SetConfigOperation<'_>,
    version: u32,
    why: km43::ConfigError,
) -> Result<SetConfigAck, ErrorCode> {
    match why.answer() {
        SectionRefusal::Error(code) => Err(code),
        SectionRefusal::Outcome(outcome) => Ok(ack(operation, version, outcome)),
    }
}
async fn save_behaviour<F: Fram>(
    record: &mut Behaviour,
    operation: SetConfigOperation<'_>,
    fram: &mut F,
) -> Result<SetConfigAck, ErrorCode> {
    save(record, operation, fram, |body, dst| {
        BehaviourSection::decode(body)?.encode(dst)
    })
    .await
}
async fn save<F: Fram, const N: usize, const M: usize>(
    record: &mut Kept<Section<N>, M>,
    operation: SetConfigOperation<'_>,
    fram: &mut F,
    encode: impl FnOnce(&[u8], &mut [u8]) -> Result<usize, km43::ConfigError>,
) -> Result<SetConfigAck, ErrorCode> {
    // A damaged section has no knowable version; only an explicit zero can replace it.
    let version = record.present().map_or(0, |value| value.version);
    if let Err(outcome) = operation.check_version(version) {
        return Ok(ack(operation, version, outcome));
    }
    let Some(next) = version.checked_add(1) else {
        return Ok(ack(operation, version, SetConfig::ExceedsCap));
    };
    let mut bytes = [0; N];
    let len = match encode(operation.body, &mut bytes) {
        Ok(len) => len,
        Err(why) => return invalid(operation, version, why),
    };
    let len = u8::try_from(len).map_err(|_| ErrorCode::BusyRetry)?;
    record
        .write(
            fram,
            Section {
                version: next,
                len,
                bytes,
            },
        )
        .await
        .map_err(|_| ErrorCode::BusyRetry)?;
    Ok(ack(operation, next, SetConfig::Accepted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, Position, Refused};
    use embassy_futures::block_on;

    struct Part([u8; crate::FRAM_BYTES]);
    impl Fram for Part {
        type Error = ();
        fn read(
            &mut self,
            at: Address,
            into: &mut [u8],
        ) -> impl core::future::Future<Output = Result<(), ()>> {
            into.copy_from_slice(&self.0[usize::from(at.0)..][..into.len()]);
            core::future::ready(Ok(()))
        }
        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl core::future::Future<Output = Result<(), Refused<()>>> {
            self.0[usize::from(at.0)..][..bytes.len()].copy_from_slice(bytes);
            core::future::ready(Ok(()))
        }
    }

    #[expect(
        clippy::large_stack_arrays,
        reason = "The host fixture models bounded FRAM without an allocator, including unused reservations."
    )]
    fn damaged_part(malformed: bool) -> Part {
        let mut part = Part([0x42; crate::FRAM_BYTES]);
        if malformed {
            let _ =
                block_on(map::NETWORK.write(&mut part, Position::Start, &[0x42; NETWORK_BYTES]))
                    .expect("network");
            let _ = block_on(map::SITE_CONFIG.prefix().write(
                &mut part,
                Position::Start,
                &[0x42; IDENTITY_RECORD_BYTES],
            ))
            .expect("identity");
            for record in [
                map::GENERATOR_CONFIG,
                map::FROST_CONFIG,
                map::SCHEDULE_CONFIG,
                map::LOAD_SHED_CONFIG,
            ] {
                let _ = block_on(record.prefix().write(
                    &mut part,
                    Position::Start,
                    &[0x42; BEHAVIOUR_RECORD_BYTES],
                ))
                .expect("behaviour");
            }
        }
        part
    }

    /// The generator over a state the station wrote onto `part` (P-237).
    fn seeded(part: &mut Part) -> Generator {
        let mut kept = block_on(Kept::read(map::DRBG, part)).expect("drbg");
        block_on(kept.write(part, crate::DrbgState::new([0x61; 32]).expect("entropy")))
            .expect("seeded");
        Generator::new(kept)
    }

    fn network_write(ssid: &str, body: &mut [u8]) -> usize {
        km43::NetworkWrite {
            join: Some(km43::JoinWrite {
                ssid: km43::Ssid::new(ssid).expect("ssid"),
                psk: Some(km43::Passphrase::new("correct horse").expect("psk")),
            }),
            country: km43::Country::new("CA").expect("country"),
            hostname: km43::Hostname::new("origin89").expect("host"),
        }
        .encode(body)
        .expect("network")
    }

    fn network_set(expected_version: u32, body: &[u8]) -> SetConfigOperation<'_> {
        SetConfigOperation {
            section: ConfigSection::Network,
            expected_version,
            body,
        }
    }

    #[test]
    fn l_138_the_first_write_draws_the_token_and_later_writes_keep_it() {
        let mut part = damaged_part(false);
        let mut config = block_on(Configuration::read(&mut part)).expect("config");
        let mut network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
        let mut generator = seeded(&mut part);
        let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
        let len = network_write("cabin", &mut body);
        let before = generator_bytes(&part);
        let ack = block_on(config.set(
            network_set(0, &body[..len]),
            &mut network,
            &mut generator,
            &mut part,
        ))
        .expect("first write");
        assert_eq!((ack.version, ack.outcome), (1, SetConfig::Accepted));
        assert_ne!(generator_bytes(&part), before, "the token is a draw");
        let origin = network.present().and_then(Network::origin).expect("token");
        let drawn = generator_bytes(&part);
        let len = network_write("cabin-2", &mut body);
        let ack = block_on(config.set(
            network_set(1, &body[..len]),
            &mut network,
            &mut generator,
            &mut part,
        ))
        .expect("edit");
        assert_eq!((ack.version, ack.outcome), (2, SetConfig::Accepted));
        assert_eq!(network.present().and_then(Network::origin), Some(origin));
        assert_eq!(generator_bytes(&part), drawn, "an edit draws nothing");
        let reread = block_on(Kept::<Network, NETWORK_BYTES>::read(
            map::NETWORK,
            &mut part,
        ))
        .expect("network");
        assert_eq!(reread.present().and_then(Network::origin), Some(origin));
    }

    #[test]
    fn l_138_a_repair_draws_a_token_the_damaged_section_never_had() {
        let mut part = damaged_part(false);
        let mut config = block_on(Configuration::read(&mut part)).expect("config");
        let mut network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
        let mut generator = seeded(&mut part);
        let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
        let len = network_write("cabin", &mut body);
        let _ = block_on(config.set(
            network_set(0, &body[..len]),
            &mut network,
            &mut generator,
            &mut part,
        ))
        .expect("first write");
        let first = network.present().and_then(Network::origin).expect("token");
        // Both copies of the section damaged: it reads as never written.
        let _ = block_on(map::NETWORK.write(&mut part, Position::Start, &[0x42; NETWORK_BYTES]))
            .expect("damage");
        let _ = block_on(map::NETWORK.write(&mut part, Position::Start, &[0x42; NETWORK_BYTES]))
            .expect("damage");
        let mut network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
        assert!(network.present().is_none());
        let ack = block_on(config.set(
            network_set(0, &body[..len]),
            &mut network,
            &mut generator,
            &mut part,
        ))
        .expect("repair");
        assert_eq!((ack.version, ack.outcome), (1, SetConfig::Accepted));
        let repaired = network.present().and_then(Network::origin).expect("token");
        assert_ne!(repaired, first);
    }

    #[test]
    fn l_138_a_failed_draw_writes_nothing_and_answers_busy_until_the_generator_recovers() {
        let mut part = damaged_part(false);
        let mut config = block_on(Configuration::read(&mut part)).expect("config");
        let mut network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
        // The station never wrote a state: nothing to draw from.
        let mut generator =
            Generator::new(block_on(Kept::read(map::DRBG, &mut part)).expect("drbg"));
        assert!(!generator.is_available());
        let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
        let len = network_write("cabin", &mut body);
        let before = part.0;
        assert_eq!(
            block_on(config.set(
                network_set(0, &body[..len]),
                &mut network,
                &mut generator,
                &mut part,
            )),
            Err(ErrorCode::BusyRetry)
        );
        assert_eq!(part.0, before, "no section and no token");
        assert!(network.present().is_none());
        assert_eq!(config.version(ConfigSection::Network, &network), 0);
        // The station's reseed lands; the next draw starts from it.
        let mut kept = block_on(Kept::read(map::DRBG, &mut part)).expect("drbg");
        block_on(kept.write(
            &mut part,
            crate::DrbgState::new([0x61; 32]).expect("entropy"),
        ))
        .expect("reseeded");
        let ack = block_on(config.set(
            network_set(0, &body[..len]),
            &mut network,
            &mut generator,
            &mut part,
        ))
        .expect("after recovery");
        assert_eq!((ack.version, ack.outcome), (1, SetConfig::Accepted));
        assert!(network.present().and_then(Network::origin).is_some());
    }

    /// The generator's record as the part holds it, both copies.
    fn generator_bytes(part: &Part) -> [u8; 256] {
        let held = &part.0[usize::from(map::DRBG.start().0)..usize::from(map::DRBG.end().0)];
        let mut out = [0; 256];
        out[..held.len()].copy_from_slice(held);
        out
    }

    #[test]
    fn p_108_p_100_unreadable_sections_read_zero_and_replace_only_at_zero() {
        for malformed in [false, true] {
            let mut part = damaged_part(malformed);
            let mut config = block_on(Configuration::read(&mut part)).expect("config");
            let mut network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
            let mut generator = seeded(&mut part);
            assert_eq!(matches!(network.held(), Held::Malformed(_)), malformed);
            assert_eq!(
                matches!(config.identity.held(), Held::Malformed(_)),
                malformed
            );
            assert_eq!(matches!(network.held(), Held::Corrupt), !malformed);
            for section in [
                ConfigSection::IdentityAndSite,
                ConfigSection::Network,
                ConfigSection::GeneratorBehaviour,
                ConfigSection::FrostBehaviour,
                ConfigSection::ScheduleBehaviour,
                ConfigSection::LoadShedBehaviour,
            ] {
                let before = part.0;
                let mut bytes = [0; 160];
                let len = config
                    .answer(section, &network, &mut bytes)
                    .expect("damaged read");
                let answer = ConfigAnswer::decode(&bytes[..len]).expect("answer");
                assert_eq!(
                    (answer.section(), answer.version(), answer.body()),
                    (section, 0, None)
                );
                let mut body = [0; km43::MAX_NETWORK_WRITE_BYTES];
                let len = match section {
                    ConfigSection::IdentityAndSite => {
                        body[..4].copy_from_slice(&[0xa1, 1, 0x61, b'a']);
                        4
                    }
                    ConfigSection::Network => km43::NetworkWrite {
                        join: None,
                        country: km43::Country::new("CA").expect("country"),
                        hostname: km43::Hostname::new("origin89").expect("host"),
                    }
                    .encode(&mut body)
                    .expect("network"),
                    ConfigSection::GeneratorBehaviour
                    | ConfigSection::FrostBehaviour
                    | ConfigSection::ScheduleBehaviour
                    | ConfigSection::LoadShedBehaviour => km43::BehaviourSection { shadow: true }
                        .encode(&mut body)
                        .expect("behaviour"),
                    ConfigSection::Channels
                    | ConfigSection::BusesAndDevices
                    | ConfigSection::Cloud => panic!("unsupported section"),
                };
                let operation = SetConfigOperation {
                    section,
                    expected_version: 1,
                    body: &body[..len],
                };
                let ack = block_on(config.set(operation, &mut network, &mut generator, &mut part))
                    .expect("stale ack");
                assert_eq!((ack.version, ack.outcome), (0, SetConfig::StaleVersion));
                assert_eq!(part.0, before, "read and stale write preserve damage");
                let ack = block_on(config.set(
                    SetConfigOperation {
                        expected_version: 0,
                        ..operation
                    },
                    &mut network,
                    &mut generator,
                    &mut part,
                ))
                .expect("repair");
                assert_eq!((ack.version, ack.outcome), (1, SetConfig::Accepted));
                let len = config
                    .answer(section, &network, &mut bytes)
                    .expect("repaired read");
                let answer = ConfigAnswer::decode(&bytes[..len]).expect("answer");
                assert_eq!((answer.version(), answer.body()), (1, Some(operation.body)));
            }
        }
    }

    mod buses_and_devices {
        use super::*;
        use km43::{
            Addr, BoardBus, BusesAndDevicesWrite, ConfigError, DevId, DeviceEntry, DeviceOptions,
            DeviceRole, Dialect, DialectRule, Product, SiteRules, Transport,
        };

        const BUSES: [BoardBus; 1] = [BoardBus {
            bus: 2,
            transport: Transport::Rs485,
        }];
        const DIALECTS: [DialectRule<'static>; 1] = [DialectRule {
            dialect: Dialect::PZEM_DC,
            transports: &[Transport::Rs485],
            options: &[],
            min_poll_ms: 0,
        }];
        static RULES: SiteRules<'static> = SiteRules {
            buses: &BUSES,
            dialects: &DIALECTS,
            max_devices: 4,
            max_topology_depth: 4,
        };

        #[expect(
            clippy::unnecessary_wraps,
            reason = "the check's signature, which a refusing check needs"
        )]
        fn accept(_: &km43::BusesAndDevicesRead<'_>) -> Result<(), ConfigError> {
            Ok(())
        }

        fn checked(part: &mut Part) -> Configuration {
            let mut config = block_on(Configuration::read(part)).expect("config");
            config.check_buses_with(BusesCheck {
                rules: &RULES,
                plan: accept,
            });
            config
        }

        fn body(addrs: &[u8], bus: u8, out: &mut [u8]) -> usize {
            let mut write = BusesAndDevicesWrite::EMPTY;
            for addr in addrs {
                write
                    .push_device(DeviceEntry {
                        dev: None,
                        bus,
                        addr: Some(Addr::new(core::slice::from_ref(addr)).expect("addr")),
                        product: Product::PZEM_017,
                        dialect: Dialect::PZEM_DC,
                        role: DeviceRole::ENERGY_METER,
                        parent: None,
                        options: DeviceOptions::NONE,
                    })
                    .expect("room");
            }
            write.encode(out).expect("encodes")
        }

        fn set(expected_version: u32, body: &[u8]) -> SetConfigOperation<'_> {
            SetConfigOperation {
                section: ConfigSection::BusesAndDevices,
                expected_version,
                body,
            }
        }

        fn write(
            config: &mut Configuration,
            part: &mut Part,
            operation: SetConfigOperation<'_>,
        ) -> Result<SetConfigAck, ErrorCode> {
            let mut network = block_on(Kept::read(map::NETWORK, part)).expect("network");
            let mut generator = seeded(part);
            block_on(config.set(operation, &mut network, &mut generator, part))
        }

        fn read(config: &Configuration, part: &mut Part) -> (u32, Option<[u8; 64]>, usize) {
            let network = block_on(Kept::read(map::NETWORK, part)).expect("network");
            let mut bytes = [0; km43::CONFIG_HEADER_BYTES + MAX_SECTION_READ_BYTES];
            let len = config
                .answer(ConfigSection::BusesAndDevices, &network, &mut bytes)
                .expect("answered");
            let answer = ConfigAnswer::decode(&bytes[..len]).expect("answer");
            let body = answer.body().map(|body| {
                let mut out = [0; 64];
                out[..body.len()].copy_from_slice(body);
                out
            });
            (answer.version(), body, answer.body().map_or(0, <[u8]>::len))
        }

        #[expect(
            clippy::large_stack_arrays,
            reason = "The host fixture models bounded FRAM without an allocator."
        )]
        fn blank() -> Part {
            Part([0; crate::FRAM_BYTES])
        }

        /// Whether the section's record is byte for byte what `before` held.
        fn untouched(part: &Part, before: &[u8; crate::FRAM_BYTES]) -> bool {
            let record =
                usize::from(map::BUSES_CONFIG.start().0)..usize::from(map::BUSES_CONFIG.end().0);
            part.0[record.clone()] == before[record]
        }

        #[test]
        fn the_section_is_unknown_until_the_firmware_checks_it() {
            let mut part = damaged_part(false);
            let mut config = block_on(Configuration::read(&mut part)).expect("config");
            let mut out = [0; 64];
            let len = body(&[1], 2, &mut out);
            assert_eq!(
                write(&mut config, &mut part, set(0, &out[..len])),
                Err(ErrorCode::UnknownSection)
            );
            let network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
            let mut bytes = [0; 64];
            assert_eq!(
                config.answer(ConfigSection::BusesAndDevices, &network, &mut bytes),
                Err(ErrorCode::UnknownSection)
            );
        }

        #[test]
        fn p_100_an_empty_site_then_a_valid_one_are_stored_and_read_back_after_a_reboot() {
            let mut part = blank();
            let mut config = checked(&mut part);
            assert_eq!(read(&config, &mut part), (0, None, 0));
            let mut out = [0; 64];
            let len = body(&[], 2, &mut out);
            let ack = write(&mut config, &mut part, set(0, &out[..len])).expect("ack");
            assert_eq!((ack.version, ack.outcome), (1, SetConfig::Accepted));
            let len = body(&[1, 2], 2, &mut out);
            let ack = write(&mut config, &mut part, set(1, &out[..len])).expect("ack");
            assert_eq!((ack.version, ack.outcome), (2, SetConfig::Accepted));
            let rebooted = checked(&mut part);
            let (version, held, held_len) = read(&rebooted, &mut part);
            assert_eq!(version, 2);
            let held = held.expect("a body");
            let section = km43::BusesAndDevicesRead::decode(&held[..held_len]).expect("read");
            let devs: [u16; 2] = {
                let mut devs = [0; 2];
                for (slot, device) in devs.iter_mut().zip(section.devices()) {
                    *slot = device.dev.get();
                }
                devs
            };
            assert_eq!(devs, [1, 2]);
            assert_eq!(
                rebooted
                    .buses()
                    .present()
                    .map(|record| record.allocator().next()),
                Some(DevId::new(3).ok())
            );
        }

        #[test]
        fn p_100_a_write_at_an_unknown_version_is_refused_and_stores_nothing() {
            let mut part = blank();
            let mut config = checked(&mut part);
            let mut out = [0; 64];
            let len = body(&[1], 2, &mut out);
            let before = part.0;
            let ack = write(&mut config, &mut part, set(7, &out[..len])).expect("ack");
            assert_eq!((ack.version, ack.outcome), (0, SetConfig::StaleVersion));
            assert!(untouched(&part, &before));
        }

        #[test]
        fn p_265_an_invalid_write_is_refused_and_stores_nothing() {
            let mut part = blank();
            let mut config = checked(&mut part);
            let mut out = [0; 64];
            // A device on a bus the board does not have.
            let len = body(&[1], 3, &mut out);
            let before = part.0;
            let ack = write(&mut config, &mut part, set(0, &out[..len])).expect("ack");
            assert_eq!((ack.version, ack.outcome), (0, SetConfig::Invalid));
            assert!(untouched(&part, &before));
            assert_eq!(read(&config, &mut part), (0, None, 0));
        }
    }
}
