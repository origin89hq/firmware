//! Versioned configuration sections. Every accepted write commits its inactive
//! slot before publishing the new RAM value (P-100 to P-103).
use crate::body::{Reader, Writer};
use crate::{Body, Fram, Held, Kept, Malformed, NETWORK_BYTES, Network, map};
use km43::{
    BehaviourSection, ConfigAnswer, ConfigSection, ErrorCode, IdentitySection, SectionRefusal,
    SetConfig, SetConfigAck, SetConfigOperation,
};

/// Version and length followed by the protocol's maximum identity body.
pub const IDENTITY_RECORD_BYTES: usize = 5 + km43::MAX_IDENTITY_BYTES;
/// Version and length followed by the protocol's maximum behaviour body.
pub const BEHAVIOUR_RECORD_BYTES: usize = 5 + km43::MAX_BEHAVIOUR_BYTES;

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

/// The currently implemented section records; the network stays the master copy.
pub struct Configuration {
    identity: Identity,
    generator: Behaviour,
    frost: Behaviour,
    schedule: Behaviour,
    load_shed: Behaviour,
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
        })
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
            ConfigSection::Channels | ConfigSection::BusesAndDevices | ConfigSection::Cloud => {
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
            ConfigSection::Channels | ConfigSection::BusesAndDevices | ConfigSection::Cloud => 0,
        }
    }

    /// Apply an operation only after request admission has persisted its counter.
    /// Version comparison precedes every section decoder (P-100).
    pub async fn set<F: Fram>(
        &mut self,
        operation: SetConfigOperation<'_>,
        network: &mut Kept<Network, NETWORK_BYTES>,
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
                    Ok(next) => next,
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
            ConfigSection::Channels | ConfigSection::BusesAndDevices | ConfigSection::Cloud => {
                Err(ErrorCode::UnknownSection)
            }
        }
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

    #[test]
    fn p_108_p_100_unreadable_sections_read_zero_and_replace_only_at_zero() {
        for malformed in [false, true] {
            let mut part = damaged_part(malformed);
            let mut config = block_on(Configuration::read(&mut part)).expect("config");
            let mut network = block_on(Kept::read(map::NETWORK, &mut part)).expect("network");
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
                let ack =
                    block_on(config.set(operation, &mut network, &mut part)).expect("stale ack");
                assert_eq!((ack.version, ack.outcome), (0, SetConfig::StaleVersion));
                assert_eq!(part.0, before, "read and stale write preserve damage");
                let ack = block_on(config.set(
                    SetConfigOperation {
                        expected_version: 0,
                        ..operation
                    },
                    &mut network,
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
}
