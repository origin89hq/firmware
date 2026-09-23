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

    /// Encode only the read shape. A damaged record is never reported unwritten.
    pub fn answer(
        &self,
        section: ConfigSection,
        network: &Kept<Network, NETWORK_BYTES>,
        dst: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let mut bytes = [0; km43::MAX_NETWORK_READ_BYTES];
        let (version, body) = match section {
            ConfigSection::IdentityAndSite => shown(&self.identity)?,
            ConfigSection::GeneratorBehaviour => shown(&self.generator)?,
            ConfigSection::FrostBehaviour => shown(&self.frost)?,
            ConfigSection::ScheduleBehaviour => shown(&self.schedule)?,
            ConfigSection::LoadShedBehaviour => shown(&self.load_shed)?,
            ConfigSection::Network => match network.held() {
                Held::Absent => (0, None),
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
                Held::Corrupt | Held::Malformed(_) => return Err(ErrorCode::BusyRetry),
            },
            ConfigSection::Channels | ConfigSection::BusesAndDevices | ConfigSection::Cloud => {
                return Err(ErrorCode::UnknownSection);
            }
        };
        ConfigAnswer::new(section, version, body)
            .and_then(|answer| answer.encode(dst))
            .map_err(|_| ErrorCode::BusyRetry)
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
                    Held::Absent => Network::NONE,
                    Held::Corrupt | Held::Malformed(_) => return Err(ErrorCode::BusyRetry),
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
fn shown<const N: usize, const M: usize>(
    record: &Kept<Section<N>, M>,
) -> Result<(u32, Option<&[u8]>), ErrorCode> {
    match record.held() {
        Held::Absent => Ok((0, None)),
        Held::Present(value) => Ok((value.version, Some(value.body()))),
        Held::Corrupt | Held::Malformed(_) => Err(ErrorCode::BusyRetry),
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
    let (version, _) = shown(record)?;
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
