//! The client table as P-239 keeps it: eight slots, each a key record in
//! two copies and a generation mark beside it.
//!
//! **A slot is occupied only if its record reads, says occupied, and was
//! written under the current epoch.** Everything else is free, and a free
//! slot's key is matched by nothing. So a factory reset commits with the
//! one epoch write (P-085): the slots it leaves behind are free the moment
//! the epoch lands, and clearing them afterwards is housekeeping.
//!
//! **A re-key writes the slot free first.** FRAM commits byte by byte, so
//! a record rewritten in place and cut between the label and the key would
//! leave the stolen install's key under the new label. Instead the
//! generation mark is raised and read back, the slot is written free under
//! that generation and read back, the slot's dedup entries are forgotten,
//! and only then is the new record written and read back. A cut anywhere
//! leaves the old enrolment or a free slot, never half of each; and the
//! record copies are the `Record`'s two, the write always to the older.
//!
//! **A generation is never issued twice under an epoch.** The mark is the
//! highest a slot has issued; one that cannot be read back makes the table
//! corrupt, and the boot repairs it to empty under a new epoch (P-239), so
//! `(epoch, client_id, generation)` names one enrolment and never a second.
//!
//! Every slot carries the key its client proved at message 3, the
//! admission key computed from it then (P-238), the suite it paired under,
//! and its role (P-250), all fixed until the next re-key. The mask is the
//! role's row and is never stored (P-105): `client_kind` is kept to be
//! shown and decides nothing. Nothing here runs a handshake; `km43` did
//! that before anything in this file is asked.
//!
//! **Which slot a pairing gets is decided here** (P-240), with the role
//! ceilings of P-258 in its steps, because km43's `Allocation::choose`
//! reads no role (origin89hq/km43#141).
//!
//! cites: P-064, P-066, P-085, P-086, P-105, P-238, P-239, P-240, P-250, P-258

use core::fmt;

use km43::{
    AdmitKey, ClientCapability, ClientId, ClientKind, Epoch, Generation, KEY_BYTES, MAX_ADMINS,
    MAX_CLIENTS, MAX_LABEL, MAX_VIEWERS, PublicKey, Role, Suite,
};

use crate::body::{Body, Held, Kept, Malformed, Reader, Unverified, Writer};
use crate::dedup::{COMMANDS_BYTES, Commands};
use crate::fram::Fram;
use crate::map;
use crate::text::Text;

/// The slots: one per `client_id` P-086 can allocate.
pub const SLOTS: usize = MAX_CLIENTS;

/// The bytes a key record budgets. The layout takes 109 of them.
pub const KEY_RECORD_BYTES: usize = 128;

/// The bytes a generation mark takes: one `u32`, zero for none issued.
pub const MARK_BYTES: usize = 4;

const LAYOUT: usize = 1 + 4 + 4 + 1 + KEY_BYTES + KEY_BYTES + 1 + 1 + (1 + MAX_LABEL);
const _: () = assert!(LAYOUT <= KEY_RECORD_BYTES);

/// The state byte of a free slot and of an occupied one.
const FREE: u8 = 0;
const OCCUPIED: u8 = 1;

/// A client's own name for itself, as the bytes `PairOffer` carried: byte
/// equality is the only comparison P-240 permits, and a label past the cap
/// is refused rather than truncated.
pub type ClientLabel = Text<MAX_LABEL>;

/// What an enrolment writes into a slot: the key it proved, what the
/// client said of itself, and the role the controller decided.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Enrolment {
    /// The static key the enrolment proved (`IS`).
    pub client: PublicKey,
    /// P-238's admission key, computed once from `cs` and `IS`.
    pub admit: [u8; KEY_BYTES],
    /// The suite the pairing ran.
    pub suite: Suite,
    /// The role, which the caller decided: [`Place::role`] for a pairing
    /// through the label, the invite's for an approved one (P-250). Never
    /// derived from `kind`.
    pub role: Role,
    /// What the client said it was: shown, deciding nothing (P-105).
    pub kind: ClientKind,
    /// What the client named itself.
    pub label: ClientLabel,
}

/// An occupied slot's record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Occupant {
    epoch: Epoch,
    generation: Generation,
    suite: Suite,
    client: PublicKey,
    admit: [u8; KEY_BYTES],
    role: Role,
    kind: ClientKind,
    label: ClientLabel,
}

impl Occupant {
    /// The epoch the slot was written under.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Which enrolment of this slot it is (P-239).
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// The suite a `Hello` must present (P-226).
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// The key a `Hello` must prove.
    #[must_use]
    pub const fn client(&self) -> PublicKey {
        self.client
    }

    /// The key a `Hello`'s admission tag is checked under.
    #[must_use]
    pub fn admit_key(&self) -> AdmitKey {
        AdmitKey::from_stored(self.admit)
    }

    /// What the slot may do (P-250), fixed when it was written.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The kind the client attested: shown, deciding nothing (P-105).
    #[must_use]
    pub const fn kind(&self) -> ClientKind {
        self.kind
    }

    /// The label that entered the pairing.
    #[must_use]
    pub const fn label(&self) -> &ClientLabel {
        &self.label
    }

    /// The role's row of the registry and nothing else (P-105).
    #[must_use]
    pub const fn mask(&self) -> ClientCapability {
        ClientCapability::granted(self.role)
    }
}

#[cfg(test)]
impl Occupant {
    /// The enrolment that wrote this record, for a test to write it again
    /// with one field changed.
    pub(crate) const fn enrolment(&self) -> Enrolment {
        Enrolment {
            client: self.client,
            admit: self.admit,
            suite: self.suite,
            role: self.role,
            kind: self.kind,
            label: self.label,
        }
    }
}

/// What a slot's record says.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyRecord {
    /// No key: written free before a re-key or after a reset, carrying the
    /// generation the mark had reached, if any.
    Free {
        /// The generation the slot was freed under.
        generation: Option<Generation>,
    },
    /// A key and everything fixed with it.
    Occupied(Occupant),
}

/// The admission key is a secret; the rest is what a dump needs.
impl fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free { generation } => f
                .debug_struct("Free")
                .field("generation", &generation.map(Generation::get))
                .finish(),
            Self::Occupied(occupant) => f
                .debug_struct("Occupied")
                .field("epoch", &occupant.epoch.get())
                .field("generation", &occupant.generation.get())
                .field("role", &occupant.role)
                .field("kind", &occupant.kind)
                .field("label", &occupant.label)
                .field("client", &occupant.client)
                .finish_non_exhaustive(),
        }
    }
}

impl Body<KEY_RECORD_BYTES> for KeyRecord {
    fn encode(&self) -> [u8; KEY_RECORD_BYTES] {
        let mut out = [0u8; KEY_RECORD_BYTES];
        let mut writer = Writer::over(&mut out);
        match self {
            Self::Free { generation } => {
                writer.u8(FREE);
                writer.u32(0);
                writer.u32(generation.map_or(0, Generation::get));
            }
            Self::Occupied(occupant) => {
                writer.u8(OCCUPIED);
                writer.u32(occupant.epoch.get());
                writer.u32(occupant.generation.get());
                writer.u8(occupant.suite as u8);
                writer.put(occupant.client.as_bytes());
                writer.put(&occupant.admit);
                writer.u8(occupant.role as u8);
                writer.u8(occupant.kind as u8);
                occupant.label.put(&mut writer);
            }
        }
        out
    }

    fn decode(bytes: &[u8; KEY_RECORD_BYTES]) -> Result<Self, Malformed> {
        let mut reader = Reader::over(bytes);
        let state = reader.u8()?;
        let epoch = reader.u32()?;
        let generation = reader.u32()?;
        match state {
            FREE => Ok(Self::Free {
                generation: Generation::new(generation),
            }),
            OCCUPIED => {
                let epoch = Epoch::new(epoch).ok_or(Malformed { at: 1 })?;
                let generation = Generation::new(generation).ok_or(Malformed { at: 5 })?;
                let suite = Suite::try_from(reader.u8()?).map_err(|()| reader.malformed(1))?;
                let client = PublicKey::from_bytes(reader.take::<KEY_BYTES>()?);
                let admit = reader.take::<KEY_BYTES>()?;
                let role = Role::try_from(reader.u8()?).map_err(|()| reader.malformed(1))?;
                let kind = ClientKind::try_from(reader.u8()?).map_err(|()| reader.malformed(1))?;
                let label = ClientLabel::take(&mut reader)?;
                Ok(Self::Occupied(Occupant {
                    epoch,
                    generation,
                    suite,
                    client,
                    admit,
                    role,
                    kind,
                    label,
                }))
            }
            _ => Err(Malformed { at: 0 }),
        }
    }
}

/// Where P-240 puts a pairing through the label, and the role the slot is
/// written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a placement nobody writes enrols nobody"]
pub enum Place {
    /// Step 1: the slot already holding this key, re-keyed with the role it
    /// had (P-250), answered `reclaimed`.
    SameKey(ClientId, Role),
    /// Step 2: the lowest free slot the role may take (P-258), answered
    /// `enrolled`. `owner` when no occupied slot holds one, else `admin`.
    Free(ClientId, Role),
    /// Step 3: the lowest `admin` slot with this label, re-keyed as an
    /// admin and answered `reclaimed`. An owner or a viewer is never taken
    /// this way (P-258).
    Reclaim(ClientId),
    /// Step 4: `table_full`.
    Full,
}

impl Place {
    /// The slot to write and the role to write it with, or `None` for a
    /// full table.
    #[must_use]
    pub const fn slot(self) -> Option<(ClientId, Role)> {
        match self {
            Self::SameKey(id, role) | Self::Free(id, role) => Some((id, role)),
            Self::Reclaim(id) => Some((id, Role::Admin)),
            Self::Full => None,
        }
    }
}

/// The highest generation a slot has issued, or none yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GenerationMark(Option<Generation>);

impl GenerationMark {
    /// The generation a re-key issues next, or `None` at the top of the
    /// `u32`, which no slot reaches.
    #[must_use]
    pub fn next(self) -> Option<Generation> {
        match self.0 {
            Some(issued) => issued.next(),
            None => Some(Generation::FIRST),
        }
    }
}

impl Body<MARK_BYTES> for GenerationMark {
    fn encode(&self) -> [u8; MARK_BYTES] {
        self.0.map_or(0, Generation::get).to_le_bytes()
    }

    fn decode(bytes: &[u8; MARK_BYTES]) -> Result<Self, Malformed> {
        Ok(Self(Generation::new(u32::from_le_bytes(*bytes))))
    }
}

/// Why a slot was not written. P-064: the slot is not used, `Enrol` is
/// answered outcome 7 `not_stored`, the window stays open, and the caller
/// raises condition 23 `client table write failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a slot that did not land must not be answered as enrolled"]
pub enum NotStored<E> {
    /// No slot has that number.
    NoSuchSlot,
    /// The mark cannot be raised: unreadable, or at the top of its `u32`.
    Mark,
    /// A write did not read back.
    Write(Unverified<E>),
}

impl<E> From<Unverified<E>> for NotStored<E> {
    fn from(why: Unverified<E>) -> Self {
        Self::Write(why)
    }
}

/// What a boot did with the table (P-066, P-239).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repaired {
    /// Every mark and record read; nothing was written.
    Nothing,
    /// A mark had never been written: a fresh part, or one this layout is
    /// new to. Each was written as none issued, and each unreadable record
    /// written free.
    Initialised,
    /// A record had no copy that read, and was written free (P-239).
    Freed,
    /// A mark could not be read, so the epoch was advanced as a reset
    /// advances it and every slot written free under it (P-239).
    Rebuilt(Epoch),
}

/// Why the boot could not repair the table. Nothing is enrolled under it,
/// and the power-on window stays shut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Unrepaired<E> {
    /// A mark needed the epoch advanced, and there is no epoch to advance.
    NoEpoch,
    /// The epoch did not advance.
    Epoch(crate::EpochFailed<E>),
    /// A repair write did not read back.
    Write(Unverified<E>),
}

impl<E> From<Unverified<E>> for Unrepaired<E> {
    fn from(why: Unverified<E>) -> Self {
        Self::Write(why)
    }
}

/// The eight slots, as the part holds them.
pub struct Clients {
    keys: [Kept<KeyRecord, KEY_RECORD_BYTES>; SLOTS],
    marks: [Kept<GenerationMark, MARK_BYTES>; SLOTS],
    commands: Kept<Commands, COMMANDS_BYTES>,
}

impl fmt::Debug for Clients {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clients")
            .field("keys", &self.keys)
            .field("marks", &self.marks)
            .finish_non_exhaustive()
    }
}

/// The `client_id` of each slot, counting from one (P-086).
fn ids() -> impl Iterator<Item = ClientId> {
    (1u32..).map_while(ClientId::new)
}

impl Clients {
    /// Read every slot, every mark and the dedup record.
    pub async fn read<F: Fram>(fram: &mut F) -> Result<Self, F::Error> {
        let mut keys = map::CLIENT_KEYS.map(Kept::unread);
        let mut marks = map::GENERATION_MARKS.map(Kept::unread);
        for key in &mut keys {
            *key = Kept::read(key.record(), fram).await?;
        }
        for mark in &mut marks {
            *mark = Kept::read(mark.record(), fram).await?;
        }
        let commands = Kept::read(map::COMMANDS, fram).await?;
        Ok(Self {
            keys,
            marks,
            commands,
        })
    }

    /// Every slot under `epoch`, with its number: the occupant, or `None`
    /// for a free slot (P-239).
    fn slots(&self, epoch: Epoch) -> impl Iterator<Item = (ClientId, Option<&Occupant>)> {
        ids()
            .zip(&self.keys)
            .map(move |(id, key)| match key.held() {
                Held::Present(KeyRecord::Occupied(occupant)) if occupant.epoch == epoch => {
                    (id, Some(occupant))
                }
                Held::Present(KeyRecord::Occupied(_) | KeyRecord::Free { .. })
                | Held::Absent
                | Held::Corrupt
                | Held::Malformed(_) => (id, None),
            })
    }

    /// The occupied slots under `epoch`, with their numbers.
    pub fn occupied(&self, epoch: Epoch) -> impl Iterator<Item = (ClientId, &Occupant)> {
        self.slots(epoch)
            .filter_map(|(id, occupant)| occupant.map(|occupant| (id, occupant)))
    }

    /// The slot at `id`, if it is occupied under `epoch`.
    #[must_use]
    pub fn occupant(&self, id: ClientId, epoch: Epoch) -> Option<&Occupant> {
        self.occupied(epoch)
            .find(|(slot, _)| *slot == id)
            .map(|(_, occupant)| occupant)
    }

    /// How many slots are occupied under `epoch`.
    #[must_use]
    pub fn enrolled(&self, epoch: Epoch) -> usize {
        self.occupied(epoch).count()
    }

    /// Whether P-258 lets one more slot hold `role`: fewer than
    /// `MAX_ADMINS` admins, fewer than `MAX_VIEWERS` viewers, and an owner
    /// always. A free slot is a separate question, [`Self::free_for`]'s.
    #[must_use]
    pub fn admits(&self, role: Role, epoch: Epoch) -> bool {
        let holding = self
            .occupied(epoch)
            .filter(|(_, occupant)| occupant.role == role)
            .count();
        match role {
            Role::Owner => true,
            Role::Admin => holding < MAX_ADMINS,
            Role::Viewer => holding < MAX_VIEWERS,
        }
    }

    /// The lowest free slot (P-086) an enrolment of `role` may take under
    /// P-258, or `None`. This is where an approved invite goes: an invite
    /// never reclaims by label (P-255).
    #[must_use]
    pub fn free_for(&self, role: Role, epoch: Epoch) -> Option<ClientId> {
        if !self.admits(role, epoch) {
            return None;
        }
        self.slots(epoch)
            .find(|(_, occupant)| occupant.is_none())
            .map(|(id, _)| id)
    }

    /// P-240 for a pairing through the label, in its order, with P-250's
    /// role and P-258's ceilings. `key` is `None` at message 1, which
    /// carries no client key, so only steps 2 to 4 run there; at message 3
    /// step 1 wins over them. `label` is compared as bytes.
    pub fn place(&self, epoch: Epoch, key: Option<&PublicKey>, label: &str) -> Place {
        if let Some((id, occupant)) = key.and_then(|key| {
            self.occupied(epoch)
                .find(|(_, occupant)| occupant.client.matches(key))
        }) {
            return Place::SameKey(id, occupant.role);
        }
        let owned = self
            .occupied(epoch)
            .any(|(_, occupant)| occupant.role == Role::Owner);
        let role = if owned { Role::Admin } else { Role::Owner };
        if let Some(id) = self.free_for(role, epoch) {
            return Place::Free(id, role);
        }
        self.occupied(epoch)
            .find(|(_, occupant)| {
                occupant.role == Role::Admin && occupant.label.as_bytes() == label.as_bytes()
            })
            .map_or(Place::Full, |(id, _)| Place::Reclaim(id))
    }

    /// The dedup table.
    #[must_use]
    pub const fn commands(&self) -> &Kept<Commands, COMMANDS_BYTES> {
        &self.commands
    }

    /// The dedup table, to change through its record.
    pub fn commands_mut(&mut self) -> &mut Kept<Commands, COMMANDS_BYTES> {
        &mut self.commands
    }

    /// Write `enrolment` into slot `id` under `epoch`, in P-239's order, and
    /// hand back the generation it was issued. The caller has unbound every
    /// session on the slot (P-240). A refusal at any step leaves the old
    /// enrolment or a free slot, and nothing enrolled.
    pub async fn enrol<F: Fram>(
        &mut self,
        id: ClientId,
        enrolment: Enrolment,
        epoch: Epoch,
        fram: &mut F,
    ) -> Result<Generation, NotStored<F::Error>> {
        let generation = self.freed(id, epoch, fram).await?;
        let key = self.key_mut(id).ok_or(NotStored::NoSuchSlot)?;
        key.write_verified(
            fram,
            KeyRecord::Occupied(Occupant {
                epoch,
                generation,
                suite: enrolment.suite,
                client: enrolment.client,
                admit: enrolment.admit,
                role: enrolment.role,
                kind: enrolment.kind,
                label: enrolment.label,
            }),
        )
        .await?;
        Ok(generation)
    }

    /// Free slot `id`: the mark raised, the slot written free under it, and
    /// its dedup entries forgotten (P-239). The generation that was raised
    /// comes back for a re-key to use.
    async fn freed<F: Fram>(
        &mut self,
        id: ClientId,
        epoch: Epoch,
        fram: &mut F,
    ) -> Result<Generation, NotStored<F::Error>> {
        let index = id.slot().ok_or(NotStored::NoSuchSlot)?;
        let mark = self.marks.get_mut(index).ok_or(NotStored::NoSuchSlot)?;
        let generation = mark
            .present()
            .and_then(|issued| issued.next())
            .ok_or(NotStored::Mark)?;
        mark.write_verified(fram, GenerationMark(Some(generation)))
            .await?;
        let key = self.keys.get_mut(index).ok_or(NotStored::NoSuchSlot)?;
        key.write_verified(
            fram,
            KeyRecord::Free {
                generation: Some(generation),
            },
        )
        .await?;
        let commands = match self.commands.present() {
            Some(held) if held.dedup().holds(id) => {
                let mut forgotten = held.clone();
                forgotten.dedup_mut().forget(id);
                Some(forgotten)
            }
            Some(_) => None,
            None => Some(Commands::cleared(epoch)),
        };
        if let Some(commands) = commands {
            self.commands.write_verified(fram, commands).await?;
        }
        Ok(generation)
    }

    /// Every slot freed and the dedup table emptied under `epoch`, after a
    /// factory reset's epoch landed. Housekeeping: the slots were free the
    /// moment the epoch moved (P-085), so a refusal here is reported and
    /// changes nothing a client can use.
    pub async fn cleared<F: Fram>(
        &mut self,
        clearing: &crate::Clearing,
        fram: &mut F,
    ) -> Result<(), NotStored<F::Error>> {
        let epoch = clearing.epoch();
        self.commands
            .write_verified(fram, Commands::cleared(epoch))
            .await?;
        for id in ids().take(SLOTS) {
            let free = matches!(
                self.key(id).map(Kept::held),
                Some(Held::Present(KeyRecord::Free { .. }) | Held::Absent)
            );
            if !free {
                self.freed(id, epoch, fram).await?;
            }
        }
        Ok(())
    }

    /// Take the table as a boot does, under the epoch the boot holds
    /// (P-066, P-121, P-239). Marks that were never written are written as
    /// none issued; a record with no copy that reads is written free; a mark
    /// that cannot be read advances the epoch and frees every slot under
    /// it. The dedup table is kept, rebased, under this epoch, and cleared
    /// under any other.
    pub async fn booted<F: Fram>(
        &mut self,
        epoch: &mut Kept<Epoch, { crate::EPOCH_BYTES }>,
        fram: &mut F,
    ) -> Result<Repaired, Unrepaired<F::Error>> {
        let corrupt = self
            .marks
            .iter()
            .any(|mark| matches!(mark.held(), Held::Corrupt | Held::Malformed(_)));
        let mut repaired = Repaired::Nothing;
        let under = if corrupt {
            let clearing = epoch.advance(fram).await.map_err(|why| match why {
                crate::EpochFailed::Unknown => Unrepaired::NoEpoch,
                crate::EpochFailed::AtTheCeiling
                | crate::EpochFailed::Write(_)
                | crate::EpochFailed::ReadBack(_)
                | crate::EpochFailed::Disagreed => Unrepaired::Epoch(why),
            })?;
            repaired = Repaired::Rebuilt(clearing.epoch());
            clearing.epoch()
        } else {
            *epoch.present().ok_or(Unrepaired::NoEpoch)?
        };
        for (mark, key) in self.marks.iter_mut().zip(&mut self.keys) {
            let issued = match mark.held() {
                Held::Present(issued) => *issued,
                Held::Absent | Held::Corrupt | Held::Malformed(_) => {
                    // Under a new epoch when it was unreadable, so a
                    // generation restarting is a new name all the same.
                    mark.write_verified(fram, GenerationMark(None)).await?;
                    if repaired == Repaired::Nothing {
                        repaired = Repaired::Initialised;
                    }
                    GenerationMark(None)
                }
            };
            let free = match key.held() {
                Held::Present(KeyRecord::Free { .. }) | Held::Absent => false,
                Held::Present(KeyRecord::Occupied(_)) => corrupt,
                Held::Corrupt | Held::Malformed(_) => {
                    if repaired == Repaired::Nothing {
                        repaired = Repaired::Freed;
                    }
                    true
                }
            };
            if free {
                key.write_verified(
                    fram,
                    KeyRecord::Free {
                        generation: issued.0,
                    },
                )
                .await?;
            }
        }
        let commands = match self.commands.present() {
            Some(held) if held.epoch() == under => {
                let rebased = held.clone().rebased();
                self.commands.rebase(rebased);
                None
            }
            Some(_) | None => Some(Commands::cleared(under)),
        };
        if let Some(commands) = commands {
            self.commands.write_verified(fram, commands).await?;
        }
        Ok(repaired)
    }

    /// The highest epoch any record was written under: a second copy of a
    /// counter that only climbs, which the boot raises the epoch record to
    /// if the record fell behind it.
    #[must_use]
    pub fn highest_epoch(&self) -> Option<Epoch> {
        self.keys
            .iter()
            .filter_map(|key| match key.held() {
                Held::Present(KeyRecord::Occupied(occupant)) => Some(occupant.epoch),
                Held::Present(KeyRecord::Free { .. })
                | Held::Absent
                | Held::Corrupt
                | Held::Malformed(_) => None,
            })
            .max()
    }

    /// The record at `id`, for the bench and the tests.
    #[must_use]
    pub fn key(&self, id: ClientId) -> Option<&Kept<KeyRecord, KEY_RECORD_BYTES>> {
        id.slot().and_then(|index| self.keys.get(index))
    }

    /// The mark at `id`, for the bench and the tests.
    #[must_use]
    pub fn mark(&self, id: ClientId) -> Option<&Kept<GenerationMark, MARK_BYTES>> {
        id.slot().and_then(|index| self.marks.get(index))
    }

    fn key_mut(&mut self, id: ClientId) -> Option<&mut Kept<KeyRecord, KEY_RECORD_BYTES>> {
        id.slot().and_then(|index| self.keys.get_mut(index))
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use embassy_futures::block_on;
    use km43::Epoch;

    use super::*;
    use crate::dedup::{Fingerprint, Recorded, Verdict};
    use crate::fram::{Address, Refused, slot_bytes};
    use crate::tick::Tick;
    use crate::{EPOCH_BYTES, EpochFailed};

    /// Everything up to the end of the map.
    const PART_BYTES: usize = map::END.0 as usize;

    /// A part whose power can be cut before any byte of a write, and whose
    /// supply can fall.
    #[derive(Clone)]
    struct Part {
        bytes: [u8; PART_BYTES],
        falling: bool,
        landed: usize,
        cut_at: Option<usize>,
        dead: bool,
    }

    impl Part {
        #[expect(
            clippy::large_stack_arrays,
            reason = "the whole map, as the boot reads it; a test thread's stack holds it"
        )]
        fn fresh() -> Self {
            Self {
                bytes: [0xFF; PART_BYTES],
                falling: false,
                landed: 0,
                cut_at: None,
                dead: false,
            }
        }

        /// The same bytes, powered up, with the power cut before byte `at`
        /// of what is written next.
        fn cut_before(&self, at: usize) -> Self {
            Self {
                bytes: self.bytes,
                falling: false,
                landed: 0,
                cut_at: Some(at),
                dead: false,
            }
        }

        /// Power back on: the bytes stay.
        fn rebooted(&self) -> Self {
            Self {
                bytes: self.bytes,
                falling: false,
                landed: 0,
                cut_at: None,
                dead: false,
            }
        }
    }

    impl Fram for Part {
        type Error = ();

        fn read(&mut self, at: Address, into: &mut [u8]) -> impl Future<Output = Result<(), ()>> {
            if self.dead {
                return core::future::ready(Err(()));
            }
            let start = usize::from(at.0);
            into.copy_from_slice(&self.bytes[start..][..into.len()]);
            core::future::ready(Ok(()))
        }

        fn write(
            &mut self,
            at: Address,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), Refused<()>>> {
            if self.falling {
                return core::future::ready(Err(Refused::SupplyFalling));
            }
            if self.dead {
                return core::future::ready(Err(Refused::Bus(())));
            }
            let start = usize::from(at.0);
            for (offset, byte) in bytes.iter().enumerate() {
                if self.cut_at == Some(self.landed) {
                    self.dead = true;
                    return core::future::ready(Err(Refused::Bus(())));
                }
                self.bytes[start.saturating_add(offset)] = *byte;
                self.landed = self.landed.saturating_add(1);
            }
            core::future::ready(Ok(()))
        }
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a nonzero epoch")
    }

    fn id(n: u32) -> ClientId {
        ClientId::new(n).expect("a nonzero client")
    }

    fn generation(n: u32) -> Generation {
        Generation::new(n).expect("a nonzero generation")
    }

    /// An admin's enrolment.
    fn phone(key: u8, label: &str) -> Enrolment {
        holding(Role::Admin, key, label)
    }

    fn holding(role: Role, key: u8, label: &str) -> Enrolment {
        Enrolment {
            client: PublicKey::from_bytes([key; KEY_BYTES]),
            admit: [key; KEY_BYTES],
            suite: Suite::X25519ChachapolySha256,
            role,
            kind: ClientKind::App,
            label: ClientLabel::new(label).expect("fits"),
        }
    }

    /// Slot `n` written with `role` and `label` under epoch 1.
    fn seat(clients: &mut Clients, part: &mut Part, n: u32, role: Role, label: &str) {
        let key = u8::try_from(n).expect("a slot number");
        block_on(clients.enrol(id(n), holding(role, key, label), epoch(1), part)).expect("lands");
    }

    /// A part with an epoch, and its table booted under it.
    fn booted(raw: u32) -> (Part, Kept<Epoch, EPOCH_BYTES>, Clients) {
        let mut part = Part::fresh();
        let mut epoch_record = block_on(Kept::read(map::EPOCH, &mut part)).expect("reads");
        block_on(epoch_record.write(&mut part, epoch(raw))).expect("the supply is fine");
        let mut clients = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            block_on(clients.booted(&mut epoch_record, &mut part)),
            Ok(Repaired::Initialised)
        );
        (part, epoch_record, clients)
    }

    /// The bytes of one slot's body, both copies, for damaging.
    fn bodies<const N: usize>(record: crate::fram::Record<N>) -> [usize; 2] {
        let start = usize::from(record.end().0).saturating_sub(slot_bytes(N).saturating_mul(2));
        [
            start.saturating_add(8),
            start.saturating_add(slot_bytes(N)).saturating_add(8),
        ]
    }

    fn damage<const N: usize>(part: &mut Part, record: crate::fram::Record<N>) {
        for at in bodies(record) {
            part.bytes[at] ^= 0x01;
        }
    }

    fn record(clients: &Clients, n: u32) -> KeyRecord {
        *clients
            .key(id(n))
            .and_then(|key| key.present())
            .expect("a record")
    }

    fn mark(clients: &Clients, n: u32) -> GenerationMark {
        *clients
            .mark(id(n))
            .and_then(|mark| mark.present())
            .expect("a mark")
    }

    #[test]
    fn p_239_a_slot_is_occupied_only_under_the_epoch_it_was_written_in() {
        let (mut part, _, mut clients) = booted(1);
        assert_eq!(clients.enrolled(epoch(1)), 0);
        assert_eq!(clients.free_for(Role::Admin, epoch(1)), Some(id(1)));
        let issued =
            block_on(clients.enrol(id(3), phone(3, "phone"), epoch(1), &mut part)).expect("lands");
        assert_eq!(issued, generation(1));
        assert_eq!(clients.enrolled(epoch(1)), 1);
        let occupant = clients.occupant(id(3), epoch(1)).expect("occupied");
        assert!(occupant.client().matches(&PublicKey::from_bytes([3; 32])));
        assert_eq!(occupant.label().as_str(), "phone");
        assert_eq!(occupant.role(), Role::Admin);
        assert_eq!(occupant.mask(), ClientCapability::granted(Role::Admin));
        assert_eq!(occupant.epoch(), epoch(1));
        let occupied: [Option<ClientId>; 2] = {
            let mut found = clients.occupied(epoch(1)).map(|(id, _)| id);
            [found.next(), found.next()]
        };
        assert_eq!(occupied, [Some(id(3)), None]);
        // Under the next epoch the same record is free and matched by
        // nothing: not occupied, not a key a pairing finds.
        assert_eq!(clients.enrolled(epoch(2)), 0);
        assert!(clients.occupant(id(3), epoch(2)).is_none());
        let key = PublicKey::from_bytes([3; 32]);
        assert_eq!(
            clients.place(epoch(2), Some(&key), "phone"),
            Place::Free(id(1), Role::Owner)
        );
        // Nor under an earlier one.
        assert!(clients.occupant(id(3), Epoch::FIRST).is_some());
        assert_eq!(clients.occupied(epoch(5)).count(), 0);
    }

    #[test]
    fn p_239_a_re_key_issues_the_next_generation_and_generations_are_per_slot() {
        let (mut part, _, mut clients) = booted(1);
        let first = block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part));
        let second = block_on(clients.enrol(id(1), phone(2, "b"), epoch(1), &mut part));
        let other = block_on(clients.enrol(id(2), phone(3, "c"), epoch(1), &mut part));
        assert_eq!(first, Ok(generation(1)));
        assert_eq!(second, Ok(generation(2)));
        assert_eq!(other, Ok(generation(1)));
        assert_eq!(mark(&clients, 1), GenerationMark(Some(generation(2))));
        let now = clients.occupant(id(1), epoch(1)).expect("occupied");
        assert!(now.client().matches(&PublicKey::from_bytes([2; 32])));
        assert_eq!(now.generation(), generation(2));
        // And the part holds what the handles hold.
        let again = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(record(&again, 1), record(&clients, 1));
    }

    #[test]
    fn p_239_a_mark_at_its_ceiling_or_unread_refuses_the_re_key_and_writes_nothing() {
        let (mut part, _, _) = booted(1);
        let mut top = block_on(Kept::<GenerationMark, MARK_BYTES>::read(
            map::GENERATION_MARKS[0],
            &mut part,
        ))
        .expect("reads");
        block_on(top.write(&mut part, GenerationMark(Generation::new(u32::MAX))))
            .expect("the supply is fine");
        let mut clients = block_on(Clients::read(&mut part)).expect("reads");
        let before = part.bytes;
        assert_eq!(
            block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part)),
            Err(NotStored::Mark)
        );
        assert_eq!(part.bytes, before);
        // A mark never written is refused the same way: the boot writes it.
        let mut fresh = Part::fresh();
        let mut unbooted = block_on(Clients::read(&mut fresh)).expect("reads");
        assert_eq!(
            block_on(unbooted.enrol(id(1), phone(1, "a"), epoch(1), &mut fresh)),
            Err(NotStored::Mark)
        );
        // And a slot number past the table.
        assert_eq!(
            block_on(clients.enrol(id(9), phone(1, "a"), epoch(1), &mut part)),
            Err(NotStored::NoSuchSlot)
        );
    }

    #[test]
    fn p_064_a_slot_write_that_does_not_land_is_not_stored_and_enrols_nobody() {
        let (mut part, _, mut clients) = booted(1);
        part.falling = true;
        assert!(matches!(
            block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part)),
            Err(NotStored::Write(Unverified::Refused(
                Refused::SupplyFalling
            )))
        ));
        assert_eq!(clients.enrolled(epoch(1)), 0);
    }

    #[test]
    fn p_239_p_250_a_re_key_cut_at_every_byte_leaves_the_old_enrolment_or_a_free_slot_never_a_mix()
    {
        let (mut part, _, mut clients) = booted(1);
        block_on(clients.enrol(id(1), holding(Role::Owner, 1, "old"), epoch(1), &mut part))
            .expect("old");
        // An entry of the old install's, which a new install must not meet.
        block_on(clients.commands_mut().update(&mut part, |table| {
            let Verdict::Fresh(seat) =
                table
                    .dedup_mut()
                    .admit(id(1), 7, Fingerprint::of(b"start"), Tick::ZERO)
            else {
                panic!("fresh");
            };
            table.dedup_mut().finished(seat, Some(Recorded::Accepted));
        }))
        .expect("lands");
        let start = part.rebooted();
        let mut cuts = 0;
        let mut seen_new = false;
        let mut seen_free = false;
        for at in 0.. {
            let mut cut = start.cut_before(at);
            let mut handles = block_on(Clients::read(&mut cut)).expect("reads");
            let result = block_on(handles.enrol(id(1), phone(2, "new"), epoch(1), &mut cut));
            let mut after = cut.rebooted();
            let mut epoch_record =
                block_on(Kept::<Epoch, EPOCH_BYTES>::read(map::EPOCH, &mut after)).expect("reads");
            let mut found = block_on(Clients::read(&mut after)).expect("reads");
            assert_eq!(
                block_on(found.booted(&mut epoch_record, &mut after)),
                Ok(Repaired::Nothing),
                "a cut at byte {at} left a record without a valid copy"
            );
            let issued = mark(&found, 1);
            match record(&found, 1) {
                KeyRecord::Occupied(occupant) if occupant.client().as_bytes() == &[1; 32] => {
                    assert_eq!(occupant.label().as_str(), "old");
                    assert_eq!(occupant.role(), Role::Owner);
                    assert_eq!(occupant.generation(), generation(1));
                    assert!(!seen_new, "the old enrolment came back after the new one");
                    assert!(!seen_free, "the old key came back after the slot was freed");
                }
                KeyRecord::Occupied(occupant) => {
                    assert_eq!(occupant.client().as_bytes(), &[2; 32]);
                    assert_eq!(occupant.admit, [2; 32]);
                    assert_eq!(occupant.label().as_str(), "new");
                    // The role changes with the key and never apart from
                    // it: no cut leaves the old key as an admin or the new
                    // one as the owner (P-239, P-250).
                    assert_eq!(occupant.role(), Role::Admin);
                    assert_eq!(occupant.mask(), ClientCapability::granted(Role::Admin));
                    assert_eq!(occupant.generation(), generation(2));
                    assert!(
                        !found
                            .commands()
                            .present()
                            .expect("held")
                            .dedup()
                            .holds(id(1)),
                        "the new install met the old one's entries"
                    );
                    seen_new = true;
                }
                KeyRecord::Free { generation: freed } => {
                    assert_eq!(freed, Some(generation(2)));
                    assert!(!seen_new);
                    seen_free = true;
                }
            }
            // Whatever the slot says, the mark is at least its generation:
            // the next re-key cannot issue one that was already written.
            let next = block_on(found.enrol(id(1), phone(3, "next"), epoch(1), &mut after))
                .expect("the next re-key lands");
            assert!(next > generation(1));
            assert_eq!(issued.next(), Some(next));
            cuts += 1;
            if result.is_ok() {
                break;
            }
        }
        assert!(seen_new, "the re-key never landed");
        // The old key is gone before the new one is written: a re-key that
        // stops part-way revokes the install it replaces (P-239, P-240).
        assert!(seen_free, "no cut ever found the slot free");
        assert!(
            cuts > 100,
            "only {cuts} cuts: the loop did not walk the write"
        );
    }

    #[test]
    fn p_085_cleared_frees_every_slot_and_empties_the_dedup_table_under_the_new_epoch() {
        let (mut part, mut epoch_record, mut clients) = booted(1);
        block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part)).expect("a");
        block_on(clients.enrol(id(4), phone(4, "b"), epoch(1), &mut part)).expect("b");
        let clearing = block_on(epoch_record.advance(&mut part)).expect("advances");
        block_on(clients.cleared(&clearing, &mut part)).expect("clears");
        for n in 1..=8 {
            let held = clients.key(id(n)).map(Kept::held);
            assert!(
                matches!(
                    held,
                    Some(Held::Absent | Held::Present(KeyRecord::Free { .. }))
                ),
                "slot {n} is not free"
            );
        }
        assert_eq!(
            record(&clients, 4),
            KeyRecord::Free {
                generation: Some(generation(2))
            }
        );
        let commands = clients.commands().present().expect("held");
        assert_eq!(commands.epoch(), epoch(2));
        assert_eq!(commands.dedup().live(Tick::ZERO), 0);
        // A table already free clears without raising a mark it need not.
        let before = mark(&clients, 1);
        let clearing = block_on(epoch_record.advance(&mut part)).expect("advances");
        block_on(clients.cleared(&clearing, &mut part)).expect("clears");
        assert_eq!(mark(&clients, 1), before);
        // And a refusal is reported, not swallowed.
        let clearing = block_on(epoch_record.advance(&mut part)).expect("advances");
        part.falling = true;
        assert!(block_on(clients.cleared(&clearing, &mut part)).is_err());
    }

    #[test]
    fn p_066_a_fresh_part_is_initialised_every_mark_as_none_issued() {
        let (mut part, mut epoch_record, clients) = booted(1);
        for n in 1..=8 {
            assert_eq!(mark(&clients, n), GenerationMark(None));
            assert!(
                clients
                    .key(id(n))
                    .is_some_and(|key| key.held() == &Held::Absent)
            );
        }
        assert_eq!(
            clients.commands().present().map(Commands::epoch),
            Some(epoch(1))
        );
        // The boot after it finds nothing to repair.
        let mut again = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            block_on(again.booted(&mut epoch_record, &mut part)),
            Ok(Repaired::Nothing)
        );
    }

    #[test]
    fn p_239_a_record_with_no_copy_that_reads_is_written_free() {
        let (mut part, mut epoch_record, mut clients) = booted(1);
        // Enrolling writes both copies: free, then occupied.
        block_on(clients.enrol(id(2), phone(2, "a"), epoch(1), &mut part)).expect("lands");
        damage(&mut part, map::CLIENT_KEYS[1]);
        let mut found = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(found.key(id(2)).map(Kept::held), Some(&Held::Corrupt));
        assert_eq!(
            block_on(found.booted(&mut epoch_record, &mut part)),
            Ok(Repaired::Freed)
        );
        assert_eq!(
            record(&found, 2),
            KeyRecord::Free {
                generation: Some(generation(1))
            }
        );
        assert_eq!(found.enrolled(epoch(1)), 0);
        assert_eq!(epoch_record.present(), Some(&epoch(1)));
    }

    #[test]
    fn p_239_an_unreadable_mark_advances_the_epoch_and_frees_every_slot() {
        let (mut part, mut epoch_record, mut clients) = booted(3);
        block_on(clients.enrol(id(1), phone(1, "a"), epoch(3), &mut part)).expect("a");
        block_on(clients.enrol(id(1), phone(2, "b"), epoch(3), &mut part)).expect("b");
        block_on(clients.enrol(id(5), phone(5, "c"), epoch(3), &mut part)).expect("c");
        damage(&mut part, map::GENERATION_MARKS[0]);
        let mut found = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            block_on(found.booted(&mut epoch_record, &mut part)),
            Ok(Repaired::Rebuilt(epoch(4)))
        );
        assert_eq!(epoch_record.present(), Some(&epoch(4)));
        assert_eq!(found.enrolled(epoch(4)), 0);
        assert!(matches!(record(&found, 1), KeyRecord::Free { .. }));
        assert!(matches!(record(&found, 5), KeyRecord::Free { .. }));
        assert_eq!(mark(&found, 1), GenerationMark(None));
        // The other slots keep their marks.
        assert_eq!(mark(&found, 5), GenerationMark(Some(generation(1))));
        // The generation restarts under the new epoch: a new name all the
        // same, because the epoch is part of it.
        assert_eq!(
            block_on(found.enrol(id(1), phone(9, "d"), epoch(4), &mut part)),
            Ok(generation(1))
        );
        let commands = found.commands().present().expect("held");
        assert_eq!(commands.epoch(), epoch(4));
    }

    #[test]
    fn p_239_an_unreadable_mark_with_no_epoch_to_advance_writes_nothing() {
        let (mut part, _, mut clients) = booted(1);
        block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part)).expect("a");
        damage(&mut part, map::GENERATION_MARKS[0]);
        let mut none = block_on(Kept::<Epoch, EPOCH_BYTES>::read(
            map::EPOCH,
            &mut Part::fresh(),
        ))
        .expect("reads");
        let before = part.bytes;
        let mut found = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            block_on(found.booted(&mut none, &mut part)),
            Err(Unrepaired::NoEpoch)
        );
        assert_eq!(part.bytes, before);
        // An epoch that will not advance is its own refusal, and nothing
        // is freed under the old one.
        let mut epoch_record =
            block_on(Kept::<Epoch, EPOCH_BYTES>::read(map::EPOCH, &mut part)).expect("reads");
        part.falling = true;
        assert_eq!(
            block_on(found.booted(&mut epoch_record, &mut part)),
            Err(Unrepaired::Epoch(EpochFailed::Write(
                Refused::SupplyFalling
            )))
        );
        assert_eq!(part.bytes, before);
    }

    #[test]
    fn p_121_the_dedup_table_is_rebased_under_its_epoch_and_cleared_under_another() {
        let (mut part, mut epoch_record, mut clients) = booted(1);
        block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part)).expect("a");
        let late = Tick::from_millis(500_000);
        let _ = block_on(clients.commands_mut().update(&mut part, |table| {
            table
                .dedup_mut()
                .admit(id(1), 7, Fingerprint::of(b"start"), late)
        }))
        .expect("lands");
        let mut found = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            block_on(found.booted(&mut epoch_record, &mut part)),
            Ok(Repaired::Nothing)
        );
        let dedup = found.commands().present().expect("held").dedup();
        assert_eq!(dedup.live(Tick::from_millis(599_999)), 1);
        assert_eq!(dedup.live(Tick::from_millis(600_000)), 0);
        // A reset cut after its epoch landed: the table is under the old one.
        let _ = block_on(epoch_record.advance(&mut part)).expect("advances");
        let mut found = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            block_on(found.booted(&mut epoch_record, &mut part)),
            Ok(Repaired::Nothing)
        );
        let commands = found.commands().present().expect("held");
        assert_eq!(commands.epoch(), epoch(2));
        assert!(!commands.dedup().holds(id(1)));
        assert_eq!(found.enrolled(epoch(2)), 0);
    }

    #[test]
    fn f_026_the_highest_epoch_any_slot_was_written_under() {
        let (mut part, _, mut clients) = booted(1);
        assert_eq!(clients.highest_epoch(), None);
        block_on(clients.enrol(id(1), phone(1, "a"), epoch(1), &mut part)).expect("a");
        block_on(clients.enrol(id(2), phone(2, "b"), epoch(3), &mut part)).expect("b");
        assert_eq!(clients.highest_epoch(), Some(epoch(3)));
        // A free record says no epoch at all.
        block_on(clients.enrol(id(3), phone(3, "c"), epoch(2), &mut part)).expect("c");
        assert_eq!(clients.highest_epoch(), Some(epoch(3)));
    }

    #[test]
    fn p_239_a_key_record_round_trips_and_refuses_what_it_cannot_read() {
        let occupied = KeyRecord::Occupied(Occupant {
            epoch: epoch(7),
            generation: generation(3),
            suite: Suite::X25519ChachapolySha256,
            client: PublicKey::from_bytes([4; 32]),
            admit: [5; 32],
            role: Role::Viewer,
            kind: ClientKind::Cloud,
            label: ClientLabel::new("relay").expect("fits"),
        });
        for held in [
            KeyRecord::Free { generation: None },
            KeyRecord::Free {
                generation: Some(generation(9)),
            },
            occupied,
        ] {
            assert_eq!(KeyRecord::decode(&held.encode()), Ok(held));
        }
        let bytes = occupied.encode();
        let mut bad = bytes;
        bad[0] = 7;
        assert_eq!(KeyRecord::decode(&bad).err(), Some(Malformed { at: 0 }));
        let mut bad = bytes;
        bad[1..5].fill(0);
        assert_eq!(KeyRecord::decode(&bad).err(), Some(Malformed { at: 1 }));
        let mut bad = bytes;
        bad[5..9].fill(0);
        assert_eq!(KeyRecord::decode(&bad).err(), Some(Malformed { at: 5 }));
        let mut bad = bytes;
        bad[9] = 0xEE;
        assert_eq!(KeyRecord::decode(&bad).err(), Some(Malformed { at: 9 }));
        // A role the registry does not name, the byte after the keys.
        for role in [0, 4, 0xEE] {
            let mut bad = bytes;
            bad[10 + 64] = role;
            assert_eq!(
                KeyRecord::decode(&bad).err(),
                Some(Malformed { at: 10 + 64 })
            );
        }
        let mut bad = bytes;
        bad[10 + 64 + 1] = 0xEE;
        assert_eq!(
            KeyRecord::decode(&bad).err(),
            Some(Malformed { at: 10 + 64 + 1 })
        );
        // The debug form names the client and never the admission key.
        let mut text = [0u8; 512];
        let mut out = Buffer(&mut text, 0);
        core::fmt::write(&mut out, format_args!("{occupied:?}")).expect("fits");
        let written = &out.0[..out.1];
        assert!(!written.windows(4).any(|window| window == b"0505"));
        assert!(written.windows(5).any(|window| window == b"relay"));
    }

    /// A formatter target with no allocator.
    struct Buffer<'a>(&'a mut [u8], usize);

    impl core::fmt::Write for Buffer<'_> {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.1.saturating_add(text.len());
            self.0
                .get_mut(self.1..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.1 = end;
            Ok(())
        }
    }

    #[test]
    fn p_105_the_mask_is_the_role_row_whatever_the_client_said_it_was() {
        let (mut part, _, mut clients) = booted(1);
        let mut relay = holding(Role::Owner, 1, "relay");
        relay.kind = ClientKind::Cloud;
        block_on(clients.enrol(id(1), relay, epoch(1), &mut part)).expect("lands");
        let occupant = clients.occupant(id(1), epoch(1)).expect("occupied");
        assert_eq!(occupant.kind(), ClientKind::Cloud);
        assert_eq!(occupant.mask(), ClientCapability::granted(Role::Owner));
        assert!(
            occupant
                .mask()
                .allows(ClientCapability::WRITE_NETWORK_AND_CLOUD)
        );
        // And the same kind as a viewer holds nothing.
        let mut viewer = holding(Role::Viewer, 2, "relay");
        viewer.kind = ClientKind::App;
        block_on(clients.enrol(id(2), viewer, epoch(1), &mut part)).expect("lands");
        let occupant = clients.occupant(id(2), epoch(1)).expect("occupied");
        assert_eq!(occupant.mask(), ClientCapability(0));
        // Read back from the part, the role is what was written.
        let again = block_on(Clients::read(&mut part)).expect("reads");
        assert_eq!(
            again.occupant(id(1), epoch(1)).map(Occupant::role),
            Some(Role::Owner)
        );
        assert_eq!(
            again.occupant(id(2), epoch(1)).map(Occupant::role),
            Some(Role::Viewer)
        );
    }

    #[test]
    fn p_258_the_ceilings_hold_at_the_bound_and_refuse_one_past_it() {
        let (mut part, _, mut clients) = booted(1);
        seat(&mut clients, &mut part, 1, Role::Owner, "owner");
        for n in 2..=6 {
            seat(&mut clients, &mut part, n, Role::Admin, "admin");
        }
        // Five admins: the sixth is admitted, at the lowest free slot.
        assert!(clients.admits(Role::Admin, epoch(1)));
        assert_eq!(clients.free_for(Role::Admin, epoch(1)), Some(id(7)));
        seat(&mut clients, &mut part, 7, Role::Admin, "admin");
        // Six: a seventh is not, though slot 8 is free.
        assert!(!clients.admits(Role::Admin, epoch(1)));
        assert_eq!(clients.free_for(Role::Admin, epoch(1)), None);
        // The row left over is an owner's or the viewer's.
        assert_eq!(clients.free_for(Role::Owner, epoch(1)), Some(id(8)));
        assert_eq!(clients.free_for(Role::Viewer, epoch(1)), Some(id(8)));
        seat(&mut clients, &mut part, 8, Role::Viewer, "cloud");
        assert!(!clients.admits(Role::Viewer, epoch(1)));
        // An owner is always admitted by the ceiling, and a full table
        // still has no slot for it.
        assert!(clients.admits(Role::Owner, epoch(1)));
        assert_eq!(clients.free_for(Role::Owner, epoch(1)), None);
        // Slots from another epoch hold no role at all.
        assert!(clients.admits(Role::Admin, epoch(2)));
        assert!(clients.admits(Role::Viewer, epoch(2)));
        assert_eq!(clients.free_for(Role::Admin, epoch(2)), Some(id(1)));
    }

    #[test]
    fn p_250_the_first_label_pairing_is_the_owner_and_the_next_an_admin() {
        let (mut part, _, mut clients) = booted(1);
        let key = PublicKey::from_bytes([9; KEY_BYTES]);
        assert_eq!(
            clients.place(epoch(1), None, "phone"),
            Place::Free(id(1), Role::Owner)
        );
        assert_eq!(
            clients.place(epoch(1), Some(&key), "phone"),
            Place::Free(id(1), Role::Owner)
        );
        seat(&mut clients, &mut part, 1, Role::Owner, "phone");
        assert_eq!(
            clients.place(epoch(1), Some(&key), "tablet"),
            Place::Free(id(2), Role::Admin)
        );
        // The same key again keeps its role: an owner pairing again is
        // still the owner, though an owner now exists.
        let own = PublicKey::from_bytes([1; KEY_BYTES]);
        assert_eq!(
            clients.place(epoch(1), Some(&own), "renamed"),
            Place::SameKey(id(1), Role::Owner)
        );
        // Message 1 has no key, so it cannot reach step 1.
        assert_eq!(
            clients.place(epoch(1), None, "renamed"),
            Place::Free(id(2), Role::Admin)
        );
        // With no owner left, a free slot is the owner's past the admin
        // ceiling.
        let (mut part, _, mut clients) = booted(1);
        for n in 1..=6 {
            seat(&mut clients, &mut part, n, Role::Admin, "admin");
        }
        assert_eq!(
            clients.place(epoch(1), None, "new"),
            Place::Free(id(7), Role::Owner)
        );
    }

    #[test]
    fn p_240_p_258_only_an_admin_slot_is_reclaimed_by_label_and_only_byte_for_byte() {
        let (mut part, _, mut clients) = booted(1);
        seat(&mut clients, &mut part, 1, Role::Owner, "owner");
        for n in 2..=7 {
            let label = ["a", "b", "phone", "phone", "c", "d"]
                .get(usize::try_from(n - 2).expect("small"))
                .copied()
                .expect("six labels");
            seat(&mut clients, &mut part, n, Role::Admin, label);
        }
        // Slot 8 is free and an admin may not take it: the lowest admin
        // slot with the label is reclaimed instead.
        assert_eq!(
            clients.place(epoch(1), None, "phone"),
            Place::Reclaim(id(4))
        );
        assert_eq!(Place::Reclaim(id(4)).slot(), Some((id(4), Role::Admin)));
        assert_eq!(clients.place(epoch(1), None, "Phone"), Place::Full);
        assert_eq!(clients.place(epoch(1), None, "phone "), Place::Full);
        // The owner's label reclaims nothing.
        assert_eq!(clients.place(epoch(1), None, "owner"), Place::Full);
        assert_eq!(Place::Full.slot(), None);
        // Nor does the viewer's.
        seat(&mut clients, &mut part, 8, Role::Viewer, "cloud");
        assert_eq!(clients.place(epoch(1), None, "cloud"), Place::Full);
        // A key already enrolled is found before any of it.
        let admin = PublicKey::from_bytes([5; KEY_BYTES]);
        assert_eq!(
            clients.place(epoch(1), Some(&admin), "owner"),
            Place::SameKey(id(5), Role::Admin)
        );
        let viewer = PublicKey::from_bytes([8; KEY_BYTES]);
        assert_eq!(
            clients.place(epoch(1), Some(&viewer), "cloud"),
            Place::SameKey(id(8), Role::Viewer)
        );
    }

    #[test]
    fn p_239_a_generation_mark_round_trips_and_names_the_next_generation() {
        for mark in [
            GenerationMark(None),
            GenerationMark(Some(generation(1))),
            GenerationMark(Some(generation(u32::MAX))),
        ] {
            assert_eq!(GenerationMark::decode(&mark.encode()), Ok(mark));
        }
        assert_eq!(GenerationMark(None).next(), Some(generation(1)));
        assert_eq!(
            GenerationMark(Some(generation(4))).next(),
            Some(generation(5))
        );
        assert_eq!(GenerationMark(Some(generation(u32::MAX))).next(), None);
    }
}
