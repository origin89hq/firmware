//! The station's multicast DNS responder (KM43 P-224): `<hostname>.local`
//! and one `_km43._tcp` instance, while the station holds an address.
//!
//! What it answers for, and nothing else:
//!
//! - `A` for `<host>.local`, the station's address;
//! - `PTR` from `_km43._tcp.local` to `<instance>._km43._tcp.local`, and
//!   from `_services._dns-sd._udp.local` to `_km43._tcp.local` (RFC 6763
//!   §9);
//! - `SRV` for the instance, `WS_PORT` on `<host>.local`;
//! - `TXT` for the instance, `id=` and the controller's `device_id` in
//!   lowercase hex (P-038), taken from its latest statement (L-035).
//!
//! Host and instance start as the network section's hostname. It probes
//! both names three times, 250 ms apart, before claiming them, loses a
//! simultaneous probe by RFC 6762 §8.2's comparison, and renames on a
//! conflict: `<hostname>-2.local` and `<hostname> (2)`, then 3, up to
//! [`RENAMES`]. It announces twice, a second apart, and again when its
//! address or the `device_id` changes. It answers queries by multicast, or
//! by unicast when asked (§5.4) or when the query did not come from port
//! 5353 (§6.7), leaves out what a query already knows (§7.1), and
//! multicasts no record twice within a second (§6). A conflict after
//! announcing sends it back to probing (§9). On the way off the network it
//! says goodbye, every record at TTL 0 (§10.1). Without an address it
//! answers nothing and says nothing: there is nobody to say it from.
//!
//! Not done: the 20 to 120 ms delay before answering a shared record (§6,
//! a SHOULD), negative answers for types it lacks (§6.1), and IPv6.
//!
//! Sans I/O: the firmware hands in received packets, the address, the
//! `device_id` and the [`Tick`], and sends what comes back.

mod wire;

use km43::{DNSSD_TXT_DEVICE_ID, Hostname, WS_PORT};
use o89_link::{DEVICE_ID_BYTES, Millis, Tick};

use wire::{
    AUTHORITATIVE, CACHE_FLUSH, CLASS_IN, HEADER_BYTES, Header, Malformed, QR, Question, Record,
    Type, UNICAST_RESPONSE, Writer, canonical_rdata, name_is, question_at, record_at,
};

/// The multicast DNS port (RFC 6762 §3).
pub const MDNS_PORT: u16 = 5353;
/// The IPv4 multicast group (RFC 6762 §3).
pub const MDNS_GROUP: [u8; 4] = [224, 0, 0, 251];
/// The longest packet read: one Ethernet MTU of UDP payload. Longer
/// packets arrive fragmented, if at all, and are not read.
pub const RECEIVE_BYTES: usize = 1_472;
/// The longest message this side writes: every record, uncompressed, with
/// the longest names a hostname and a rename allow. A test holds it to
/// that.
pub const SEND_BYTES: usize = 512;
/// Renames on conflict before the responder stops advertising for the
/// session, rather than cycle names on a network that contests them all.
pub const RENAMES: u8 = 32;

/// Probes before a name is claimed, and the gap between them (§8.1).
const PROBES: u8 = 3;
const PROBE_GAP: Millis = Millis::from_millis(250);
/// The random wait before the first probe is up to this long (§8.1).
const PROBE_JITTER_MS: u32 = 250;
/// A probe lost to a simultaneous one waits this long (§8.2).
const DEFER: Millis = Millis::from_millis(1_000);
/// Announcements and the gap between them (§8.3).
const ANNOUNCEMENTS: u8 = 2;
const ANNOUNCE_GAP: Millis = Millis::from_millis(1_000);
/// A record is not multicast again within this long (§6), or within
/// [`PROBE_DEFENCE`] when a probe claims it.
const MULTICAST_GAP: Millis = Millis::from_millis(1_000);
const PROBE_DEFENCE: Millis = Millis::from_millis(250);
/// Records naming a host are kept 120 s, the others 75 min (§10).
const HOST_TTL: u32 = 120;
const OTHER_TTL: u32 = 4_500;
/// TTLs in answers to a query from another port (§6.7).
const LEGACY_TTL: u32 = 10;
/// Questions and records read from one packet; the rest are not read.
const ITEMS: usize = 64;
/// Records of one name kept for a §8.2 comparison.
const CONTENDERS: usize = 4;
/// A name's data written out in full.
const RDATA_BYTES: usize = 300;
/// The longest label: a hostname, a space and `(32)`, or a hyphen and 32.
const LABEL_BYTES: usize = 40;

/// The service's labels, `DNSSD_SERVICE` split at its dot; a test holds
/// them to it.
const SERVICE: [&[u8]; 2] = [b"_km43", b"_tcp"];
const LOCAL: &[u8] = b"local";
const ENUMERATION: [&[u8]; 4] = [b"_services", b"_dns-sd", b"_udp", LOCAL];

/// Where a message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// The group, on [`MDNS_PORT`].
    Multicast,
    /// One host.
    Unicast {
        /// Its address.
        addr: [u8; 4],
        /// Its port.
        port: u16,
    },
}

/// A message written into the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a message nobody sends is a probe, an answer or a goodbye lost"]
pub struct Outgoing {
    /// Its length in the buffer.
    pub len: usize,
    /// Where it goes.
    pub to: Destination,
}

/// Where a received packet came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// Its address.
    pub addr: [u8; 4],
    /// Its port: anything but [`MDNS_PORT`] is a legacy resolver (§6.7).
    pub port: u16,
}

/// What the responder is doing with its names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No address, or no `device_id` yet: nothing to advertise.
    Waiting,
    /// Checking the names are free.
    Probing {
        /// Probes sent for these names.
        sent: u8,
        /// When the next goes.
        next: Tick,
    },
    /// The names are this side's; telling the network.
    Announcing {
        /// Announcements sent.
        sent: u8,
        /// When the next goes.
        next: Tick,
    },
    /// Answering.
    Announced,
    /// Every name up to [`RENAMES`] was contested; nothing more this
    /// session.
    GaveUp,
}

/// The network section's hostname does not make a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAHostname;

/// One of the records this side holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Address,
    Service,
    Text,
    Pointer,
    Enumeration,
}

impl Kind {
    const ALL: [Self; 5] = [
        Self::Address,
        Self::Service,
        Self::Text,
        Self::Pointer,
        Self::Enumeration,
    ];

    const fn bit(self) -> u8 {
        match self {
            Self::Address => 1,
            Self::Service => 2,
            Self::Text => 4,
            Self::Pointer => 8,
            Self::Enumeration => 16,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Address => 0,
            Self::Service => 1,
            Self::Text => 2,
            Self::Pointer => 3,
            Self::Enumeration => 4,
        }
    }

    const fn kind(self) -> Type {
        match self {
            Self::Address => Type::A,
            Self::Service => Type::SRV,
            Self::Text => Type::TXT,
            Self::Pointer | Self::Enumeration => Type::PTR,
        }
    }

    /// Unique to this host, so written with the cache-flush bit (§10.2).
    const fn unique(self) -> bool {
        match self {
            Self::Address | Self::Service | Self::Text => true,
            Self::Pointer | Self::Enumeration => false,
        }
    }

    const fn ttl(self) -> u32 {
        match self {
            Self::Address | Self::Service => HOST_TTL,
            Self::Text | Self::Pointer | Self::Enumeration => OTHER_TTL,
        }
    }
}

/// A set of [`Kind`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Kinds(u8);

impl Kinds {
    const NONE: Self = Self(0);
    const ALL: Self = Self(0x1F);

    const fn has(self, kind: Kind) -> bool {
        self.0 & kind.bit() != 0
    }

    const fn with(self, kind: Kind) -> Self {
        Self(self.0 | kind.bit())
    }

    const fn without(self, kind: Kind) -> Self {
        Self(self.0 & !kind.bit())
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One label, bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Label {
    bytes: [u8; LABEL_BYTES],
    len: usize,
}

impl Label {
    /// `base`, then `separator` and `n` unless `n` is 1, then `close`.
    fn numbered(base: &str, n: u8, separator: &[u8], close: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; LABEL_BYTES];
        let mut w = Writer::new(&mut bytes);
        w.put(base.as_bytes()).ok()?;
        if n > 1 {
            w.put(separator).ok()?;
            let digits = [b'0'.checked_add(n / 10)?, b'0'.checked_add(n % 10)?];
            w.put(if n < 10 { digits.get(1..)? } else { &digits })
                .ok()?;
            w.put(close).ok()?;
        }
        let len = w.len();
        Some(Self { bytes, len })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// The responder for one station session.
#[derive(Debug, Clone)]
pub struct Responder {
    hostname: [u8; km43::MAX_HOSTNAME],
    hostname_len: usize,
    /// Which name this is: 1 for the hostname itself.
    n: u8,
    host: Label,
    instance: Label,
    address: Option<[u8; 4]>,
    device_id: Option<[u8; DEVICE_ID_BYTES]>,
    phase: Phase,
    /// When each record was last multicast (§6), by [`Kind::index`].
    multicast: [Option<Tick>; 5],
    random: u32,
}

impl Responder {
    /// A responder for `hostname`, the network section's. `seed` spreads
    /// the first probe across its 250 ms, so units powered together do not
    /// probe in step.
    pub fn new(hostname: &str, seed: u32) -> Result<Self, NotAHostname> {
        let hostname_text = Hostname::new(hostname).map_err(|_| NotAHostname)?.as_str();
        let mut stored = [0u8; km43::MAX_HOSTNAME];
        let hostname_len = hostname_text.len();
        stored
            .get_mut(..hostname_len)
            .ok_or(NotAHostname)?
            .copy_from_slice(hostname_text.as_bytes());
        let (host, instance) = names(hostname_text, 1).ok_or(NotAHostname)?;
        Ok(Self {
            hostname: stored,
            hostname_len,
            n: 1,
            host,
            instance,
            address: None,
            device_id: None,
            phase: Phase::Waiting,
            multicast: [None; 5],
            random: seed | 1,
        })
    }

    /// What it is doing.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// The host label it holds now, without `.local`.
    #[must_use]
    pub fn host(&self) -> &[u8] {
        self.host.as_bytes()
    }

    /// The instance label it holds now.
    #[must_use]
    pub fn instance(&self) -> &[u8] {
        self.instance.as_bytes()
    }

    /// When [`Responder::poll`] next has something to send.
    #[must_use]
    pub const fn due(&self) -> Option<Tick> {
        match self.phase {
            Phase::Probing { next, .. } | Phase::Announcing { next, .. } => Some(next),
            Phase::Waiting | Phase::Announced | Phase::GaveUp => None,
        }
    }

    /// The station's address and the controller's `device_id` as they
    /// stand at `now`. The first time both are known it starts probing; a
    /// change to either once claimed is announced again (§8.4); losing the
    /// address stops everything, since nothing can be sent without it.
    pub fn observe(
        &mut self,
        address: Option<[u8; 4]>,
        device_id: Option<[u8; DEVICE_ID_BYTES]>,
        now: Tick,
    ) {
        let changed = (address, device_id) != (self.address, self.device_id);
        self.address = address;
        self.device_id = device_id;
        if address.is_none() || device_id.is_none() {
            if !matches!(self.phase, Phase::GaveUp) {
                self.phase = Phase::Waiting;
            }
            return;
        }
        match self.phase {
            Phase::Waiting => self.probe_from(now),
            Phase::Announcing { .. } | Phase::Announced if changed => {
                self.phase = Phase::Announcing { sent: 0, next: now };
            }
            Phase::Probing { .. } | Phase::Announcing { .. } | Phase::Announced | Phase::GaveUp => {
            }
        }
    }

    /// What is due at `now`, a probe or an announcement, written into
    /// `out`.
    pub fn poll(&mut self, now: Tick, out: &mut [u8]) -> Option<Outgoing> {
        match self.phase {
            Phase::Probing { sent, next } if now.since(next).is_some() => {
                if sent >= PROBES {
                    self.phase = Phase::Announcing { sent: 0, next: now };
                    return self.poll(now, out);
                }
                let len = self.write_probe(out).ok()?;
                self.phase = Phase::Probing {
                    sent: sent.saturating_add(1),
                    next: next.after(PROBE_GAP).unwrap_or(now),
                };
                Some(Outgoing {
                    len,
                    to: Destination::Multicast,
                })
            }
            Phase::Announcing { sent, next } if now.since(next).is_some() => {
                let len = self.write_answers(out, Kinds::ALL, Kinds::NONE, Answer::MULTICAST)?;
                self.multicast = [Some(now); 5];
                let sent = sent.saturating_add(1);
                self.phase = if sent >= ANNOUNCEMENTS {
                    Phase::Announced
                } else {
                    Phase::Announcing {
                        sent,
                        next: now.after(ANNOUNCE_GAP).unwrap_or(now),
                    }
                };
                Some(Outgoing {
                    len,
                    to: Destination::Multicast,
                })
            }
            Phase::Probing { .. }
            | Phase::Announcing { .. }
            | Phase::Waiting
            | Phase::Announced
            | Phase::GaveUp => None,
        }
    }

    /// A packet from `from` at `now`: a response is checked for a
    /// conflict with the names this side holds, a query answered once they
    /// are claimed, and a probe for them compared with this side's while
    /// it probes. The answer, if any, is written into `out`.
    pub fn received(
        &mut self,
        packet: &[u8],
        from: Source,
        now: Tick,
        out: &mut [u8],
    ) -> Option<Outgoing> {
        if matches!(self.phase, Phase::Waiting | Phase::GaveUp) {
            return None;
        }
        let header = Header::read(packet).ok()?;
        if header.is_response() {
            if self.conflicts(packet, &header).unwrap_or(false) {
                self.conflict(now);
            }
            return None;
        }
        if from.port == MDNS_PORT && header.flags & !UNICAST_RESPONSE != 0 {
            // A query with an opcode or code set is ignored (§18.3).
            return None;
        }
        match self.phase {
            Phase::Probing { .. } => {
                if self.loses_probe(packet, &header).unwrap_or(false) {
                    self.phase = Phase::Probing {
                        sent: 0,
                        next: now.after(DEFER).unwrap_or(now),
                    };
                }
                None
            }
            Phase::Announcing { .. } | Phase::Announced => {
                self.answer(packet, &header, from, now, out)
            }
            Phase::Waiting | Phase::GaveUp => None,
        }
    }

    /// Every record at TTL 0, to be sent before the station leaves the
    /// network (§10.1), and the responder waiting again. Nothing when no
    /// record was ever claimed.
    pub fn goodbye(&mut self, out: &mut [u8]) -> Option<Outgoing> {
        let claimed = matches!(self.phase, Phase::Announcing { .. } | Phase::Announced);
        if !matches!(self.phase, Phase::GaveUp) {
            self.phase = Phase::Waiting;
        }
        if !claimed || self.address.is_none() {
            return None;
        }
        let len = self.write_answers(out, Kinds::ALL, Kinds::NONE, Answer::GOODBYE)?;
        Some(Outgoing {
            len,
            to: Destination::Multicast,
        })
    }

    fn probe_from(&mut self, now: Tick) {
        self.random ^= self.random << 13;
        self.random ^= self.random >> 17;
        self.random ^= self.random << 5;
        let wait = self
            .random
            .checked_rem(PROBE_JITTER_MS.saturating_add(1))
            .unwrap_or(0);
        self.phase = Phase::Probing {
            sent: 0,
            next: now
                .after(Millis::from_millis(u64::from(wait)))
                .unwrap_or(now),
        };
    }

    /// Another host holds one of these names: take the next and probe it.
    fn conflict(&mut self, now: Tick) {
        match self.phase {
            Phase::Probing { .. } => {
                let next = self.n.saturating_add(1);
                let renamed = self.hostname().and_then(|hostname| names(hostname, next));
                match renamed {
                    Some((host, instance)) if next <= RENAMES => {
                        self.n = next;
                        self.host = host;
                        self.instance = instance;
                        self.phase = Phase::Probing { sent: 0, next: now };
                    }
                    Some(_) | None => self.phase = Phase::GaveUp,
                }
            }
            // A claimed name is probed again before it is given up (§9).
            Phase::Announcing { .. } | Phase::Announced => {
                self.phase = Phase::Probing { sent: 0, next: now };
            }
            Phase::Waiting | Phase::GaveUp => {}
        }
    }

    fn hostname(&self) -> Option<&str> {
        core::str::from_utf8(self.hostname.get(..self.hostname_len)?).ok()
    }

    fn host_name(&self) -> [&[u8]; 2] {
        [self.host.as_bytes(), LOCAL]
    }

    fn instance_name(&self) -> [&[u8]; 4] {
        let [service, tcp] = SERVICE;
        [self.instance.as_bytes(), service, tcp, LOCAL]
    }

    /// Whether a response holds a record with one of this side's unique
    /// names and types but other data (§9); while probing, any record of
    /// those names and types (§8.1).
    fn conflicts(&self, packet: &[u8], header: &Header) -> Result<bool, Malformed> {
        let mut at = skip_questions(packet, header)?;
        let records = usize::from(header.answers)
            .saturating_add(usize::from(header.authorities))
            .saturating_add(usize::from(header.additionals));
        for _ in 0..records.min(ITEMS) {
            let (record, next) = record_at(packet, at)?;
            at = next;
            if record.class != CLASS_IN || record.ttl == 0 {
                continue;
            }
            for kind in [Kind::Address, Kind::Service, Kind::Text] {
                if record.kind == kind.kind()
                    && self.names_record(packet, &record, kind)?
                    && !self.same_data(packet, &record, kind)?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether a query probing one of this side's names carries data that
    /// sorts before this side's (§8.2), so this side waits and probes again.
    fn loses_probe(&self, packet: &[u8], header: &Header) -> Result<bool, Malformed> {
        let mut at = HEADER_BYTES;
        for _ in 0..usize::from(header.questions).min(ITEMS) {
            let (_, next) = question_at(packet, at)?;
            at = next;
        }
        at = skip_records(packet, at, header.answers)?;
        let mut theirs_host = Contenders::default();
        let mut theirs_instance = Contenders::default();
        for _ in 0..usize::from(header.authorities).min(ITEMS) {
            let (record, next) = record_at(packet, at)?;
            at = next;
            if name_is(packet, record.name, &self.host_name())? {
                theirs_host.push(packet, &record)?;
            } else if name_is(packet, record.name, &self.instance_name())? {
                theirs_instance.push(packet, &record)?;
            }
        }
        let mut ours_host = Contenders::default();
        let mut ours_instance = Contenders::default();
        if !theirs_host.is_empty() {
            ours_host.push_ours(self, Kind::Address)?;
        }
        if !theirs_instance.is_empty() {
            ours_instance.push_ours(self, Kind::Service)?;
            ours_instance.push_ours(self, Kind::Text)?;
        }
        Ok(theirs_host.beats(&ours_host) || theirs_instance.beats(&ours_instance))
    }

    fn answer(
        &mut self,
        packet: &[u8],
        header: &Header,
        from: Source,
        now: Tick,
        out: &mut [u8],
    ) -> Option<Outgoing> {
        let mut at = HEADER_BYTES;
        let mut wanted = Kinds::NONE;
        let mut unicast = true;
        for _ in 0..usize::from(header.questions).min(ITEMS) {
            let (question, next) = question_at(packet, at).ok()?;
            at = next;
            let matched = self.matches(packet, &question).ok()?;
            if !matched.is_empty() {
                wanted = Kinds(wanted.0 | matched.0);
                unicast &= question.unicast;
            }
        }
        let questions_end = at;
        // Known answers (§7.1): what the querier holds at half its TTL
        // or more is not sent again.
        for _ in 0..usize::from(header.answers).min(ITEMS) {
            let (record, next) = record_at(packet, at).ok()?;
            at = next;
            for kind in Kind::ALL {
                if wanted.has(kind)
                    && record.kind == kind.kind()
                    && record.ttl >= kind.ttl() / 2
                    && self.names_record(packet, &record, kind).ok()?
                    && self.same_data(packet, &record, kind).ok()?
                {
                    wanted = wanted.without(kind);
                }
            }
        }
        if wanted.is_empty() {
            return None;
        }
        let legacy = from.port != MDNS_PORT;
        if legacy {
            let echo = packet.get(HEADER_BYTES..questions_end)?;
            let len = self.write_legacy(out, header, echo, wanted)?;
            return Some(Outgoing {
                len,
                to: Destination::Unicast {
                    addr: from.addr,
                    port: from.port,
                },
            });
        }
        if unicast {
            let len =
                self.write_answers(out, wanted, Self::additionals(wanted), Answer::MULTICAST)?;
            return Some(Outgoing {
                len,
                to: Destination::Unicast {
                    addr: from.addr,
                    port: from.port,
                },
            });
        }
        let gap = if header.authorities > 0 {
            PROBE_DEFENCE
        } else {
            MULTICAST_GAP
        };
        for kind in Kind::ALL {
            let recent = self
                .multicast
                .get(kind.index())
                .copied()
                .flatten()
                .and_then(|last| now.since(last))
                .is_some_and(|since| since.as_millis() < gap.as_millis());
            if recent {
                wanted = wanted.without(kind);
            }
        }
        if wanted.is_empty() {
            return None;
        }
        let len = self.write_answers(out, wanted, Self::additionals(wanted), Answer::MULTICAST)?;
        for kind in Kind::ALL {
            if wanted.has(kind)
                && let Some(last) = self.multicast.get_mut(kind.index())
            {
                *last = Some(now);
            }
        }
        Some(Outgoing {
            len,
            to: Destination::Multicast,
        })
    }

    /// The records a question asks for.
    fn matches(&self, packet: &[u8], question: &Question) -> Result<Kinds, Malformed> {
        if question.class != CLASS_IN && question.class != 255 {
            return Ok(Kinds::NONE);
        }
        let any = question.kind == Type::ANY;
        let mut kinds = Kinds::NONE;
        if name_is(packet, question.name, &self.host_name())? && (any || question.kind == Type::A) {
            kinds = kinds.with(Kind::Address);
        }
        let [service, tcp] = SERVICE;
        if name_is(packet, question.name, &[service, tcp, LOCAL])?
            && (any || question.kind == Type::PTR)
        {
            kinds = kinds.with(Kind::Pointer);
        }
        if name_is(packet, question.name, &self.instance_name())? {
            if any || question.kind == Type::SRV {
                kinds = kinds.with(Kind::Service);
            }
            if any || question.kind == Type::TXT {
                kinds = kinds.with(Kind::Text);
            }
        }
        if name_is(packet, question.name, &ENUMERATION)? && (any || question.kind == Type::PTR) {
            kinds = kinds.with(Kind::Enumeration);
        }
        Ok(kinds)
    }

    /// What goes with an answer so the querier need not ask again
    /// (RFC 6763 §12).
    fn additionals(answers: Kinds) -> Kinds {
        let mut more = Kinds::NONE;
        if answers.has(Kind::Pointer) {
            more = more
                .with(Kind::Service)
                .with(Kind::Text)
                .with(Kind::Address);
        }
        if answers.has(Kind::Service) {
            more = more.with(Kind::Address);
        }
        Kinds(more.0 & !answers.0)
    }

    /// Whether `record` is named as this side's record of `kind` is.
    fn names_record(&self, packet: &[u8], record: &Record, kind: Kind) -> Result<bool, Malformed> {
        let [service, tcp] = SERVICE;
        match kind {
            Kind::Address => name_is(packet, record.name, &self.host_name()),
            Kind::Service | Kind::Text => name_is(packet, record.name, &self.instance_name()),
            Kind::Pointer => name_is(packet, record.name, &[service, tcp, LOCAL]),
            Kind::Enumeration => name_is(packet, record.name, &ENUMERATION),
        }
    }

    /// Whether `record` carries the data this side's record of `kind` does.
    fn same_data(&self, packet: &[u8], record: &Record, kind: Kind) -> Result<bool, Malformed> {
        let mut theirs = [0u8; RDATA_BYTES];
        let mut theirs = Writer::new(&mut theirs);
        canonical_rdata(packet, record, &mut theirs)?;
        let mut ours = [0u8; RDATA_BYTES];
        let mut ours = Writer::new(&mut ours);
        self.rdata(kind, &mut ours).map_err(|_| Malformed)?;
        Ok(theirs.written().eq_ignore_ascii_case(ours.written()))
    }

    fn rdata(&self, kind: Kind, out: &mut Writer<'_>) -> Result<(), wire::Full> {
        match kind {
            Kind::Address => out.put(&self.address.ok_or(wire::Full)?),
            Kind::Service => {
                out.u16(0)?;
                out.u16(0)?;
                out.u16(WS_PORT)?;
                out.name(&self.host_name())
            }
            Kind::Text => {
                let id = self.device_id.ok_or(wire::Full)?;
                let key = DNSSD_TXT_DEVICE_ID.as_bytes();
                let len = key
                    .len()
                    .saturating_add(1)
                    .saturating_add(DEVICE_ID_BYTES * 2);
                out.put(&[u8::try_from(len).map_err(|_| wire::Full)?])?;
                out.put(key)?;
                out.put(b"=")?;
                for byte in id {
                    out.put(&hex(byte))?;
                }
                Ok(())
            }
            Kind::Pointer => out.name(&self.instance_name()),
            Kind::Enumeration => {
                let [service, tcp] = SERVICE;
                out.name(&[service, tcp, LOCAL])
            }
        }
    }

    fn write_record(
        &self,
        w: &mut Writer<'_>,
        kind: Kind,
        answer: Answer,
    ) -> Result<(), wire::Full> {
        let [service, tcp] = SERVICE;
        match kind {
            Kind::Address => w.name(&self.host_name())?,
            Kind::Service | Kind::Text => w.name(&self.instance_name())?,
            Kind::Pointer => w.name(&[service, tcp, LOCAL])?,
            Kind::Enumeration => w.name(&ENUMERATION)?,
        }
        w.u16(kind.kind().0)?;
        let flush = kind.unique() && answer.flush;
        w.u16(if flush {
            CLASS_IN | CACHE_FLUSH
        } else {
            CLASS_IN
        })?;
        w.u32(answer.ttl.map_or(kind.ttl(), |ttl| ttl.min(kind.ttl())))?;
        let length_at = w.len();
        w.u16(0)?;
        self.rdata(kind, w)?;
        let rdlen = w
            .len()
            .checked_sub(length_at)
            .and_then(|len| len.checked_sub(2))
            .and_then(|len| u16::try_from(len).ok())
            .ok_or(wire::Full)?;
        w.patch_u16(length_at, rdlen)
    }

    /// A response carrying `answers` and `additionals`.
    fn write_answers(
        &self,
        out: &mut [u8],
        answers: Kinds,
        additionals: Kinds,
        answer: Answer,
    ) -> Option<usize> {
        let mut w = Writer::new(out);
        let count = |set: Kinds| Kind::ALL.iter().filter(|kind| set.has(**kind)).count();
        w.u16(0).ok()?;
        w.u16(QR | AUTHORITATIVE).ok()?;
        w.u16(0).ok()?;
        w.u16(u16::try_from(count(answers)).ok()?).ok()?;
        w.u16(0).ok()?;
        w.u16(u16::try_from(count(additionals)).ok()?).ok()?;
        for set in [answers, additionals] {
            for kind in Kind::ALL {
                if set.has(kind) {
                    self.write_record(&mut w, kind, answer).ok()?;
                }
            }
        }
        Some(w.len())
    }

    /// An answer to a resolver on another port (§6.7): its id and
    /// questions back, no cache-flush bit, and short TTLs.
    fn write_legacy(
        &self,
        out: &mut [u8],
        header: &Header,
        echo: &[u8],
        answers: Kinds,
    ) -> Option<usize> {
        let mut w = Writer::new(out);
        let count = Kind::ALL.iter().filter(|kind| answers.has(**kind)).count();
        w.u16(header.id).ok()?;
        w.u16(QR | AUTHORITATIVE).ok()?;
        w.u16(header.questions).ok()?;
        w.u16(u16::try_from(count).ok()?).ok()?;
        w.u16(0).ok()?;
        w.u16(0).ok()?;
        // Offsets in the questions stay where they were, so their pointers
        // still reach the names they meant.
        w.put(echo).ok()?;
        for kind in Kind::ALL {
            if answers.has(kind) {
                self.write_record(&mut w, kind, Answer::LEGACY).ok()?;
            }
        }
        Some(w.len())
    }

    /// Two questions for the names, any type, unicast answers asked, and
    /// this side's unique records as their authority (§8.1, §8.2).
    fn write_probe(&self, out: &mut [u8]) -> Result<usize, wire::Full> {
        let mut w = Writer::new(out);
        w.u16(0)?;
        w.u16(0)?;
        w.u16(2)?;
        w.u16(0)?;
        w.u16(3)?;
        w.u16(0)?;
        for name in [&self.host_name()[..], &self.instance_name()[..]] {
            w.name(name)?;
            w.u16(Type::ANY.0)?;
            w.u16(CLASS_IN | UNICAST_RESPONSE)?;
        }
        for kind in [Kind::Address, Kind::Service, Kind::Text] {
            self.write_record(&mut w, kind, Answer::PROBE)?;
        }
        Ok(w.len())
    }
}

/// How records are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Answer {
    flush: bool,
    /// A cap on the TTL, or its own.
    ttl: Option<u32>,
}

impl Answer {
    const MULTICAST: Self = Self {
        flush: true,
        ttl: None,
    };
    const GOODBYE: Self = Self {
        flush: true,
        ttl: Some(0),
    };
    const LEGACY: Self = Self {
        flush: false,
        ttl: Some(LEGACY_TTL),
    };
    const PROBE: Self = Self {
        flush: false,
        ttl: None,
    };
}

/// One side's records of a name, as §8.2 compares them: sorted by class,
/// type and data written out.
#[derive(Debug, Clone, Copy, Default)]
struct Contenders {
    records: [Option<Contender>; CONTENDERS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Contender {
    class: u16,
    kind: Type,
    data: [u8; RDATA_BYTES],
    len: usize,
}

impl Contender {
    fn data(&self) -> &[u8] {
        self.data.get(..self.len).unwrap_or_default()
    }

    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.class, self.kind)
            .cmp(&(other.class, other.kind))
            .then_with(|| self.data().cmp(other.data()))
    }
}

impl Contenders {
    fn is_empty(&self) -> bool {
        self.records.iter().all(Option::is_none)
    }

    fn insert(&mut self, contender: &Contender) {
        // Kept sorted; one past the capacity is not compared.
        let mut carry = Some(*contender);
        for slot in &mut self.records {
            match (slot.as_mut(), carry) {
                (_, None) => break,
                (None, Some(new)) => {
                    *slot = Some(new);
                    carry = None;
                }
                (Some(held), Some(new)) => {
                    if new.cmp(held).is_lt() {
                        carry = Some(core::mem::replace(held, new));
                    }
                }
            }
        }
    }

    fn push(&mut self, packet: &[u8], record: &Record) -> Result<(), Malformed> {
        let mut data = [0u8; RDATA_BYTES];
        let mut w = Writer::new(&mut data);
        canonical_rdata(packet, record, &mut w)?;
        let len = w.len();
        self.insert(&Contender {
            class: record.class,
            kind: record.kind,
            data,
            len,
        });
        Ok(())
    }

    fn push_ours(&mut self, responder: &Responder, kind: Kind) -> Result<(), Malformed> {
        let mut data = [0u8; RDATA_BYTES];
        let mut w = Writer::new(&mut data);
        responder.rdata(kind, &mut w).map_err(|_| Malformed)?;
        let len = w.len();
        self.insert(&Contender {
            class: CLASS_IN,
            kind: kind.kind(),
            data,
            len,
        });
        Ok(())
    }

    /// Whether `self` is lexicographically later than `ours`: records
    /// compared in order, and the side with records left over is later.
    /// Identical sets are this side's own probe heard back, and lose to
    /// nobody.
    fn beats(&self, ours: &Self) -> bool {
        if self.is_empty() {
            return false;
        }
        for (theirs, mine) in self.records.iter().zip(ours.records.iter()) {
            match (theirs, mine) {
                (Some(theirs), Some(mine)) => match theirs.cmp(mine) {
                    core::cmp::Ordering::Greater => return true,
                    core::cmp::Ordering::Less => return false,
                    core::cmp::Ordering::Equal => {}
                },
                (Some(_), None) => return true,
                (None, Some(_) | None) => return false,
            }
        }
        false
    }
}

fn skip_questions(packet: &[u8], header: &Header) -> Result<usize, Malformed> {
    let mut at = HEADER_BYTES;
    for _ in 0..usize::from(header.questions).min(ITEMS) {
        let (_, next) = question_at(packet, at)?;
        at = next;
    }
    Ok(at)
}

fn skip_records(packet: &[u8], mut at: usize, count: u16) -> Result<usize, Malformed> {
    for _ in 0..usize::from(count).min(ITEMS) {
        let (_, next) = record_at(packet, at)?;
        at = next;
    }
    Ok(at)
}

/// The host and instance labels for name `n` of `hostname`.
fn names(hostname: &str, n: u8) -> Option<(Label, Label)> {
    Some((
        Label::numbered(hostname, n, b"-", b"")?,
        Label::numbered(hostname, n, b" (", b")")?,
    ))
}

/// A byte in lowercase hex, as P-038 renders a `device_id`.
fn hex(byte: u8) -> [u8; 2] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digit = |nibble: u8| DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
    [digit(byte >> 4), digit(byte & 0x0F)]
}

#[cfg(test)]
mod tests;
