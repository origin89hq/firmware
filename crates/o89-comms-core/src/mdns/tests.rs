use km43::DNSSD_SERVICE;

use super::wire::{
    CLASS_IN, Header, Name, Record, Type, UNICAST_RESPONSE, Writer, name_is, record_at,
};
use super::*;

const ADDRESS: [u8; 4] = [192, 168, 1, 40];
const DEVICE: [u8; DEVICE_ID_BYTES] = [
    0x4f, 0x52, 0x49, 0x47, 0x49, 0x4e, 0x38, 0x39, 0x20, 0x44, 0x45, 0x4d, 0x4f, 0x20, 0x30, 0x31,
];
const DEVICE_TXT: &[u8] = b"\x23id=4f524947494e38392044454d4f203031";
const PHONE: Source = Source {
    addr: [192, 168, 1, 77],
    port: MDNS_PORT,
};

const HOST: [&[u8]; 2] = [b"origin89", b"local"];
const SERVICE_NAME: [&[u8]; 3] = [b"_km43", b"_tcp", b"local"];
const INSTANCE: [&[u8]; 4] = [b"origin89", b"_km43", b"_tcp", b"local"];
const SERVICES: [&[u8]; 4] = [b"_services", b"_dns-sd", b"_udp", b"local"];

fn at(millis: u64) -> Tick {
    Tick::from_millis(millis)
}

fn later(millis: u64, by: u64) -> u64 {
    millis.checked_add(by).expect("fits")
}

fn responder() -> Responder {
    Responder::new("origin89", 7).expect("a hostname")
}

/// One message, in a buffer of its own.
#[derive(Clone, Copy)]
struct Message {
    bytes: [u8; SEND_BYTES],
    len: usize,
}

impl Message {
    const EMPTY: Self = Self {
        bytes: [0; SEND_BYTES],
        len: 0,
    };

    fn of(bytes: &[u8]) -> Self {
        let mut message = Self::EMPTY;
        message.bytes[..bytes.len()].copy_from_slice(bytes);
        message.len = bytes.len();
        message
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// What a run sent, at most eight messages.
struct Sent {
    at: [u64; 8],
    messages: [Message; 8],
    to: [Destination; 8],
    count: usize,
}

impl Sent {
    fn times(&self) -> &[u64] {
        &self.at[..self.count]
    }

    fn message(&self, n: usize) -> &[u8] {
        assert!(n < self.count, "only {} sent", self.count);
        self.messages[n].bytes()
    }
}

/// Every message due from `from` to `until`, a millisecond at a time.
fn run(r: &mut Responder, from: u64, until: u64) -> Sent {
    let mut sent = Sent {
        at: [0; 8],
        messages: [Message::EMPTY; 8],
        to: [Destination::Multicast; 8],
        count: 0,
    };
    for now in from..=until {
        let mut out = [0u8; SEND_BYTES];
        while let Some(message) = r.poll(at(now), &mut out) {
            let n = sent.count;
            sent.at[n] = now;
            sent.messages[n] = Message::of(&out[..message.len]);
            sent.to[n] = message.to;
            sent.count = n.checked_add(1).expect("fits");
        }
    }
    sent
}

/// A responder that has probed and announced by `t` = 3 000.
fn announced() -> Responder {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let _ = run(&mut r, 0, 3_000);
    assert_eq!(r.phase(), Phase::Announced);
    r
}

fn header(w: &mut Writer<'_>, flags: u16, counts: [usize; 4]) {
    w.u16(0).expect("fits");
    w.u16(flags).expect("fits");
    for count in counts {
        w.u16(u16::try_from(count).expect("fits")).expect("fits");
    }
}

fn record(w: &mut Writer<'_>, name: &Name<'_>, kind: Type, ttl: u32, rdata: &[u8]) {
    w.name(name).expect("fits");
    w.u16(kind.0).expect("fits");
    w.u16(CLASS_IN).expect("fits");
    w.u32(ttl).expect("fits");
    w.u16(u16::try_from(rdata.len()).expect("fits"))
        .expect("fits");
    w.put(rdata).expect("fits");
}

/// A query for each `(name, type, unicast)`, with `known` records in its
/// answer section.
fn query(
    questions: &[(&Name<'_>, Type, bool)],
    known: &[(&Name<'_>, Type, u32, &[u8])],
) -> Message {
    let mut message = Message::EMPTY;
    let mut w = Writer::new(&mut message.bytes);
    header(&mut w, 0, [questions.len(), known.len(), 0, 0]);
    for (name, kind, unicast) in questions {
        w.name(name).expect("fits");
        w.u16(kind.0).expect("fits");
        w.u16(if *unicast {
            CLASS_IN | UNICAST_RESPONSE
        } else {
            CLASS_IN
        })
        .expect("fits");
    }
    for (name, kind, ttl, rdata) in known {
        record(&mut w, name, *kind, *ttl, rdata);
    }
    message.len = w.len();
    message
}

/// A response carrying `records` as answers.
fn response(records: &[(&Name<'_>, Type, u32, &[u8])]) -> Message {
    let mut message = Message::EMPTY;
    let mut w = Writer::new(&mut message.bytes);
    header(&mut w, 0x8400, [0, records.len(), 0, 0]);
    for (name, kind, ttl, rdata) in records {
        record(&mut w, name, *kind, *ttl, rdata);
    }
    message.len = w.len();
    message
}

/// A probe for `name` claiming `rdata` of `kind` in its authority section.
fn probe(name: &Name<'_>, kind: Type, rdata: &[u8]) -> Message {
    let mut message = Message::EMPTY;
    let mut w = Writer::new(&mut message.bytes);
    header(&mut w, 0, [1, 0, 1, 0]);
    w.name(name).expect("fits");
    w.u16(Type::ANY.0).expect("fits");
    w.u16(CLASS_IN | UNICAST_RESPONSE).expect("fits");
    record(&mut w, name, kind, 120, rdata);
    message.len = w.len();
    message
}

/// Every record of a message this side wrote, after its questions, and
/// its header.
fn records(message: &[u8]) -> (Header, [Option<Record>; 8]) {
    let header = Header::read(message).expect("a header");
    let mut at = HEADER_BYTES;
    for _ in 0..header.questions {
        let (_, next) = question_at(message, at).expect("a question");
        at = next;
    }
    let mut read = [None; 8];
    for slot in read.iter_mut().take(
        usize::from(header.answers)
            .saturating_add(usize::from(header.authorities))
            .saturating_add(usize::from(header.additionals)),
    ) {
        let (record, next) = record_at(message, at).expect("a record");
        *slot = Some(record);
        at = next;
    }
    assert_eq!(at, message.len(), "nothing trails the records");
    (header, read)
}

/// The record of `kind` named `name` in `message`.
fn find(message: &[u8], kind: Type, name: &Name<'_>) -> Record {
    let (_, read) = records(message);
    read.iter()
        .flatten()
        .find(|record| record.kind == kind && name_is(message, record.name, name).expect("reads"))
        .copied()
        .expect("the record")
}

fn rdata<'a>(message: &'a [u8], record: &Record) -> &'a [u8] {
    let end = record.rdata.checked_add(record.rdlen).expect("fits");
    &message[record.rdata..end]
}

/// The kinds of every record in `message`, in order.
fn kinds(message: &[u8]) -> [Option<Type>; 8] {
    let (_, read) = records(message);
    read.map(|record| record.map(|record| record.kind))
}

#[test]
fn p_224_the_names_are_km43s_service_and_txt_key() {
    let [service, tcp] = SERVICE;
    let (first, second) = DNSSD_SERVICE.split_once('.').expect("two labels");
    assert_eq!((service, tcp), (first.as_bytes(), second.as_bytes()));
    assert_eq!(DNSSD_TXT_DEVICE_ID, "id");
    assert_eq!(WS_PORT, 80);
}

#[test]
fn p_224_a_name_the_network_section_cannot_hold_is_refused() {
    for bad in [
        "",
        "-origin",
        "origin-",
        "ori gin",
        "a.b",
        "abcdefghijklmnopqrstuvwxyz0123456",
    ] {
        assert_eq!(Responder::new(bad, 1).err(), Some(NotAHostname), "{bad:?}");
    }
    let longest = Responder::new("abcdefghijklmnopqrstuvwxyz012345", 1).expect("32 bytes");
    assert_eq!(longest.host(), b"abcdefghijklmnopqrstuvwxyz012345");
}

#[test]
fn p_224_nothing_is_said_or_answered_without_an_address_and_a_device_id() {
    for (address, device) in [(None, Some(DEVICE)), (Some(ADDRESS), None), (None, None)] {
        let mut r = responder();
        r.observe(address, device, at(0));
        assert_eq!(r.phase(), Phase::Waiting);
        assert_eq!(run(&mut r, 0, 5_000).count, 0);
        let mut out = [0u8; SEND_BYTES];
        let asked = query(&[(&HOST, Type::A, false)], &[]);
        assert_eq!(r.received(asked.bytes(), PHONE, at(5_000), &mut out), None);
        assert_eq!(r.goodbye(&mut out), None);
    }
}

#[test]
fn p_224_three_probes_250_ms_apart_then_two_announcements_a_second_apart() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(1_000));
    let sent = run(&mut r, 1_000, 5_000);
    let first = sent.times()[0];
    assert!(
        (1_000..=1_250).contains(&first),
        "a random wait up to 250 ms: {first}"
    );
    assert_eq!(
        sent.times(),
        [0, 250, 500, 750, 1_750].map(|by| later(first, by))
    );
    assert!(
        sent.to[..sent.count]
            .iter()
            .all(|to| *to == Destination::Multicast)
    );
    // The probes: questions for both names, unicast asked, and the unique
    // records as authority without the cache-flush bit.
    for n in 0..3 {
        let probe = sent.message(n);
        let header = Header::read(probe).expect("a header");
        assert!(!header.is_response());
        assert_eq!((header.questions, header.authorities), (2, 3));
        let (q, next) = question_at(probe, HEADER_BYTES).expect("a question");
        assert!(name_is(probe, q.name, &HOST).expect("reads"));
        assert!(q.unicast && q.kind == Type::ANY);
        let (q, _) = question_at(probe, next).expect("a question");
        assert!(name_is(probe, q.name, &INSTANCE).expect("reads"));
        let (_, authority) = records(probe);
        assert!(authority.iter().flatten().all(|record| !record.flush));
    }
    assert_eq!(r.phase(), Phase::Announced);
}

#[test]
fn p_224_the_announcement_carries_every_record_with_its_ttl_and_flush_bit() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let sent = run(&mut r, 0, 3_000);
    let message = sent.message(3);
    let (header, _) = records(message);
    assert!(header.is_response());
    assert_eq!((header.flags, header.answers), (0x8400, 5));
    let a = find(message, Type::A, &HOST);
    assert_eq!(
        (rdata(message, &a), a.ttl, a.flush),
        (&ADDRESS[..], 120, true)
    );
    let srv = find(message, Type::SRV, &INSTANCE);
    assert_eq!((srv.ttl, srv.flush), (120, true));
    assert_eq!(
        rdata(message, &srv),
        b"\x00\x00\x00\x00\x00\x50\x08origin89\x05local\x00"
    );
    let txt = find(message, Type::TXT, &INSTANCE);
    assert_eq!(
        (rdata(message, &txt), txt.ttl, txt.flush),
        (DEVICE_TXT, 4_500, true)
    );
    let ptr = find(message, Type::PTR, &SERVICE_NAME);
    assert_eq!((ptr.ttl, ptr.flush), (4_500, false));
    assert_eq!(
        rdata(message, &ptr),
        b"\x08origin89\x05_km43\x04_tcp\x05local\x00"
    );
    let services = find(message, Type::PTR, &SERVICES);
    assert_eq!(rdata(message, &services), b"\x05_km43\x04_tcp\x05local\x00");
}

#[test]
fn p_224_a_browse_is_answered_with_the_pointer_and_what_resolves_it() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let asked = query(&[(&SERVICE_NAME, Type::PTR, false)], &[]);
    let answer = r
        .received(asked.bytes(), PHONE, at(10_000), &mut out)
        .expect("answered");
    assert_eq!(answer.to, Destination::Multicast);
    let message = &out[..answer.len];
    let (header, _) = records(message);
    assert_eq!((header.answers, header.additionals), (1, 3));
    assert_eq!(
        kinds(message)[..4],
        [
            Some(Type::PTR),
            Some(Type::A),
            Some(Type::SRV),
            Some(Type::TXT)
        ]
    );
}

#[test]
fn p_224_a_question_asking_for_unicast_is_answered_to_the_asker() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let asked = query(&[(&HOST, Type::A, true)], &[]);
    let answer = r
        .received(asked.bytes(), PHONE, at(10_000), &mut out)
        .expect("answered");
    assert_eq!(
        answer.to,
        Destination::Unicast {
            addr: PHONE.addr,
            port: MDNS_PORT
        }
    );
    let message = &out[..answer.len];
    assert_eq!(kinds(message)[..2], [Some(Type::A), None]);
    assert_eq!(rdata(message, &find(message, Type::A, &HOST)), ADDRESS);
}

#[test]
fn p_224_a_resolver_on_another_port_gets_its_id_and_question_back_with_short_ttls() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let mut asked = query(&[(&INSTANCE, Type::SRV, false)], &[]);
    asked.bytes[..2].copy_from_slice(&0x1234u16.to_be_bytes());
    let legacy = Source {
        addr: PHONE.addr,
        port: 40_000,
    };
    let answer = r
        .received(asked.bytes(), legacy, at(10_000), &mut out)
        .expect("answered");
    assert_eq!(
        answer.to,
        Destination::Unicast {
            addr: PHONE.addr,
            port: 40_000
        }
    );
    let message = &out[..answer.len];
    let (header, _) = records(message);
    assert_eq!(
        (header.id, header.questions, header.answers),
        (0x1234, 1, 1)
    );
    let (q, _) = question_at(message, HEADER_BYTES).expect("the question back");
    assert!(name_is(message, q.name, &INSTANCE).expect("reads"));
    let srv = find(message, Type::SRV, &INSTANCE);
    assert_eq!((srv.ttl, srv.flush), (10, false));
}

#[test]
fn p_224_what_the_asker_already_knows_is_not_sent_again() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let pointer = b"\x08origin89\x05_km43\x04_tcp\x05local\x00";
    // Known at more than half its TTL: nothing to say.
    let asked = query(
        &[(&SERVICE_NAME, Type::PTR, false)],
        &[(&SERVICE_NAME, Type::PTR, 4_000, pointer)],
    );
    assert_eq!(r.received(asked.bytes(), PHONE, at(10_000), &mut out), None);
    // Known at less than half: sent again.
    let asked = query(
        &[(&SERVICE_NAME, Type::PTR, false)],
        &[(&SERVICE_NAME, Type::PTR, 2_000, pointer)],
    );
    assert!(
        r.received(asked.bytes(), PHONE, at(10_000), &mut out)
            .is_some()
    );
    // Known with other data: sent.
    let asked = query(
        &[(&HOST, Type::A, true)],
        &[(&HOST, Type::A, 120, &[10, 0, 0, 1])],
    );
    assert!(
        r.received(asked.bytes(), PHONE, at(10_000), &mut out)
            .is_some()
    );
}

#[test]
fn p_224_a_record_is_multicast_at_most_once_a_second() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let asked = query(&[(&HOST, Type::A, false)], &[]);
    assert!(
        r.received(asked.bytes(), PHONE, at(10_000), &mut out)
            .is_some()
    );
    assert_eq!(r.received(asked.bytes(), PHONE, at(10_999), &mut out), None);
    assert!(
        r.received(asked.bytes(), PHONE, at(11_000), &mut out)
            .is_some()
    );
    // The announcement itself counts.
    let mut fresh = responder();
    fresh.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let sent = run(&mut fresh, 0, 3_000);
    let last = sent.times()[4];
    assert_eq!(
        fresh.received(asked.bytes(), PHONE, at(later(last, 500)), &mut out),
        None
    );
}

#[test]
fn p_224_questions_for_other_names_types_and_classes_are_not_answered() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let other: [&[u8]; 2] = [b"printer", b"local"];
    let mut chaos = query(&[(&HOST, Type::A, false)], &[]);
    let class_at = chaos.len.checked_sub(2).expect("a class");
    chaos.bytes[class_at..chaos.len].copy_from_slice(&3u16.to_be_bytes());
    for asked in [
        query(&[(&other, Type::A, false)], &[]),
        query(&[(&HOST, Type(28), false)], &[]),
        query(&[(&INSTANCE, Type::A, false)], &[]),
        chaos,
    ] {
        assert_eq!(r.received(asked.bytes(), PHONE, at(10_000), &mut out), None);
    }
    // A query with an opcode is ignored (RFC 6762 §18.3).
    let mut asked = query(&[(&HOST, Type::A, false)], &[]);
    asked.bytes[2] = 0x28;
    assert_eq!(r.received(asked.bytes(), PHONE, at(10_000), &mut out), None);
}

#[test]
fn p_224_a_conflict_while_probing_takes_the_next_name() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let _ = run(&mut r, 0, 300);
    assert!(matches!(r.phase(), Phase::Probing { .. }));
    let mut out = [0u8; SEND_BYTES];
    let other = response(&[(&HOST, Type::A, 120, &[192, 168, 1, 9])]);
    assert_eq!(r.received(other.bytes(), PHONE, at(301), &mut out), None);
    assert_eq!(r.host(), b"origin89-2");
    assert_eq!(r.instance(), b"origin89 (2)");
    assert_eq!(
        r.phase(),
        Phase::Probing {
            sent: 0,
            next: at(301)
        }
    );
    // The new names probe and announce in full.
    let sent = run(&mut r, 301, 3_500);
    assert_eq!(sent.count, 5);
    let announcement = sent.message(3);
    let _ = find(announcement, Type::A, &[b"origin89-2", b"local"]);
    let _ = find(
        announcement,
        Type::SRV,
        &[b"origin89 (2)", b"_km43", b"_tcp", b"local"],
    );
}

#[test]
fn p_224_a_conflict_on_the_instance_renames_both_names() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let _ = run(&mut r, 0, 300);
    let mut out = [0u8; SEND_BYTES];
    let other = response(&[(&INSTANCE, Type::TXT, 4_500, b"\x05id=00")]);
    let _ = r.received(other.bytes(), PHONE, at(301), &mut out);
    assert_eq!(
        (r.host(), r.instance()),
        (&b"origin89-2"[..], &b"origin89 (2)"[..])
    );
}

#[test]
fn p_224_our_own_records_heard_back_are_no_conflict() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let sent = run(&mut r, 0, 3_000);
    let mut out = [0u8; SEND_BYTES];
    for n in 0..sent.count {
        let _ = r.received(sent.message(n), PHONE, at(3_001), &mut out);
    }
    assert_eq!(r.phase(), Phase::Announced);
    assert_eq!(r.host(), b"origin89");
    // A goodbye for the name is no conflict either.
    let gone = response(&[(&HOST, Type::A, 0, &[192, 168, 1, 9])]);
    let _ = r.received(gone.bytes(), PHONE, at(3_002), &mut out);
    assert_eq!(r.phase(), Phase::Announced);
}

#[test]
fn p_224_a_conflict_after_announcing_probes_the_same_name_again() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let other = response(&[(&HOST, Type::A, 120, &[192, 168, 1, 9])]);
    let _ = r.received(other.bytes(), PHONE, at(10_000), &mut out);
    assert_eq!(
        r.phase(),
        Phase::Probing {
            sent: 0,
            next: at(10_000)
        }
    );
    assert_eq!(r.host(), b"origin89", "not renamed until the probe loses");
    let _ = r.received(other.bytes(), PHONE, at(10_001), &mut out);
    assert_eq!(r.host(), b"origin89-2");
}

#[test]
fn p_224_a_simultaneous_probe_with_later_data_wins_and_ours_waits_a_second() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let _ = run(&mut r, 0, 300);
    let mut out = [0u8; SEND_BYTES];
    // 192.168.1.41 sorts after ours: we defer.
    let later_data = probe(&HOST, Type::A, &[192, 168, 1, 41]);
    assert_eq!(
        r.received(later_data.bytes(), PHONE, at(400), &mut out),
        None
    );
    assert_eq!(
        r.phase(),
        Phase::Probing {
            sent: 0,
            next: at(1_400)
        }
    );
    assert_eq!(r.host(), b"origin89", "deferring is not renaming");
    // 192.168.1.39 sorts before ours: we carry on.
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let _ = run(&mut r, 0, 300);
    let before = r.phase();
    let earlier = probe(&HOST, Type::A, &[192, 168, 1, 39]);
    let _ = r.received(earlier.bytes(), PHONE, at(400), &mut out);
    assert_eq!(r.phase(), before);
    // Our own probe heard back ties, and changes nothing.
    let own = probe(&HOST, Type::A, &ADDRESS);
    let _ = r.received(own.bytes(), PHONE, at(401), &mut out);
    assert_eq!(r.phase(), before);
}

#[test]
fn p_224_an_announced_name_is_defended_against_a_probe() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let theirs = probe(&HOST, Type::A, &[192, 168, 1, 9]);
    // Within a second of the announcement, still answered: a probe is
    // defended within 250 ms.
    let answer = r
        .received(theirs.bytes(), PHONE, at(3_001), &mut out)
        .expect("defended");
    let message = &out[..answer.len];
    assert_eq!(rdata(message, &find(message, Type::A, &HOST)), ADDRESS);
}

#[test]
fn p_224_renames_stop_at_their_bound() {
    let mut r = Responder::new("abcdefghijklmnopqrstuvwxyz012345", 3).expect("a hostname");
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let mut out = [0u8; SEND_BYTES];
    for n in 1..=RENAMES {
        assert!(matches!(r.phase(), Phase::Probing { .. }), "name {n}");
        let label = r.host;
        let other = response(&[(&[label.as_bytes(), b"local"], Type::A, 120, &[10, 0, 0, 1])]);
        let _ = r.received(other.bytes(), PHONE, at(1), &mut out);
    }
    assert_eq!(r.phase(), Phase::GaveUp);
    assert_eq!(r.host(), b"abcdefghijklmnopqrstuvwxyz012345-32");
    assert_eq!(run(&mut r, 1, 5_000).count, 0);
    let asked = query(&[(&HOST, Type::A, false)], &[]);
    assert_eq!(r.received(asked.bytes(), PHONE, at(5_000), &mut out), None);
    // A new address does not revive it within the session.
    r.observe(Some([10, 0, 0, 2]), Some(DEVICE), at(5_001));
    assert_eq!(r.phase(), Phase::GaveUp);
}

#[test]
fn p_224_the_longest_names_fit_the_send_buffer() {
    let hostname = "abcdefghijklmnopqrstuvwxyz012345";
    let mut r = Responder::new(hostname, 3).expect("a hostname");
    let (host, instance) = names(hostname, RENAMES).expect("fits");
    r.n = RENAMES;
    r.host = host;
    r.instance = instance;
    r.address = Some(ADDRESS);
    r.device_id = Some(DEVICE);
    let mut out = [0u8; SEND_BYTES];
    let len = r
        .write_answers(&mut out, Kinds::ALL, Kinds::NONE, Answer::MULTICAST)
        .expect("fits");
    assert!(len <= SEND_BYTES);
    assert!(r.write_probe(&mut out).is_ok());
    assert_eq!(r.instance(), b"abcdefghijklmnopqrstuvwxyz012345 (32)");
}

#[test]
fn p_224_leaving_the_network_says_goodbye_to_every_record() {
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    let goodbye = r.goodbye(&mut out).expect("a goodbye");
    assert_eq!(goodbye.to, Destination::Multicast);
    let (header, read) = records(&out[..goodbye.len]);
    assert_eq!(header.answers, 5);
    assert!(read.iter().flatten().all(|record| record.ttl == 0));
    assert_eq!(r.phase(), Phase::Waiting);
    // Said once: nothing is claimed any more.
    assert_eq!(r.goodbye(&mut out), None);
}

#[test]
fn p_224_nothing_claimed_is_nothing_to_say_goodbye_to() {
    let mut r = responder();
    r.observe(Some(ADDRESS), Some(DEVICE), at(0));
    let _ = run(&mut r, 0, 300);
    let mut out = [0u8; SEND_BYTES];
    assert!(matches!(r.phase(), Phase::Probing { .. }));
    assert_eq!(r.goodbye(&mut out), None);
    assert_eq!(r.phase(), Phase::Waiting);
}

#[test]
fn p_224_a_new_address_or_device_id_is_announced_again() {
    let mut r = announced();
    let moved = [192, 168, 1, 41];
    r.observe(Some(moved), Some(DEVICE), at(10_000));
    let sent = run(&mut r, 10_000, 12_000);
    assert_eq!(sent.count, 2, "two announcements, no probes");
    let message = sent.message(0);
    assert_eq!(rdata(message, &find(message, Type::A, &HOST)), moved);
    let other = [0x22; DEVICE_ID_BYTES];
    r.observe(Some(moved), Some(other), at(20_000));
    let sent = run(&mut r, 20_000, 22_000);
    let message = sent.message(0);
    assert_eq!(
        rdata(message, &find(message, Type::TXT, &INSTANCE)),
        b"\x23id=22222222222222222222222222222222"
    );
    // Unchanged, nothing more.
    r.observe(Some(moved), Some(other), at(30_000));
    assert_eq!(run(&mut r, 30_000, 32_000).count, 0);
}

#[test]
fn p_224_losing_the_address_stops_answering_until_it_is_back() {
    let mut r = announced();
    r.observe(None, Some(DEVICE), at(10_000));
    assert_eq!(r.phase(), Phase::Waiting);
    let mut out = [0u8; SEND_BYTES];
    let asked = query(&[(&HOST, Type::A, false)], &[]);
    assert_eq!(r.received(asked.bytes(), PHONE, at(10_001), &mut out), None);
    assert_eq!(r.goodbye(&mut out), None, "no address to say it from");
    // Back: the names are probed again before they are answered for.
    r.observe(Some(ADDRESS), Some(DEVICE), at(20_000));
    assert!(matches!(r.phase(), Phase::Probing { .. }));
}

#[test]
fn p_224_every_cut_of_a_query_or_a_response_is_read_without_harm() {
    let asked = query(
        &[(&SERVICE_NAME, Type::PTR, false), (&HOST, Type::A, false)],
        &[(&HOST, Type::A, 120, &[10, 0, 0, 1])],
    );
    let heard = response(&[(&INSTANCE, Type::TXT, 4_500, b"\x05id=00")]);
    let contest = probe(&INSTANCE, Type::SRV, b"\x00\x00\x00\x00\x00\x50\xC0\x0C");
    for packet in [asked, heard, contest] {
        for len in 0..packet.len {
            let mut r = announced();
            let mut out = [0u8; SEND_BYTES];
            let _ = r.received(&packet.bytes[..len], PHONE, at(10_000), &mut out);
            assert_eq!(r.host(), b"origin89", "a cut packet renamed at {len}");
        }
    }
    // A pointer loop in a question.
    let mut looped = query(&[(&HOST, Type::A, false)], &[]);
    looped.bytes[12] = 0xC0;
    looped.bytes[13] = 12;
    let mut r = announced();
    let mut out = [0u8; SEND_BYTES];
    assert_eq!(
        r.received(looped.bytes(), PHONE, at(10_000), &mut out),
        None
    );
}
