//! `0x0003 buses and devices` through `Configuration`, on a simulated part:
//! served only once the firmware hands in its check, versioned like the
//! other sections, refused whole when invalid, and kept with its next
//! device id in one record that a cut at any byte leaves old or new.
//!
//! The check is `o89-drivers`' plan, the one the controller hands in.

use embassy_futures::block_on;
use km43::{
    Addr, BusesAndDevicesRead, BusesAndDevicesWrite, ConfigAnswer, ConfigSection, DevId,
    DeviceEntry, DeviceOptions, DeviceRole, Dialect, ErrorCode, Product, SetConfig, SetConfigAck,
    SetConfigOperation,
};
use o89_core::{
    Configuration, DRBG_BYTES, DrbgState, Generator, Kept, MAX_SECTION_READ_BYTES, Network, map,
};
use o89_drivers::plan::BUSES_CHECK;

use crate::SimFram;

fn checked(part: &mut SimFram) -> Configuration {
    let mut config = block_on(Configuration::read(part)).expect("read");
    config.check_buses_with(BUSES_CHECK);
    config
}

/// PZEM-017s on RS-485 #2 at `addrs`, each added.
fn meters(addrs: &[u8], bus: u8, out: &mut [u8]) -> usize {
    let mut write = BusesAndDevicesWrite::EMPTY;
    for addr in addrs {
        write
            .push_device(DeviceEntry {
                dev: None,
                bus,
                addr: Some(Addr::new(core::slice::from_ref(addr)).expect("an address")),
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
    part: &mut SimFram,
    operation: SetConfigOperation<'_>,
) -> Result<SetConfigAck, ErrorCode> {
    let mut network = block_on(Kept::<Network, 160>::read(map::NETWORK, part)).expect("network");
    let mut generator = Generator::new(
        block_on(Kept::<DrbgState, DRBG_BYTES>::read(map::DRBG, part)).expect("drbg"),
    );
    block_on(config.set(operation, &mut network, &mut generator, part))
}

/// The version `GetConfig` answers, and the devs its body lists.
fn read(config: &Configuration, part: &mut SimFram) -> (u32, Option<[u16; 4]>) {
    let network = block_on(Kept::<Network, 160>::read(map::NETWORK, part)).expect("network");
    let mut bytes = [0; km43::CONFIG_HEADER_BYTES + MAX_SECTION_READ_BYTES];
    let len = config
        .answer(ConfigSection::BusesAndDevices, &network, &mut bytes)
        .expect("answered");
    let answer = ConfigAnswer::decode(&bytes[..len]).expect("answer");
    let devs = answer.body().map(|body| {
        let section = BusesAndDevicesRead::decode(body).expect("a section");
        let mut devs = [0; 4];
        for (slot, device) in devs.iter_mut().zip(section.devices()) {
            *slot = device.dev.get();
        }
        devs
    });
    (answer.version(), devs)
}

/// The section's record, both copies.
fn record(part: &SimFram) -> Vec<u8> {
    let at = usize::from(map::BUSES_CONFIG.start().0)..usize::from(map::BUSES_CONFIG.end().0);
    part.bytes()[at].to_vec()
}

#[test]
fn the_section_is_unknown_until_the_firmware_checks_it() {
    let mut part = SimFram::fresh();
    let mut config = block_on(Configuration::read(&mut part)).expect("read");
    let mut out = [0; 64];
    let len = meters(&[1], 2, &mut out);
    assert_eq!(
        write(&mut config, &mut part, set(0, &out[..len])),
        Err(ErrorCode::UnknownSection)
    );
    let network = block_on(Kept::<Network, 160>::read(map::NETWORK, &mut part)).expect("read");
    let mut bytes = [0; 64];
    assert_eq!(
        config.answer(ConfigSection::BusesAndDevices, &network, &mut bytes),
        Err(ErrorCode::UnknownSection)
    );
}

#[test]
fn p_100_an_empty_site_then_a_valid_one_are_stored_and_read_back_after_a_reboot() {
    let mut part = SimFram::fresh();
    let mut config = checked(&mut part);
    assert_eq!(read(&config, &mut part), (0, None));
    let mut out = [0; 64];
    let len = meters(&[], 2, &mut out);
    let ack = write(&mut config, &mut part, set(0, &out[..len])).expect("ack");
    assert_eq!((ack.version, ack.outcome), (1, SetConfig::Accepted));
    assert_eq!(read(&config, &mut part), (1, Some([0; 4])));
    let len = meters(&[1, 2], 2, &mut out);
    let ack = write(&mut config, &mut part, set(1, &out[..len])).expect("ack");
    assert_eq!((ack.version, ack.outcome), (2, SetConfig::Accepted));
    part.reboot();
    let rebooted = checked(&mut part);
    assert_eq!(read(&rebooted, &mut part), (2, Some([1, 2, 0, 0])));
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
    let mut part = SimFram::fresh();
    let mut config = checked(&mut part);
    let mut out = [0; 64];
    let len = meters(&[1], 2, &mut out);
    let before = record(&part);
    let ack = write(&mut config, &mut part, set(7, &out[..len])).expect("ack");
    assert_eq!((ack.version, ack.outcome), (0, SetConfig::StaleVersion));
    assert_eq!(record(&part), before);
}

#[test]
fn p_265_an_invalid_write_is_refused_whole_and_stores_nothing() {
    let mut part = SimFram::fresh();
    let mut config = checked(&mut part);
    let mut out = [0; 128];
    // Nine meters on one channel, past its eight: the plan's refusal.
    let len = meters(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 2, &mut out);
    let before = record(&part);
    let ack = write(&mut config, &mut part, set(0, &out[..len])).expect("ack");
    assert_eq!((ack.version, ack.outcome), (0, SetConfig::Invalid));
    // A meter on the 1-Wire line: km43's.
    let len = meters(&[1], 7, &mut out);
    let ack = write(&mut config, &mut part, set(0, &out[..len])).expect("ack");
    assert_eq!((ack.version, ack.outcome), (0, SetConfig::Invalid));
    assert_eq!(record(&part), before);
    assert_eq!(read(&config, &mut part), (0, None));
}

#[test]
fn p_102_p_262_a_write_cut_at_every_byte_leaves_the_old_section_or_the_new_with_its_next_id() {
    let mut seed = SimFram::fresh();
    let mut config = checked(&mut seed);
    let mut out = [0; 64];
    let len = meters(&[1], 2, &mut out);
    let ack = write(&mut config, &mut seed, set(0, &out[..len])).expect("first");
    assert_eq!(ack.outcome, SetConfig::Accepted);
    seed.reboot();
    // Two added meters, the first one left out: dev 1 removed, devs 2
    // and 3 given.
    let second_len = meters(&[1, 2], 2, &mut out);
    // How many bytes the second write takes, uncut.
    let mut whole = seed.clone();
    let mut config = checked(&mut whole);
    let ack = write(&mut config, &mut whole, set(1, &out[..second_len])).expect("second");
    assert_eq!(ack.outcome, SetConfig::Accepted);
    let steps = whole.bytes_written();
    assert!(steps > 0);
    for cut in 0..=steps {
        let mut torn = seed.clone();
        let mut config = checked(&mut torn);
        torn.cut_after(cut);
        let _ = write(&mut config, &mut torn, set(1, &out[..second_len]));
        torn.reboot();
        let config = checked(&mut torn);
        let held = read(&config, &mut torn);
        let next = config
            .buses()
            .present()
            .and_then(|record| record.allocator().next())
            .map(DevId::get);
        assert!(
            matches!(
                (held, next),
                ((1, Some([1, 0, 0, 0])), Some(2)) | ((2, Some([2, 3, 0, 0])), Some(4))
            ),
            "cut {cut}: {held:?} next {next:?}"
        );
    }
}
