//! The bench tool: the controller's FRAM, NOR and module rail from a
//! laptop, over SWD, through the mailbox the running firmware serves.
//!
//! Nothing here touches a part behind the firmware's back. A byte written
//! to the FRAM goes through the recorder task and the same seam the store
//! writes through, so the voltage detector's refusal and the bus's answer
//! are the firmware's own; and a record written from here is framed by
//! `o89-core`'s own `Record`, so an epoch the bench lands is one the boot
//! reads the way it reads its own. The one thing read straight from the
//! part is the rail's pin, which is the point (#4): what the registers
//! say, and what that means on the revision, as two fields.
//!
//! The probe-rs release is the one the recipes flash with, pinned in the
//! workspace manifest.

mod flash;
mod layout;
mod link;
mod rail;
mod store;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use o89_core::Revision;
use o89_core::mailbox::DownloadEntry;

/// The route into the module's ROM, on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Entry {
    /// Knock at the window the comms firmware opens.
    Knock,
    /// Hold IO9 low across the reset; IO8 must be high, a wire on revision A.
    Strap,
    /// Reset and listen; the ROM never enters its loader by itself.
    Reset,
}

impl From<Entry> for DownloadEntry {
    fn from(entry: Entry) -> Self {
        match entry {
            Entry::Knock => Self::Knock,
            Entry::Strap => Self::Strap,
            Entry::Reset => Self::Reset,
        }
    }
}

/// The routes into the ROM's loader, the only ones a flash can take: a plain
/// reset boots whatever the module holds, and the ROM never waits in its
/// loader by itself, so esptool would find nothing to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FlashEntry {
    /// Knock at the window the comms firmware opens.
    Knock,
    /// Hold IO9 low across the reset; IO8 must be high, a wire on revision A.
    Strap,
}

impl From<FlashEntry> for DownloadEntry {
    fn from(entry: FlashEntry) -> Self {
        match entry {
            FlashEntry::Knock => Self::Knock,
            FlashEntry::Strap => Self::Strap,
        }
    }
}

use crate::link::Link;

/// The controller's FRAM, NOR and rail over SWD, through the firmware.
#[derive(Debug, Parser)]
#[command(name = "o89-dev", version, about)]
struct Cli {
    /// The probe's serial number, when more than one is plugged in.
    #[arg(long, global = true)]
    probe: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The probes plugged in.
    Probes,
    /// Attach and ask the firmware for its boot count.
    Ping,
    /// The store: every record on the FRAM, decoded, or one of them written.
    Store {
        #[command(subcommand)]
        what: Option<StoreCommand>,
    },
    /// The module rail: the pin as the registers say, and what that means
    /// on the board revision.
    Rail {
        /// The board revision, which decides what a pin nobody drives means.
        #[arg(long)]
        revision: RevisionArg,
    },
    /// Bytes of the FRAM, in hex.
    Fram {
        /// The first address.
        #[arg(long, default_value_t = 0)]
        at: u16,
        /// How many bytes.
        #[arg(long, default_value_t = 256)]
        len: u16,
    },
    /// Bytes of the NOR, in hex.
    Nor {
        /// The first address.
        #[arg(long, default_value_t = 0)]
        at: u32,
        /// How many bytes.
        #[arg(long, default_value_t = 256)]
        len: u32,
    },
    /// Erase NOR blocks of 4 KiB, one per request; the ring finds its head
    /// again after each block of its own.
    EraseNor {
        /// The first block, counted from the part's start.
        block: u32,
        /// How many blocks.
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
    /// Reset the controller through the firmware.
    Reboot,
    /// FLASH the comms image onto the module through the controller: the
    /// module is reset into its ROM's download mode by the firmware, and
    /// esptool writes the application into an OTA slot, leaving the
    /// factory image that carries the download window where it is.
    FlashComms {
        /// The comms ELF, as `cargo build --release -p o89-comms` leaves it.
        elf: PathBuf,
        /// The partition table.
        #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../firmwares/o89-comms/partitions.csv"))]
        partitions: PathBuf,
        /// The route into the ROM: the window the comms firmware opens, or
        /// the strap for a module that runs nothing that answers, which on
        /// revision A needs IO8 held high by a wire.
        /// Left out, the layout chooses: the slot route knocks, and the
        /// whole route straps, because the modules it is for answer
        /// nothing.
        #[arg(long, value_enum)]
        entry: Option<FlashEntry>,
        /// What is written: the application into an OTA slot, which leaves
        /// the recovery image alone, or the whole flash, which replaces it.
        #[arg(long, value_enum, default_value_t = Layout::Slot)]
        layout: Layout,
        /// Acknowledge that `--layout whole` replaces the factory image
        /// that carries the download window. Required for that layout, and
        /// meaningless for the slot one. `just dev-flash-comms-whole`
        /// passes it, having asked first.
        #[arg(long)]
        yes: bool,
    },
    /// LISTEN to the module through the bridge: the module is reset by the
    /// firmware and whatever it says on its UART0 for `seconds` is printed,
    /// then it is reset normally. What the ROM prints says which mode it
    /// booted into.
    CommsListen {
        /// How long to listen.
        #[arg(long, default_value_t = 3)]
        seconds: u64,
        /// The route in: a plain reset by default, to hear what the module
        /// boots into.
        #[arg(long, value_enum, default_value_t = Entry::Reset)]
        entry: Entry,
        /// Exit without giving the module back, as a host that died
        /// would: the fault the firmware's reclaim and idle close answer.
        #[arg(long)]
        leave_open: bool,
    },
}

#[derive(Debug, Subcommand)]
enum StoreCommand {
    /// Write the epoch: refused unless above the one held, because a client
    /// table stamped with a later epoch would be left alone by the boot.
    WriteEpoch {
        /// The epoch, one or more.
        epoch: u32,
    },
    /// Write the device secret: sixteen bytes of id and thirty-two of
    /// printed secret from the operating system's generator, shown once.
    WriteSecret {
        /// The device id as thirty-two hex characters; generated when absent.
        #[arg(long)]
        device_id: Option<String>,
        /// Replace a secret the part already holds, which orphans every
        /// client enrolled under it.
        #[arg(long)]
        replace: bool,
    },
}

impl Layout {
    /// Refuse the whole flash unless the operator said so in as many
    /// words.
    ///
    /// The recipe asks before it runs, but the recipe is not the only way
    /// in: this binary is run directly on the bench, and the one route
    /// that takes the download window away should not be reachable by a
    /// flag nobody had to think about.
    fn permitted(self, yes: bool) -> Result<()> {
        match self {
            Self::Slot => Ok(()),
            Self::Whole if yes => Ok(()),
            Self::Whole => bail!(
                "--layout whole replaces the bootloader, the partition table and the factory \
                 image that carries the download window; from the first erase until it finishes \
                 the module boots nothing, and on revision A recovering one that boots nothing \
                 needs a wire holding IO8 high. Pass --yes, or use `just dev-flash-comms-whole`, \
                 which asks."
            ),
        }
    }

    /// The route into the ROM this layout is for, when nobody named one.
    ///
    /// The whole route replaces the factory image, so the modules it
    /// exists for — a new one, and one whose factory image is gone — boot
    /// nothing and cannot answer a knock. It straps. The slot route runs
    /// against a module that is running, so it knocks.
    fn entry(self) -> FlashEntry {
        match self {
            Self::Slot => FlashEntry::Knock,
            Self::Whole => FlashEntry::Strap,
        }
    }
}

/// What a flash writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Layout {
    /// The application into an OTA slot. The bootloader, the partition
    /// table and the factory image stay, so the download window survives a
    /// transfer that dies (F-084).
    Slot,
    /// The whole flash from address zero, the factory image with it: how a
    /// module is brought up the first time, and how one whose recovery
    /// image is gone is restored. Until it finishes the module boots
    /// nothing, and a module that boots nothing is reached by the strap
    /// with a wire on revision A, or not at all (#1).
    Whole,
}

/// The board revision on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum RevisionArg {
    /// Revision A: the rail defaults off.
    A,
    /// Revision B: the rail defaults on (hardware#48).
    B,
}

impl From<RevisionArg> for Revision {
    fn from(arg: RevisionArg) -> Self {
        match arg {
            RevisionArg::A => Self::A,
            RevisionArg::B => Self::B,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if let Command::Probes = cli.command {
        for probe in Link::probes() {
            println!("{probe}");
        }
        return Ok(());
    }
    let mut link = Link::attach(cli.probe.as_deref()).context("attaching to the controller")?;
    match cli.command {
        Command::Probes => Ok(()),
        Command::Ping => {
            let boot = link.ping()?;
            println!("boot {boot}");
            Ok(())
        }
        Command::Store { what: None } => store::show(&mut link),
        Command::Store {
            what: Some(StoreCommand::WriteEpoch { epoch }),
        } => store::write_epoch(&mut link, epoch),
        Command::Store {
            what: Some(StoreCommand::WriteSecret { device_id, replace }),
        } => store::write_secret(&mut link, device_id.as_deref(), replace),
        Command::Rail { revision } => {
            let readout = rail::read(&mut link, revision.into())?;
            println!("pin  {:?}", readout.pin);
            println!("rail {:?}", readout.rail);
            Ok(())
        }
        Command::Fram { at, len } => {
            let mut bytes = vec![0u8; usize::from(len)];
            link.read_fram(at, &mut bytes)?;
            dump(u32::from(at), &bytes);
            Ok(())
        }
        Command::Nor { at, len } => {
            let len = usize::try_from(len).context("a length that fits")?;
            let mut bytes = vec![0u8; len];
            link.read_nor(at, &mut bytes)?;
            dump(at, &bytes);
            Ok(())
        }
        Command::EraseNor { block, count } => {
            if count == 0 {
                bail!("nothing to erase");
            }
            let last = block
                .checked_add(count)
                .and_then(|end| end.checked_sub(1))
                .context("a block range that fits")?;
            for block in block..=last {
                link.erase_nor_block(block)
                    .with_context(|| format!("erasing block {block}"))?;
                println!("erased block {block}");
            }
            Ok(())
        }
        Command::Reboot => link.reboot(),
        Command::FlashComms {
            elf,
            partitions,
            entry,
            layout,
            yes,
        } => flash_comms(&mut link, &elf, &partitions, entry, layout, yes),
        Command::CommsListen {
            seconds,
            entry,
            leave_open,
        } => flash::listen(&mut link, seconds, entry.into(), leave_open),
    }
}

/// FLASH the comms image onto the module through the controller.
fn flash_comms(
    link: &mut Link,
    elf: &Path,
    partitions: &Path,
    entry: Option<FlashEntry>,
    layout: Layout,
    yes: bool,
) -> Result<()> {
    // The generated files live for this flash and go with it.
    let scratch = flash::Scratch::new()?;
    layout.permitted(yes)?;
    let entry = entry.unwrap_or_else(|| layout.entry());
    let app;
    let declared;
    let merged;
    let request = match layout {
        Layout::Slot => {
            app = scratch.file("o89-comms.bin");
            flash::app_image(elf, &app)?;
            // Only to be compared against the module's own, which
            // is what the slot route plans from (F-085): a table
            // the repository cannot read is not a reason to refuse
            // a flash the module's table fully describes.
            declared = layout::Table::read(partitions)
                .inspect_err(|error| {
                    println!("note: {}: {error:#}", partitions.display());
                })
                .ok();
            flash::Request::Slot {
                app: &app,
                scratch: &scratch,
                declared: declared.as_ref(),
            }
        }
        Layout::Whole => {
            merged = scratch.file("o89-comms-merged.bin");
            flash::merge(elf, partitions, &merged)?;
            flash::Request::Whole { merged: &merged }
        }
    };
    flash::flash(link, &request, entry.into())
}

/// Sixteen bytes a line, the address in front.
fn dump(from: u32, bytes: &[u8]) {
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let at = u32::try_from(row.saturating_mul(16))
            .ok()
            .and_then(|offset| from.checked_add(offset));
        match at {
            Some(at) => print!("{at:08x} "),
            None => print!("........ "),
        }
        for byte in chunk {
            print!(" {byte:02x}");
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn a_flash_takes_the_knock_or_the_strap_and_refuses_a_plain_reset() {
        let knock = Cli::try_parse_from(["o89-dev", "flash-comms", "o89-comms"]).expect("parses");
        assert!(matches!(
            knock.command,
            Command::FlashComms { entry: None, .. }
        ));
        let strap =
            Cli::try_parse_from(["o89-dev", "flash-comms", "o89-comms", "--entry", "strap"])
                .expect("parses");
        assert!(matches!(
            strap.command,
            Command::FlashComms {
                entry: Some(FlashEntry::Strap),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["o89-dev", "flash-comms", "o89-comms", "--entry", "reset"])
                .is_err()
        );
    }

    #[test]
    fn f_036_the_whole_flash_is_refused_until_the_operator_says_so_in_as_many_words() {
        let error = format!("{:#}", Layout::Whole.permitted(false).expect_err("refused"));
        assert!(error.contains("download window"), "{error}");
        assert!(error.contains("--yes"), "{error}");
        Layout::Whole
            .permitted(true)
            .expect("said in as many words");
        // The slot route takes no acknowledgement either way: it keeps the
        // image the acknowledgement is about.
        Layout::Slot.permitted(false).expect("nothing to lose");
        Layout::Slot.permitted(true).expect("nothing to lose");
    }

    #[test]
    fn the_whole_route_straps_by_default_because_what_it_recovers_answers_no_knock() {
        assert_eq!(Layout::Whole.entry(), FlashEntry::Strap);
        assert_eq!(Layout::Slot.entry(), FlashEntry::Knock);
        // And a route named on the command line is still the one taken:
        // a healthy module's factory image is replaced through its window.
        let named = Cli::try_parse_from([
            "o89-dev",
            "flash-comms",
            "o89-comms",
            "--layout",
            "whole",
            "--entry",
            "knock",
        ])
        .expect("parses");
        assert!(matches!(
            named.command,
            Command::FlashComms {
                entry: Some(FlashEntry::Knock),
                layout: Layout::Whole,
                ..
            }
        ));
    }

    #[test]
    fn f_084_a_flash_writes_a_slot_unless_the_whole_flash_is_asked_for_by_name() {
        let plain = Cli::try_parse_from(["o89-dev", "flash-comms", "o89-comms"]).expect("parses");
        assert!(
            matches!(
                plain.command,
                Command::FlashComms {
                    layout: Layout::Slot,
                    ..
                }
            ),
            "the recovery image is kept unless something asks for it to go"
        );
        let whole =
            Cli::try_parse_from(["o89-dev", "flash-comms", "o89-comms", "--layout", "whole"])
                .expect("parses");
        assert!(matches!(
            whole.command,
            Command::FlashComms {
                layout: Layout::Whole,
                ..
            }
        ));
    }

    #[test]
    fn listening_still_takes_the_plain_reset() {
        let listen = Cli::try_parse_from(["o89-dev", "comms-listen"]).expect("parses");
        assert!(matches!(
            listen.command,
            Command::CommsListen {
                entry: Entry::Reset,
                ..
            }
        ));
    }
}
