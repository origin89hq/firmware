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

mod link;
mod rail;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use o89_core::Revision;

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
    }
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
