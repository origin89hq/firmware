//! The OTA slot's state, confirmed only once the window has run (F-036).
//!
//! The ESP-IDF bootloader, with rollback enabled, boots a freshly written
//! slot in pending verification and puts the previous image back if the
//! new one does not confirm itself before the next reset. The thing that
//! proves this image safe to keep is not that it booted but that it
//! honours the window, so the confirmation is the statement after the
//! window and not the first in `main`, and the confirmation takes the proof
//! the window hands out and nothing else (F-089): an image whose window is
//! omitted has nothing to confirm with. The bootloader is the one this
//! repository builds with rollback enabled (F-088); under one without it
//! the state is valid already, and this is then a write of what is there.

use esp_bootloader_esp_idf::ota::{Ota, OtaImageState};
use esp_bootloader_esp_idf::partitions::{
    DataPartitionSubType, Error, PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
};
use esp_storage::FlashStorage;
use o89_comms_core::WindowRan;

/// The two OTA slots the partition table declares.
const OTA_SLOTS: usize = 2;

/// How many times the state is read and, when due, confirmed before the
/// part gives up and resets: a flash read or write that fails once is tried
/// again rather than taken as the image's verdict.
const ATTEMPTS: usize = 3;

/// The slot could not be read, or its confirmation did not land.
struct Unconfirmed;

/// Mark the current slot valid when it is waiting to be, and leave every
/// other state as it is. A table without OTA data, or OTA data that selects
/// no slot, has nothing to confirm: the factory image is running, which OTA
/// never writes (F-036).
/// A state that cannot be read, or a confirmation that was due and did not
/// land, is tried again; after the last attempt the part resets rather than
/// run an image that has not been kept. A bootloader with rollback then puts
/// the previous image back, which honours the window too (F-036), and one
/// without it boots this image again, window first, to try again.
///
/// `ran` is the proof the window ran, which only the window makes (F-089).
pub fn confirm_if_pending(storage: &mut FlashStorage<'_>, _ran: WindowRan) {
    // Bounded: `ATTEMPTS` turns.
    for _ in 0..ATTEMPTS {
        if confirm(storage).is_ok() {
            return;
        }
    }
    esp_hal::system::software_reset()
}

/// One read of the slot's state, and its confirmation when it is due.
fn confirm(storage: &mut FlashStorage<'_>) -> Result<(), Unconfirmed> {
    let mut table = [0u8; PARTITION_TABLE_MAX_LEN];
    let table = read_partition_table(storage, &mut table).map_err(|_| Unconfirmed)?;
    let Some(otadata) = table
        .find_partition(PartitionType::Data(DataPartitionSubType::Ota))
        .map_err(|_| Unconfirmed)?
    else {
        return Ok(());
    };
    let mut ota = Ota::new(otadata.as_flash_region(storage), OTA_SLOTS).map_err(|_| Unconfirmed)?;
    match ota.current_ota_state() {
        Ok(OtaImageState::New | OtaImageState::PendingVerify) => ota
            .set_current_ota_state(OtaImageState::Valid)
            .map_err(|_| Unconfirmed),
        Ok(
            OtaImageState::Valid
            | OtaImageState::Invalid
            | OtaImageState::Aborted
            | OtaImageState::Undefined,
        )
        | Err(Error::InvalidState) => Ok(()),
        Err(_) => Err(Unconfirmed),
    }
}
