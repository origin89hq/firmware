//! Exclusive flash ownership after OTA confirmation; offsets come from the table.
use esp_bootloader_esp_idf::partitions::{
    DataPartitionSubType, PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
};
use esp_storage::FlashStorage;
use o89_comms_core::CredentialFlash;

pub struct Store {
    flash: FlashStorage<'static>,
    region: Option<(u32, u32)>,
}
impl Store {
    pub fn new(mut flash: FlashStorage<'static>) -> Self {
        let mut bytes = [0; PARTITION_TABLE_MAX_LEN];
        let region = read_partition_table(&mut flash, &mut bytes)
            .ok()
            .and_then(|table| {
                table
                    .find_partition(PartitionType::Data(DataPartitionSubType::Nvs))
                    .ok()
                    .flatten()
            })
            .filter(|entry| {
                entry.label_as_str() == "creds"
                    && entry.len() >= 4096
                    && entry.offset().is_multiple_of(4096)
                    && entry.len().is_multiple_of(4096)
            })
            .and_then(|entry| {
                entry
                    .offset()
                    .checked_add(entry.len())
                    .map(|end| (entry.offset(), end))
            });
        Self { flash, region }
    }
    fn address(&self, offset: u32, len: usize) -> Result<u32, ()> {
        let (start, end) = self.region.ok_or(())?;
        let address = start.checked_add(offset).ok_or(())?;
        let after = address
            .checked_add(u32::try_from(len).map_err(|_| ())?)
            .ok_or(())?;
        if after > end {
            return Err(());
        }
        Ok(address)
    }
}
impl CredentialFlash for Store {
    type Error = ();
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), ()> {
        let address = self.address(offset, bytes.len())?;
        self.flash.read_nor(address, bytes).map_err(|_| ())
    }
    fn erase(&mut self) -> Result<(), ()> {
        let (start, end) = self.region.ok_or(())?;
        self.flash.erase(start, end).map_err(|_| ())
    }
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), ()> {
        let address = self.address(offset, bytes.len())?;
        self.flash.write_nor(address, bytes).map_err(|_| ())
    }
}
