//! Where everything sits on the W25Q128: the log ring from the bottom, then
//! the two regions revision A stages its controller updates in (#185).
//!
//! One map, so that the ring, the bench tool's erase and, with M7, the
//! updater and the bootloader agree on it. An image region holds either the
//! update being staged or the image it replaced, the rollback target; the
//! bench tool's erase refuses both, because erasing a region under a copy
//! the bootloader has started leaves nothing to finish it with.

/// Bytes in one erase sector, the unit a block is counted in.
pub const SECTOR_BYTES: u32 = 4096;

/// Bytes on the part: 128 Mbit.
pub const PART_BYTES: u32 = 16 * 1024 * 1024;

/// The ring's span, in sectors from the bottom of the part: 14.5 MiB.
pub const RING_BLOCKS: u32 = 3712;

/// Bytes in one image region: the 480 KB application region with room for
/// its manifest, rounded to whole 64 KiB erase blocks.
pub const IMAGE_REGION_BYTES: u32 = 512 * 1024;

/// Where each image region starts, in bytes: back to back from the ring's
/// end. Nothing is placed above the second yet; 512 KiB is free.
pub const IMAGE_REGIONS: [u32; 2] = [RING_END, RING_END + IMAGE_REGION_BYTES];

const RING_END: u32 = RING_BLOCKS * SECTOR_BYTES;

/// The application region the bootloader copies an image into, which an
/// image region has to hold. `o89-controller/memory.x` states the same.
const APPLICATION_BYTES: u32 = 480 * 1024;

const _: () = {
    let [first, second] = IMAGE_REGIONS;
    assert!(second + IMAGE_REGION_BYTES <= PART_BYTES);
    assert!(first.is_multiple_of(64 * 1024));
    assert!(IMAGE_REGION_BYTES.is_multiple_of(64 * 1024));
    assert!(IMAGE_REGION_BYTES >= APPLICATION_BYTES);
};

/// Whether the sector `block` lies in an image region, which nothing but the
/// updater and the bootloader may erase.
#[must_use]
pub fn in_an_image_region(block: u32) -> bool {
    let Some(at) = block.checked_mul(SECTOR_BYTES) else {
        return false;
    };
    IMAGE_REGIONS.iter().any(|&start| {
        at.checked_sub(start)
            .is_some_and(|offset| offset < IMAGE_REGION_BYTES)
    })
}

/// The serial clock the controller drives the part at. The W25Q128JV takes
/// 133 MHz for a fast read and 50 MHz for the plain `0x03` read the driver
/// uses; 8 MHz is what board A was proven at, and a record of under three
/// hundred bytes is a fraction of a millisecond at it.
pub const SCK: Hertz = Hertz(8_000_000);

/// A frequency, in hertz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Hertz(pub u32);

/// Why the NOR's bus was not built, so the recorder runs without a ring
/// instead of the HAL panicking on every boot (#217).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BusRefused {
    /// The HAL recorded no clock for the bus: the clock tree it was given
    /// does not run the bus's kernel clock.
    NoKernelClock,
    /// The kernel clock is slower than the serial clock asked of it: an SPI
    /// divides its kernel clock by two at least, so no divider reaches it.
    KernelBelowSck {
        /// The kernel clock the HAL recorded.
        kernel: Hertz,
    },
}

/// Whether an SPI whose kernel clock the HAL recorded as `kernel` can be
/// built for [`SCK`]: the same test the HAL's baud-rate divider makes, and
/// that it `unwrap`s, taken first so a bus it would refuse is a refusal
/// here rather than a panic there (F-095). From `SCK` up to twice it, the
/// HAL divides by two and the part is driven slower than asked, which it
/// takes; only below `SCK` does no divider exist.
///
/// # Errors
///
/// [`BusRefused`] names the clock that cannot carry the part.
pub fn bus(kernel: Option<Hertz>) -> Result<(), BusRefused> {
    match kernel {
        None | Some(Hertz(0)) => Err(BusRefused::NoKernelClock),
        Some(kernel) if kernel < SCK => Err(BusRefused::KernelBelowSck { kernel }),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_IMAGE_BLOCK: u32 = RING_BLOCKS;
    const BLOCKS_PER_REGION: u32 = IMAGE_REGION_BYTES / SECTOR_BYTES;

    #[test]
    fn the_first_and_last_sector_of_each_image_region_are_reserved() {
        for region in 0..2 {
            let first = FIRST_IMAGE_BLOCK + region * BLOCKS_PER_REGION;
            let last = first + BLOCKS_PER_REGION - 1;
            assert!(in_an_image_region(first), "block {first}");
            assert!(in_an_image_region(last), "block {last}");
        }
    }

    #[test]
    fn the_ring_and_the_free_space_above_the_regions_are_not_image_regions() {
        assert!(!in_an_image_region(0));
        assert!(
            !in_an_image_region(RING_BLOCKS - 1),
            "the ring's last block"
        );
        let above = FIRST_IMAGE_BLOCK + 2 * BLOCKS_PER_REGION;
        assert!(!in_an_image_region(above), "the first free block");
        assert!(!in_an_image_region(PART_BYTES / SECTOR_BYTES - 1));
    }

    #[test]
    fn a_block_past_the_part_or_past_u32_is_not_an_image_region() {
        assert!(!in_an_image_region(PART_BYTES / SECTOR_BYTES));
        assert!(!in_an_image_region(u32::MAX), "its address overflows");
    }

    #[test]
    fn the_regions_sit_just_past_the_ring_and_end_inside_the_part() {
        assert_eq!(IMAGE_REGIONS, [0x00E8_0000, 0x00F0_0000]);
        assert_eq!(IMAGE_REGIONS[1] + IMAGE_REGION_BYTES, 0x00F8_0000);
    }

    #[test]
    fn f_095_the_bus_is_built_on_the_clock_tree_board_a_runs() {
        // PCLK1 at 64 MHz, as `clock.rs` sets it: a divide by eight.
        assert_eq!(bus(Some(Hertz(64_000_000))), Ok(()));
    }

    #[test]
    fn f_095_a_kernel_clock_equal_to_the_sck_is_the_slowest_one_accepted() {
        assert_eq!(bus(Some(SCK)), Ok(()));
        assert_eq!(
            bus(Some(Hertz(SCK.0 - 1))),
            Err(BusRefused::KernelBelowSck {
                kernel: Hertz(SCK.0 - 1)
            })
        );
    }

    #[test]
    fn f_095_a_clobbered_kernel_clock_is_refused_not_unwrapped() {
        // #217: a word the stack left where the HAL keeps PCLK1.
        assert_eq!(
            bus(Some(Hertz(1))),
            Err(BusRefused::KernelBelowSck { kernel: Hertz(1) })
        );
    }

    #[test]
    fn f_095_no_kernel_clock_is_refused() {
        assert_eq!(bus(None), Err(BusRefused::NoKernelClock));
        assert_eq!(bus(Some(Hertz(0))), Err(BusRefused::NoKernelClock));
    }
}
