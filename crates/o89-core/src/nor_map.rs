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
}
