/* The bootloader's 32 KB at the bottom of flash.
 *
 * Revision A stages an update on the NOR and copies it into the one
 * application region above this, so the bootloader carries a NOR driver, a
 * signature check over NOR reads and a journaled copy. 16 KB is the estimate
 * and nothing has measured it; 32 KB is reserved so that a bootloader larger
 * than the estimate never moves the application, which on a unit updated
 * over the air takes a visit with a probe (#185). Written at manufacture and
 * never by an update: this region is never erased after that, so bank 1 never
 * reads empty (origin89hq/hardware#30).
 */
/* This image's stack starts at the top of RAM and grows down through the
 * controller's mailbox toward the controller's `.uninit`, which holds the
 * last words the controller reads after this image jumps: about 9.9 KB of
 * room at #233. The image is never updated, so a deeper stack here, the
 * NOR copy of #185 for one, is measured against that before it ships. */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 32K
  RAM   : ORIGIN = 0x20000000, LENGTH = 144K
}
