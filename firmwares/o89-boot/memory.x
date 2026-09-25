/* The bootloader's 16 KB at the bottom of flash.
 *
 * Revision A stages an update on the NOR and copies it into the one
 * application region above this, so the bootloader carries a NOR driver, a
 * signature check over NOR reads and a journaled copy: more than 8 KB, and
 * 16 KB is the estimate (#185). Written at manufacture and never by an
 * update: this region is never erased after that, so the flash never reads
 * empty and the system bootloader's empty check cannot fire
 * (origin89hq/hardware#30).
 */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 16K
  RAM   : ORIGIN = 0x20000000, LENGTH = 144K
}
