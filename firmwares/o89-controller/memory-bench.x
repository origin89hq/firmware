/* The bench map: boots straight from the bottom of flash on a blank board.
 *
 * 256K, not the part's 512K, on purpose: every size measured here is only
 * worth anything to the shipped image if both are measured against the same
 * one-slot budget. An image linked here has nowhere for the bootloader to
 * live and must never be flashed onto a unit that will take an update.
 */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 256K
  RAM   : ORIGIN = 0x20000000, LENGTH = 144K
}

_stext = ORIGIN(FLASH) + 0x100;

SECTIONS
{
  .o89_build_id ORIGIN(FLASH) + 0xC0 :
  {
    KEEP(*(.note.gnu.build-id))
  } > FLASH
}
INSERT AFTER .vector_table;
