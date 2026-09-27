/* The image budget on revision A: the part's flash less the bootloader.
 *
 * The STM32G0B1RE has 512 KB in two banks. Revision A does not swap them: an
 * update is staged and verified on the NOR and copied into this one region by
 * the bootloader, with the previous image kept on the NOR for a rollback
 * (#185). So the budget is 512 KB less the 32 KB at the bottom that the
 * bootloader owns, and the region runs across the bank boundary at
 * 0x08040000. Revision B keeps A/B on a larger part (origin89hq/hardware#57)
 * and will have its own map.
 */
MEMORY
{
  FLASH : ORIGIN = 0x08008000, LENGTH = 480K
}

/* The stack, the statics and the mailbox. */
INCLUDE ram.x

/* The vector table is 0xBC bytes. Right after it, at 0xC0, the linker writes
 * the image's GNU build ID note (36 bytes; build.rs asks for it), so a probe
 * can tell which image a board runs, and so which ELF decodes its log,
 * without being told. .text starts at 0x100, the next 8-byte boundary past
 * the note: cortex-m's calibrated delay loop is an 8-byte-aligned section and
 * cortex-m-rt asserts .text starts past the vector table. */
_stext = ORIGIN(FLASH) + 0x100;

SECTIONS
{
  .o89_build_id ORIGIN(FLASH) + 0xC0 :
  {
    KEEP(*(.note.gnu.build-id))
  } > FLASH
}
INSERT AFTER .vector_table;
