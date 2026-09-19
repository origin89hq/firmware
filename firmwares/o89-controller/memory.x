/* The image budget, which is not the part's flash.
 *
 * The STM32G0B1RE has 512 KB in two banks the part swaps by an option bit. An
 * image lives in one bank while the other holds the one it is replacing, so
 * the budget is one bank, 256 KB, less the 8 KB at its bottom that the
 * bootloader owns. A firmware that fits the part and not the slot builds,
 * flashes, ships, and fails its first update in a cabin.
 */
MEMORY
{
  FLASH : ORIGIN = 0x08002000, LENGTH = 248K
  RAM   : ORIGIN = 0x20000000, LENGTH = 140K
  /* The bench tool's mailbox: the last 4 KiB, out of the stack's way and
   * never loaded or zeroed by the runtime, at the address o89-core names. */
  MAILBOX : ORIGIN = 0x20023000, LENGTH = 4K
}

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

SECTIONS
{
  .o89_mailbox (NOLOAD) :
  {
    KEEP(*(.o89_mailbox))
  } > MAILBOX
}
