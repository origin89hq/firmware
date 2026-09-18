/* The bootloader's 8 KB at the bottom of the bank.
 *
 * The STM32G0B1RE's flash is two 256 KB banks the part swaps by an option bit,
 * so the bootloader is the same bytes at the bottom of each bank and the
 * application always links just past it. Written at manufacture and never by
 * an update: an update that could rewrite this region could put a broken
 * bootloader in the new bank, and nothing would ever flip back.
 */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 8K
  RAM   : ORIGIN = 0x20000000, LENGTH = 144K
}
