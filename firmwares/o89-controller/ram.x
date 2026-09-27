/* The controller's RAM, one map for the production and the bench image,
 * which differ only in where their flash starts: a bench run proves the
 * RAM layout that ships. `memory.x` and `memory-bench.x` include it. */
MEMORY
{
  /* The stack, at the bottom of RAM, below every static (F-096, #233).
   * It grows down toward 0x20000000, and a push below that address lands
   * under RAM, where it is expected to fault, instead of on a static: the
   * core locks up, because the hard fault cannot stack its own frame
   * either, and the IWDG resets the part (bench pending, #233). 63K is
   * the stack's budget: F-094 holds the deepest stack the gate can
   * measure 2 KB under it. A static that no longer fits fails the link on
   * `RAM`; take what it needs from here and let F-094 say whether the
   * stack still fits. */
  STACK : ORIGIN = 0x20000000, LENGTH = 63K
  /* .data, .bss and .uninit, above the stack. */
  RAM   : ORIGIN = ORIGIN(STACK) + LENGTH(STACK), LENGTH = 136K - LENGTH(STACK)
  /* The bench tool's mailbox and the bridge's rings: the last 8 KiB, above
   * the statics and never loaded or zeroed by the runtime, at the address
   * o89-core names. */
  MAILBOX : ORIGIN = 0x20022000, LENGTH = 8K
}

/* cortex-m-rt puts the stack at the end of `RAM` unless told otherwise:
 * here it starts at the top of its own region, and its floor is the
 * part's RAM origin, which is where the gate measures it from. */
_stack_start = ORIGIN(STACK) + LENGTH(STACK);
_stack_end = ORIGIN(STACK);

SECTIONS
{
  .o89_mailbox (NOLOAD) :
  {
    KEEP(*(.o89_mailbox))
  } > MAILBOX
}
