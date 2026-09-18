# Controller board A

Every STM32 pin the firmware touches on controller board A, with the
peripheral, the connector and the source, and the rules the firmware carries
per revision because of the board's defects. The board itself is
[origin89hq/hardware](https://github.com/origin89hq/hardware/tree/main/boards/controller-a);
its layout rules are `A-nn` there, and what constrains the generator
connector is `B-nn` in the generator board's document. Nothing here is a
second opinion on the copper: the pins come from the 2026-09-09 export's
flying-probe netlist, checked against the HAL's pin-function table for the
`stm32g0b1re`, and revision B's moves are recorded where the rule that moves
them is.

The controller firmware's board module carries this table as its own
documentation, and from M1 the gate checks that every pin the code takes
appears here and every row here is taken or marked as deliberately left alone.

## Revision A pin map

| Pin | Net | Function | Peripheral | Connector | Source |
| --- | --- | --- | --- | --- | --- |
| PB6 | `ESP_TX` | to the module's RXD0 (GPIO17) | USART1 TX | U8 | hardware#13 |
| PB7 | `ESP_RX` | from the module's TXD0 (GPIO16) | USART1 RX | U8 | hardware#13 |
| PB3 | `ESP_RTS` | to the module's IO4, its CTS | USART1 RTS, AF4 | U8 | hardware#13 |
| PB4 | `ESP_CTS` | from the module's IO5, its RTS | USART1 CTS, AF4 | U8 | hardware#13, `A` §5 item 2 |
| PC2 | `ESP_EN` | module enable; R55 10 kΩ to `V3V3_ESP`, C26 1 µF, no series resistor | GPIO out | U8 | hardware#14, #17 |
| PC3 | `ESP_BOOT` | module IO9 strap; the chip's internal pull-up only | GPIO out | U8 | hardware#6, #17 |
| PC5 | `ESP_PWR_EN` | gates `V3V3_ESP` through Q3 and Q2; high is on; off with the pin high-impedance | GPIO out | — | hardware#5, bench 2026-09-14 |
| PA2 / PA3 | RS-485 #1 TX / RX | EPEver-class, 115200 8N1 | USART2 | CN2 | netlist |
| PB10 / PB11 | RS-485 #2 TX / RX | PZEM DC meters, 9600 8N2 | USART3 | CN3 | netlist |
| PA0 / PA1 | RS-485 #3 TX / RX | PZEM-016, modules | USART4 | CN4 | netlist, hardware#34 |
| PB8 / PB9 | CAN RX / TX | TJA1051T/3 | FDCAN1, AF3 | CN5 | `A` §5 item 2 |
| PC0 | VE.Direct 1 RX | through R14 1 kΩ, connector pin 3 on revision A | LPUART1 | CN6 | hardware#27 |
| PC1 | VE.Direct 2 RX | through R15 1 kΩ, connector pin 3 on revision A | LPUART2 | CN7 | hardware#27 |
| PB13 / PB14 | FRAM SCL / SDA | FM24W256, 32 KB, 400 kHz | I2C2 | U9 | bench 2026-09-14 |
| PA4, PA5, PA6, PA7 | NOR CS, SCK, MISO, MOSI | W25Q128JV, 16 MB, JEDEC `EF 40 18`; PA4 and PA5 are 3.3 V-only pins | SPI1 | U10 | bench 2026-09-14, `A` §5 item 3 |
| PC4 | `OW_DATA_F` | 1-Wire, bit-banged; R41 100 Ω, D9 at CN8, R16 4.7 kΩ pull-up | GPIO | CN8, CN11 | `A-26`, hardware#31 |
| PB0 | `AIN_HOUSE` | bank voltage ÷11, about 36 V full scale | ADC1 | from `V12` | `A-29` |
| PB1 | `AIN_START` | start battery ÷11 | ADC1 | CN12 | `A-29` |
| PB2 | `AIN_TANK` | 4–20 mA across R46 150 Ω, 0.6–3.0 V | ADC1 | CN13 | `A-27`, hardware#24, #36 |
| PB12 / PB15 | `SEL_AUTO` / `SEL_MANUAL` | 10 kΩ pull-ups, switch to ground | GPIO in | CN10 | hardware#31 |
| PD0 | `GEN_RUN_CMD` | `RUN` to board B, CN9 pin 3 | GPIO out | CN9 | `B-09`, hardware#30 |
| PD1 | `GEN_WDT_KICK` | `KICK` to board B, CN9 pin 4 | GPIO out | CN9 | `B-09` |
| PD2 | `GEN_STATUS` | `FEEDBACK` from board B, CN9 pin 5; internal pull-up, low is both relays closed | GPIO in | CN9 | `B-09b` |
| PC6 / PC7 | status / fault lamps | active high | GPIO out | — | bench 2026-09-14 |
| PF0 / PF1 | HSE 12 MHz | X1 | RCC | — | `A-17` |
| PC14 / PC15 | LSE 32.768 kHz | X2, CR2032 backup on CN14 through D11 | RCC, RTC | — | `A-28`, `A-25` |
| PA13 / PA14 | SWDIO / SWCLK; PA14 is also BOOT0 (R17 10 kΩ to ground) | debug; no NRST on the header | SWD | H1 | hardware#29 |

Nineteen pins are unused on revision A and only on pads: PC11–PC13, PA8–PA12,
PA15, PB5, PC8–PC10, PD3–PD6, PD8, PD9. `PA11` and `PA12` stay untouched
(`A` §5 item 2). Revision B moves `RUN`, `KICK` and `FEEDBACK` off PD0–PD2
(`A-34`), adds the button (`A-42`) and up to four fault or enable lines for
the current limiters (`A-20b`, `A-20c`, `A-24`); the pins are chosen in the
hardware repository's item 2 and land here with the revision B export.

## Connectors

| Connector | What | Pins |
| --- | --- | --- |
| CN1 | 12 V in on revision A; the bank, 12 or 24 V, on revision B | 1 positive, 2 ground |
| CN2, CN3, CN4 | RS-485 #1, #2, #3 | 1 A, 2 B, 3 ground; CN4 gains 4 `5V` on revision B (`A-37`) |
| CN5 | CAN | H, L, ground |
| CN6, CN7 | VE.Direct 1, 2 | Victron's table: 1 ground, 2 RX, 3 TX, 4 power; revision A listens on pin 3 |
| CN8, CN11 | 1-Wire | 1 `OW_VCC`, 2 data, 3 ground |
| CN9 | board B | 1 `+12V` (the bank on revision B), 2 ground, 3 `RUN`, 4 `KICK`, 5 `FEEDBACK` (`B-09`) |
| CN10 | selector | auto, manual, ground |
| CN12 | start battery sense | positive, ground |
| CN13 | tank sender | 1 raw `V12` on revision A, a 24 V loop on B; 2 sense; 3 ground |
| CN14 | RTC cell | CR2032; moves inboard on revision B |
| H1 | SWD | 3V3, SWDIO, SWCLK, ground; six pins with NRST on revision B (`A-40`) |
| JP1–JP4 | termination | RS-485 #1, #2, #3, CAN; fitted means terminated |

## What the firmware does because of the board, per revision

Each row is an `F-nnn` in [`REQUIREMENTS.md`](REQUIREMENTS.md); the number
is the one the gate traces.

| Hazard | Revision A | Revision B | Rules |
| --- | --- | --- | --- |
| The ST bootloader on empty flash pulls `RUN` up and drives `KICK` (hardware#30) | `RUN` and `KICK` low at the reset vector; never an empty-flash window | The lines leave the bootloader's pins and gain pull-downs (`A-34`); the firmware keeps both rules | F-001, F-070 |
| RS-485 `DI` floats through reset and holds the bus low (hardware#28) | TX pins high at the reset vector; every image configures all three USARTs | Pull-ups on the nets (`A-41`); the firmware keeps the rule | F-002 |
| Lines into an unpowered module back-power it (hardware#17) | PB6, PB3, PC2, PC3 inputs while the rail is off | Series resistors (`A-39`); the rule stays | F-003 |
| `EN` has only an RC delay (hardware#14) | PC2 low across every rail cycle | A supervisor on `V3V3_ESP` (`A-39`); the rule stays | F-004 |
| The rail switched on after minutes off corrupts the STM32 (hardware#5) | No cycle longer than 5 s off; L-112's rung replaced; USART1 configured after the rail settles | A slew-limited switch (`A-23`); the full ladder once the rework passes ten-minute off-times | F-005, F-006 |
| The rail defaults off through every reset (hardware#48) | Every STM32 reset reboots the module; the boot record says so | The switch defaults on with `PC5` high-impedance; the controller takes ownership after boot | F-014 |
| No `NRST` on the debug header (hardware#29) | No stop mode; PA13 and PA14 untouched | `NRST` on the six-pin header (`A-40`); low power becomes possible | F-012 |
| Any controller reset opens the contact (hardware#18) | The run reason in FRAM; the boot record explains the stop | A ride-through window on board B; automatic starts resume, manual starts stop by kicking with `RUN` low | F-022, F-061, F-015 |
| `FEEDBACK` has no pull-up on either board (`B-09b`) | The internal pull-up; low is both closed | The same, through a series resistor | F-013 |
| The monostable's 4.5 s is a design figure; the bench measured 4.23–4.46 s and drifting (hardware#22) | Measure every dropout against 3.0–6.5 s | The same | F-054 |
| VE.Direct lines carry 5 V from an MPPT with no level shift (hardware#27) | Pull-ups off unless the port is configured for a 3.3 V product; listens on pin 3 | An isolator per port with a fail-safe-high output; listens on pin 2 | F-051 |
| Selector and 1-Wire inputs are unclamped (hardware#31) | Debounce the selector; a CRC failure is no value; an out-of-range reading is not a state change | Clamps (`A-26`, `A-36`); the rules stay | F-053 |
| Three terminators leave the idle bias inside the receiver's undefined band (hardware#26) | Expect a silent or garbled bus and say so in the concern | Bias raised (`A-13c`) | — |
| `PC5` reads high-impedance in the bench tool as "off" (#4) | Off | On; the tool reports the pin and the rail as two fields keyed on the revision | — |
