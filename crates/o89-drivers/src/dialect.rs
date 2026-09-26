//! The register maps: where each value is on a device, what it is, and
//! where it came from.
//!
//! A [`Cell`] declares its kind, span, sign, unit, decade, the vendor's
//! absent pattern and the provenance the vendor can justify, with no
//! implicit `measured` (F-052). A [`Block`] is the one register read that
//! covers a run of cells, and it is the only way a cell reaches a decode:
//! [`Block::try_new`] refuses a cell whose unit is not its kind's, whose
//! decade cannot be brought to the kind's scale, or whose provenance its
//! kind cannot carry, and [`block!`](crate::block) makes the same refusal a build
//! error for a table declared `const`.
//!
//! [`REGISTER_MAPS`] is the table of every register map this build decodes,
//! and the one `cargo xtask registry` will read to say which dialects the
//! firmware supports (#6).
//!
//! cites: F-052, P-185

/// A checked [`dialect::Block`](crate::dialect::Block), evaluated at
/// compile time wherever it is written, so a refused declaration is a build
/// error and never a panic on the part. Code that builds a block at runtime
/// calls `Block::try_new` and handles its error.
///
/// ```compile_fail
/// use km43::{Provenance, SignalDomain, Unit};
/// use o89_drivers::block;
/// use o89_drivers::dialect::{Block, Cell, Kind, Sign, Span};
/// use o89_drivers::modbus::Function;
///
/// // A state of charge is never measured.
/// const SOC: Block = block!(Function::ReadInput, 0x311A, 1, &[Cell {
///     register: 0x311A,
///     kind: Kind::StateOfCharge,
///     domain: SignalDomain::Live,
///     span: Span::One,
///     sign: Sign::Unsigned,
///     unit: Unit::Percent,
///     decade: 0,
///     absent: None,
///     plausible: None,
///     provenance: Provenance::Measured,
/// }]);
/// ```
///
/// ```compile_fail
/// use km43::{Provenance, SignalDomain, Unit};
/// use o89_drivers::block;
/// use o89_drivers::dialect::{Block, Cell, Kind, Sign, Span};
/// use o89_drivers::modbus::Function;
///
/// // A voltage in amperes.
/// const VOLTS: Block = block!(Function::ReadInput, 0x3104, 1, &[Cell {
///     register: 0x3104,
///     kind: Kind::DcVoltage,
///     domain: SignalDomain::Live,
///     span: Span::One,
///     sign: Sign::Unsigned,
///     unit: Unit::Ampere,
///     decade: -2,
///     absent: None,
///     plausible: None,
///     provenance: Provenance::Measured,
/// }]);
/// ```
///
/// Written in a function body, it is still evaluated by the compiler:
///
/// ```compile_fail
/// use km43::{Provenance, SignalDomain, Unit};
/// use o89_drivers::block;
/// use o89_drivers::dialect::{Block, Cell, Kind, Sign, Span};
/// use o89_drivers::modbus::Function;
///
/// fn at_runtime() -> Block {
///     block!(Function::ReadInput, 0x311A, 1, &[Cell {
///         register: 0x311A,
///         kind: Kind::StateOfCharge,
///         domain: SignalDomain::Live,
///         span: Span::One,
///         sign: Sign::Unsigned,
///         unit: Unit::Percent,
///         decade: 0,
///         absent: None,
///         plausible: None,
///         provenance: Provenance::Measured,
///     }])
/// }
/// ```
///
/// The same declarations, corrected, build:
///
/// ```
/// use km43::{Provenance, SignalDomain, Unit};
/// use o89_drivers::block;
/// use o89_drivers::dialect::{Block, Cell, Kind, Sign, Span};
/// use o89_drivers::modbus::Function;
///
/// const SOC: Block = block!(Function::ReadInput, 0x311A, 1, &[Cell {
///     register: 0x311A,
///     kind: Kind::StateOfCharge,
///     domain: SignalDomain::Live,
///     span: Span::One,
///     sign: Sign::Unsigned,
///     unit: Unit::Percent,
///     decade: 0,
///     absent: None,
///     plausible: None,
///     provenance: Provenance::Estimated,
/// }]);
/// fn at_runtime() -> Block {
///     block!(Function::ReadInput, 0x3104, 1, &[Cell {
///         register: 0x3104,
///         kind: Kind::DcVoltage,
///         domain: SignalDomain::Live,
///         span: Span::One,
///         sign: Sign::Unsigned,
///         unit: Unit::Volt,
///         decade: -2,
///         absent: None,
///         plausible: None,
///         provenance: Provenance::Measured,
///     }])
/// }
/// assert_eq!(SOC.cells().len(), 1);
/// assert_eq!(at_runtime().cells().len(), 1);
/// ```
#[macro_export]
macro_rules! block {
    ($function:expr, $start:expr, $count:expr, $cells:expr $(,)?) => {
        const {
            match $crate::dialect::Block::try_new($function, $start, $count, $cells) {
                ::core::result::Result::Ok(block) => block,
                ::core::result::Result::Err(error) => ::core::panic!("{}", error.why()),
            }
        }
    };
}

use km43::{Dialect, MetricKind, Provenance, QualityError, SignalDomain, Unit, Validity};
use o89_core::{Observation, ProvenanceSet};

use crate::modbus::{Address, Function, MAX_REGISTERS, Read, Registers};

/// The metric kinds a register map may publish, with the unit and scale
/// KM43's registry gives each.
///
/// Closed, so a kind nobody has argued a provenance rule for cannot be
/// declared; the host test holds each row to `km43::METRIC_UNITS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Kind {
    /// `0x0101`, V at −3.
    DcVoltage,
    /// `0x0102`, A at −3, positive into the component.
    DcCurrent,
    /// `0x0103`, W at −1.
    DcPower,
    /// `0x0104`, % at −1.
    StateOfCharge,
    /// `0x0201`, V at −1.
    AcVoltage,
    /// `0x0202`, A at −3.
    AcCurrent,
    /// `0x0203`, W at −1.
    AcPower,
    /// `0x0204`, Hz at −2.
    AcFrequency,
    /// `0x0205`, Wh at 0.
    AcEnergy,
    /// `0x0302`, °C at −1.
    Temperature,
    /// `0x0401`, % at −1.
    TankLevel,
}

impl Kind {
    /// The KM43 metric kind.
    #[must_use]
    pub const fn metric(self) -> MetricKind {
        match self {
            Self::DcVoltage => MetricKind::DC_VOLTAGE,
            Self::DcCurrent => MetricKind::DC_CURRENT,
            Self::DcPower => MetricKind::DC_POWER,
            Self::StateOfCharge => MetricKind::STATE_OF_CHARGE,
            Self::AcVoltage => MetricKind::AC_VOLTAGE,
            Self::AcCurrent => MetricKind::AC_CURRENT,
            Self::AcPower => MetricKind::AC_POWER,
            Self::AcFrequency => MetricKind::AC_FREQUENCY,
            Self::AcEnergy => MetricKind::AC_ENERGY,
            Self::Temperature => MetricKind::TEMPERATURE,
            Self::TankLevel => MetricKind::TANK_LEVEL,
        }
    }

    /// The unit the registry publishes it in.
    #[must_use]
    pub const fn unit(self) -> Unit {
        match self {
            Self::DcVoltage | Self::AcVoltage => Unit::Volt,
            Self::DcCurrent | Self::AcCurrent => Unit::Ampere,
            Self::DcPower | Self::AcPower => Unit::Watt,
            Self::StateOfCharge | Self::TankLevel => Unit::Percent,
            Self::AcFrequency => Unit::Hertz,
            Self::AcEnergy => Unit::WattHour,
            Self::Temperature => Unit::DegreeCelsius,
        }
    }

    /// The registry's scale: the wire integer times ten to this is the value
    /// in [`Kind::unit`].
    #[must_use]
    pub const fn scale(self) -> i8 {
        match self {
            Self::DcVoltage | Self::DcCurrent | Self::AcCurrent => -3,
            Self::DcPower
            | Self::StateOfCharge
            | Self::AcVoltage
            | Self::AcPower
            | Self::Temperature
            | Self::TankLevel => -1,
            Self::AcFrequency => -2,
            Self::AcEnergy => 0,
        }
    }

    /// The range the kind's meaning allows at its registry scale, whatever
    /// the device: a percentage is 0 to 100 %. `None` where the bound
    /// depends on the device, such as a current or a temperature; a cell
    /// narrows those from its vendor's documentation with
    /// [`Cell::plausible`].
    #[must_use]
    pub const fn intrinsic(self) -> Option<Plausible> {
        match self {
            Self::StateOfCharge | Self::TankLevel => Some(Plausible { low: 0, high: 1000 }),
            Self::DcVoltage
            | Self::DcCurrent
            | Self::DcPower
            | Self::AcVoltage
            | Self::AcCurrent
            | Self::AcPower
            | Self::AcFrequency
            | Self::AcEnergy
            | Self::Temperature => None,
        }
    }

    /// The provenances a vendor can justify for this kind over `domain`.
    ///
    /// A limit or a setpoint a source states is `reported`, whatever it
    /// limits. A total over a window is `counted`, for the kinds that
    /// accumulate. A present value is `measured` for what an instrument reads
    /// directly; a state of charge is never measured, only counted or
    /// estimated. No cell is `derived`, which is this controller's own
    /// arithmetic, or `commanded`, which is not an observation.
    #[must_use]
    pub const fn accepts(self, domain: SignalDomain) -> ProvenanceSet {
        match domain {
            SignalDomain::LimitUpper | SignalDomain::LimitLower => {
                ProvenanceSet::of(&[Provenance::Reported])
            }
            SignalDomain::Lifetime
            | SignalDomain::SinceReset
            | SignalDomain::Today
            | SignalDomain::Yesterday => match self {
                Self::AcEnergy => ProvenanceSet::of(&[Provenance::Counted]),
                Self::DcVoltage
                | Self::DcCurrent
                | Self::DcPower
                | Self::StateOfCharge
                | Self::AcVoltage
                | Self::AcCurrent
                | Self::AcPower
                | Self::AcFrequency
                | Self::Temperature
                | Self::TankLevel => ProvenanceSet::EMPTY,
            },
            SignalDomain::Live | SignalDomain::Max | SignalDomain::Min => match self {
                Self::StateOfCharge => {
                    ProvenanceSet::of(&[Provenance::Counted, Provenance::Estimated])
                }
                Self::AcEnergy => ProvenanceSet::EMPTY,
                Self::DcVoltage
                | Self::DcCurrent
                | Self::DcPower
                | Self::AcVoltage
                | Self::AcCurrent
                | Self::AcPower
                | Self::AcFrequency
                | Self::Temperature
                | Self::TankLevel => ProvenanceSet::of(&[Provenance::Measured]),
            },
        }
    }
}

/// How many registers a cell's raw value takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Span {
    /// One register.
    One,
    /// Two registers, the low word at the cell's register.
    TwoLowFirst,
    /// Two registers, the high word at the cell's register.
    TwoHighFirst,
}

impl Span {
    /// The registers taken.
    #[must_use]
    pub const fn registers(self) -> u16 {
        match self {
            Self::One => 1,
            Self::TwoLowFirst | Self::TwoHighFirst => 2,
        }
    }

    /// The largest raw value the span can hold.
    const fn max(self) -> u32 {
        match self {
            Self::One => 0xFFFF,
            Self::TwoLowFirst | Self::TwoHighFirst => u32::MAX,
        }
    }
}

/// Whether the raw value is two's complement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Sign {
    /// Never negative.
    Unsigned,
    /// Two's complement over the span.
    Signed,
}

/// An inclusive range of wire integers at a kind's registry scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Plausible {
    /// The lowest value that can be true.
    pub low: i32,
    /// The highest value that can be true.
    pub high: i32,
}

impl Plausible {
    /// Whether `value` is inside.
    #[must_use]
    pub const fn holds(self, value: i32) -> bool {
        self.low <= value && value <= self.high
    }
}

/// One value in a register map.
///
/// Built as a plain `const` and admitted only through [`Block`], which is
/// where its declaration is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cell {
    /// The register the value starts at.
    pub register: u16,
    /// What it is.
    pub kind: Kind,
    /// Which window of it: now, a limit, a total.
    pub domain: SignalDomain,
    /// How many registers, and in which order.
    pub span: Span,
    /// Whether it is signed.
    pub sign: Sign,
    /// The unit the vendor states it in, which must be the kind's.
    pub unit: Unit,
    /// The vendor's decimal exponent: the raw value times ten to this is the
    /// value in `unit`.
    pub decade: i8,
    /// The raw pattern the vendor sends for *not available*, if it has one.
    /// It publishes `unsupported` and no value.
    pub absent: Option<u32>,
    /// The range the vendor documents for this value, at the kind's scale,
    /// inside the kind's own [`Kind::intrinsic`] range where it has one. A
    /// decoded value outside either publishes `out_of_range` and no value.
    pub plausible: Option<Plausible>,
    /// The provenance the vendor can justify for this value. There is no
    /// default: a cell says where its number comes from.
    pub provenance: Provenance,
}

/// The widest step between a vendor's decade and a kind's scale: `10^9` is
/// the largest power of ten a `u32` holds.
const MAX_DECADE_STEP: u8 = 9;

/// Why a cell's declaration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CellError {
    /// The unit is not the kind's.
    Unit,
    /// The decade is more than nine decades from the kind's scale.
    Decade,
    /// The kind cannot carry this provenance over this domain.
    Provenance,
    /// The absent pattern does not fit the span.
    AbsentPattern,
    /// The cell's registers are not all inside the block's read.
    OutsideBlock,
    /// The plausible range is empty, or reaches outside the kind's own.
    Plausible,
}

impl CellError {
    /// Why, in words, for the build error a `const` table gets.
    #[must_use]
    pub const fn why(self) -> &'static str {
        match self {
            Self::Unit => "a cell's unit is not its kind's",
            Self::Decade => "a cell's decade is more than nine decades from its kind's scale",
            Self::Provenance => "a cell declares a provenance its kind cannot carry",
            Self::AbsentPattern => "a cell's absent pattern does not fit its span",
            Self::OutsideBlock => "a cell's registers are outside its block's read",
            Self::Plausible => "a cell's plausible range is empty or outside its kind's",
        }
    }
}

/// Why a block's declaration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BlockError {
    /// The read is zero registers, more than [`MAX_REGISTERS`], or runs past
    /// register `0xFFFF`.
    Read,
    /// The block has no cells.
    Empty,
    /// The cell at `index` was refused.
    Cell {
        /// Its position in the block.
        index: usize,
        /// Why.
        error: CellError,
    },
}

impl BlockError {
    /// Why, in words.
    #[must_use]
    pub const fn why(self) -> &'static str {
        match self {
            Self::Read => "a block's read is zero registers, more than 125, or past 0xFFFF",
            Self::Empty => "a block has no cells",
            Self::Cell { error, .. } => error.why(),
        }
    }
}

/// One register read and the cells it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Block {
    function: Function,
    start: u16,
    count: u16,
    cells: &'static [Cell],
}

impl Block {
    /// A block reading `count` registers from `start`, or why not.
    pub const fn try_new(
        function: Function,
        start: u16,
        count: u16,
        cells: &'static [Cell],
    ) -> Result<Self, BlockError> {
        if count == 0 || count > MAX_REGISTERS {
            return Err(BlockError::Read);
        }
        let Some(last) = start.checked_add(count.saturating_sub(1)) else {
            return Err(BlockError::Read);
        };
        if cells.is_empty() {
            return Err(BlockError::Empty);
        }
        let mut index = 0usize;
        let mut rest = cells;
        while let [cell, tail @ ..] = rest {
            if let Err(error) = check(cell, start, last) {
                return Err(BlockError::Cell { index, error });
            }
            index = index.saturating_add(1);
            rest = tail;
        }
        Ok(Self {
            function,
            start,
            count,
            cells,
        })
    }

    /// The cells, in declaration order.
    #[must_use]
    pub const fn cells(&self) -> &'static [Cell] {
        self.cells
    }

    /// The register space it reads.
    #[must_use]
    pub const fn function(&self) -> Function {
        self.function
    }

    /// The first register it reads.
    #[must_use]
    pub const fn start(&self) -> u16 {
        self.start
    }

    /// How many registers it reads.
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// The read that fetches this block from the server at `address`.
    #[must_use]
    pub const fn read(&self, address: Address) -> Read {
        // `try_new` held the count and range to what `Read::new` requires.
        Read::checked(address, self.function, self.start, self.count)
    }

    /// Each cell's observation from `registers`, in declaration order.
    ///
    /// The only way to decode a cell: the decoder behind it is private, so a
    /// cell nobody checked cannot reach it.
    ///
    /// ```compile_fail
    /// use o89_drivers::dialect::decode;
    /// ```
    ///
    /// ```
    /// use o89_drivers::dialect::Block;
    ///
    /// let _ = Block::decode;
    /// ```
    pub fn decode<'a>(
        &self,
        registers: &'a Registers<'a>,
    ) -> impl Iterator<Item = Result<Observation, DecodeError>> + 'a {
        self.cells.iter().map(|cell| decode(cell, registers))
    }
}

/// Whether `cell` is a declaration its block may carry.
const fn check(cell: &Cell, first: u16, last: u16) -> Result<(), CellError> {
    if unit_code(cell.unit) != unit_code(cell.kind.unit()) {
        return Err(CellError::Unit);
    }
    if cell.decade.abs_diff(cell.kind.scale()) > MAX_DECADE_STEP {
        return Err(CellError::Decade);
    }
    if !cell.kind.accepts(cell.domain).contains(cell.provenance) {
        return Err(CellError::Provenance);
    }
    if let Some(range) = cell.plausible {
        if range.low > range.high {
            return Err(CellError::Plausible);
        }
        if let Some(own) = cell.kind.intrinsic()
            && (range.low < own.low || range.high > own.high)
        {
            return Err(CellError::Plausible);
        }
    }
    if let Some(pattern) = cell.absent
        && pattern > cell.span.max()
    {
        return Err(CellError::AbsentPattern);
    }
    let Some(end) = cell
        .register
        .checked_add(cell.span.registers().saturating_sub(1))
    else {
        return Err(CellError::OutsideBlock);
    };
    if cell.register < first || end > last {
        return Err(CellError::OutsideBlock);
    }
    Ok(())
}

/// A unit's registry number, which a `const` can compare where `==` cannot.
const fn unit_code(unit: Unit) -> u8 {
    match unit {
        Unit::Volt => 0x1,
        Unit::Ampere => 0x2,
        Unit::Watt => 0x3,
        Unit::WattHour => 0x4,
        Unit::AmpereHour => 0x5,
        Unit::DegreeCelsius => 0x6,
        Unit::Percent => 0x7,
        Unit::Hertz => 0x8,
        Unit::Second => 0x9,
        Unit::Minute => 0xa,
        Unit::Hour => 0xb,
        Unit::Count => 0xc,
        Unit::Ohm => 0xd,
        Unit::Pascal => 0xe,
        Unit::Litre => 0xf,
        Unit::None => 0x10,
    }
}

/// Why a cell produced no observation at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a cell that could not be decoded is a reading that was not recorded"]
pub enum DecodeError {
    /// A register the cell spans is not in the reply: the registers are not
    /// this block's read.
    Missing(u16),
    /// KM43 refused the observation. A checked block's provenance always
    /// carries a value, so this is a defect surfaced rather than hidden.
    Quality(QualityError),
}

/// `cell`'s observation from `registers`. Private: a cell is decoded only
/// through the [`Block`] that checked it.
///
/// The vendor's absent pattern publishes `unsupported`; a value
/// that does not fit an `i32` at the kind's scale, or falls outside the
/// kind's intrinsic range or the cell's plausible one, publishes
/// `out_of_range` rather than a clamped number (P-185); anything else
/// publishes with the cell's declared provenance and nothing else.
fn decode(cell: &Cell, registers: &Registers<'_>) -> Result<Observation, DecodeError> {
    let word = |at: u16| {
        let register = cell
            .register
            .checked_add(at)
            .ok_or(DecodeError::Missing(cell.register))?;
        registers.at(register).ok_or(DecodeError::Missing(register))
    };
    let sign = |raw: u32, signed: i64| match cell.sign {
        Sign::Unsigned => i64::from(raw),
        Sign::Signed => signed,
    };
    let (raw, value) = match cell.span {
        Span::One => {
            let word = word(0)?;
            (
                u32::from(word),
                sign(u32::from(word), i64::from(word.cast_signed())),
            )
        }
        Span::TwoLowFirst | Span::TwoHighFirst => {
            let (first, second) = (u32::from(word(0)?), u32::from(word(1)?));
            let raw = match cell.span {
                Span::TwoHighFirst => (first << 16) | second,
                Span::One | Span::TwoLowFirst => first | (second << 16),
            };
            (raw, sign(raw, i64::from(raw.cast_signed())))
        }
    };
    if cell.absent == Some(raw) {
        return Observation::missing(Validity::Unsupported).map_err(DecodeError::Quality);
    }
    let Some(scaled) = rescale(value, cell.decade, cell.kind.scale()) else {
        return Observation::missing(Validity::OutOfRange).map_err(DecodeError::Quality);
    };
    let Ok(value) = i32::try_from(scaled) else {
        return Observation::missing(Validity::OutOfRange).map_err(DecodeError::Quality);
    };
    let implausible = [cell.kind.intrinsic(), cell.plausible]
        .into_iter()
        .flatten()
        .any(|range| !range.holds(value));
    if implausible {
        return Observation::missing(Validity::OutOfRange).map_err(DecodeError::Quality);
    }
    Observation::value(value, cell.provenance).map_err(DecodeError::Quality)
}

/// `value × 10^decade` expressed at `scale`, rounding half away from zero
/// when the vendor is finer than the registry.
fn rescale(value: i64, decade: i8, scale: i8) -> Option<i64> {
    let step = u32::from(decade.abs_diff(scale));
    let factor = 10i64.checked_pow(step)?;
    if decade >= scale {
        value.checked_mul(factor)
    } else {
        let half = factor.checked_div(2)?;
        let nudged = if value < 0 {
            value.checked_sub(half)?
        } else {
            value.checked_add(half)?
        };
        nudged.checked_div(factor)
    }
}

/// A Modbus device's register map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RegisterMap {
    /// The KM43 dialect this map speaks.
    pub dialect: Dialect,
    /// The reads that cover it, in the order a poll makes them.
    pub blocks: &'static [Block],
}

impl RegisterMap {
    /// Every cell across every block, in poll order.
    pub fn cells(&self) -> impl Iterator<Item = &'static Cell> {
        self.blocks.iter().flat_map(|block| block.cells.iter())
    }
}

/// Every register map this build decodes. Empty until the first dialect
/// lands (#191); the table #6's `xtask` reads.
pub const REGISTER_MAPS: &[RegisterMap] = &[];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::modbus::tests::register_reply as reply;
    use crate::modbus::{Address, parse};
    use km43::METRIC_UNITS;
    use o89_core::{ChargeSource, Limits, Millis, Signals, Tick};

    const EVERY_KIND: [Kind; 11] = [
        Kind::DcVoltage,
        Kind::DcCurrent,
        Kind::DcPower,
        Kind::StateOfCharge,
        Kind::AcVoltage,
        Kind::AcCurrent,
        Kind::AcPower,
        Kind::AcFrequency,
        Kind::AcEnergy,
        Kind::Temperature,
        Kind::TankLevel,
    ];

    const EVERY_DOMAIN: [SignalDomain; 9] = [
        SignalDomain::Live,
        SignalDomain::Lifetime,
        SignalDomain::SinceReset,
        SignalDomain::Today,
        SignalDomain::Yesterday,
        SignalDomain::LimitUpper,
        SignalDomain::LimitLower,
        SignalDomain::Max,
        SignalDomain::Min,
    ];

    /// A cell built by hand for these tests; not a vendor's row.
    pub(crate) const fn cell(
        register: u16,
        kind: Kind,
        domain: SignalDomain,
        decade: i8,
        provenance: Provenance,
    ) -> Cell {
        Cell {
            register,
            kind,
            domain,
            span: Span::One,
            sign: Sign::Unsigned,
            unit: kind.unit(),
            decade,
            absent: None,
            plausible: None,
            provenance,
        }
    }

    fn one(block: &Block, words: &[u16]) -> Observation {
        let read = block.read(Address::new(1).unwrap());
        let (frame, len) = reply(1, block.function().code(), words);
        let registers = parse(read, &frame[..len]).unwrap();
        block.decode(&registers).next().unwrap().unwrap()
    }

    #[test]
    fn every_kind_s_unit_and_scale_are_km43_s_registry_row() {
        for kind in EVERY_KIND {
            let row = METRIC_UNITS
                .iter()
                .find(|(code, _, _)| *code == kind.metric().0)
                .expect("a registry row");
            let symbol = match kind.unit() {
                Unit::Volt => "V",
                Unit::Ampere => "A",
                Unit::Watt => "W",
                Unit::WattHour => "Wh",
                Unit::Percent => "%",
                Unit::Hertz => "Hz",
                Unit::DegreeCelsius => "°C",
                other => panic!("{kind:?} publishes {other:?}, which no kind here uses"),
            };
            assert_eq!((row.1, row.2), (symbol, kind.scale()), "{kind:?}");
            // A percentage's own range is 0 to 100 % at the registry's scale.
            if symbol == "%" {
                let steps = u32::from(kind.scale().unsigned_abs());
                let hundred = 100i32.checked_mul(10i32.pow(steps)).unwrap();
                assert_eq!(
                    kind.intrinsic(),
                    Some(Plausible {
                        low: 0,
                        high: hundred
                    }),
                    "{kind:?}"
                );
            } else {
                assert_eq!(kind.intrinsic(), None, "{kind:?}");
            }
        }
    }

    #[test]
    fn f_052_no_kind_accepts_none_derived_or_commanded_over_any_domain() {
        for kind in EVERY_KIND {
            for domain in EVERY_DOMAIN {
                let set = kind.accepts(domain);
                for never in [Provenance::None, Provenance::Derived, Provenance::Commanded] {
                    assert!(!set.contains(never), "{kind:?} {domain:?} {never:?}");
                }
            }
        }
    }

    #[test]
    fn f_052_estimated_counted_reported_and_measured_have_distinct_eligibility() {
        let soc = Kind::StateOfCharge.accepts(SignalDomain::Live);
        assert!(soc.contains(Provenance::Estimated));
        assert!(soc.contains(Provenance::Counted));
        assert!(!soc.contains(Provenance::Measured));
        assert!(!soc.contains(Provenance::Reported));

        let volts = Kind::DcVoltage.accepts(SignalDomain::Live);
        assert!(volts.contains(Provenance::Measured));
        assert!(!volts.contains(Provenance::Estimated));

        for kind in EVERY_KIND {
            for limit in [SignalDomain::LimitUpper, SignalDomain::LimitLower] {
                assert_eq!(
                    kind.accepts(limit),
                    ProvenanceSet::of(&[Provenance::Reported]),
                    "{kind:?}"
                );
            }
        }
        assert_eq!(
            Kind::AcEnergy.accepts(SignalDomain::Lifetime),
            ProvenanceSet::of(&[Provenance::Counted])
        );
        assert_eq!(
            Kind::AcEnergy.accepts(SignalDomain::Live),
            ProvenanceSet::EMPTY
        );
    }

    const VOLTS: Cell = cell(
        0,
        Kind::DcVoltage,
        SignalDomain::Live,
        -2,
        Provenance::Measured,
    );

    #[test]
    fn f_052_a_disallowed_kind_and_provenance_pair_fails_checked_construction() {
        static SOC: [Cell; 1] = [Cell {
            kind: Kind::StateOfCharge,
            unit: Unit::Percent,
            decade: 0,
            ..VOLTS
        }];
        static LIMIT: [Cell; 2] = [
            VOLTS,
            Cell {
                register: 1,
                domain: SignalDomain::LimitUpper,
                ..VOLTS
            },
        ];
        static NONE: [Cell; 1] = [Cell {
            provenance: Provenance::None,
            ..VOLTS
        }];
        static ESTIMATED_VOLTS: [Cell; 1] = [Cell {
            provenance: Provenance::Estimated,
            ..VOLTS
        }];
        for (cells, index) in [
            (&SOC[..], 0),
            (&LIMIT[..], 1),
            (&NONE[..], 0),
            (&ESTIMATED_VOLTS[..], 0),
        ] {
            assert_eq!(
                Block::try_new(Function::ReadInput, 0, 2, cells),
                Err(BlockError::Cell {
                    index,
                    error: CellError::Provenance
                }),
                "{:?}",
                cells[index]
            );
        }
    }

    #[test]
    fn a_unit_decade_absent_pattern_or_register_outside_the_block_fails_checked_construction() {
        static WRONG_UNIT: [Cell; 1] = [Cell {
            unit: Unit::Ampere,
            ..VOLTS
        }];
        static FAR: [Cell; 1] = [Cell { decade: 7, ..VOLTS }];
        static WIDE: [Cell; 1] = [Cell {
            absent: Some(0x1_0000),
            ..VOLTS
        }];
        static PAST: [Cell; 1] = [Cell {
            register: 1,
            span: Span::TwoLowFirst,
            ..VOLTS
        }];
        // Nine decades from the scale is the edge, and allowed; a two-word
        // cell ending on the block's last register is inside it.
        static EDGE: [Cell; 2] = [
            Cell { decade: 6, ..VOLTS },
            Cell {
                register: 1,
                span: Span::TwoHighFirst,
                ..VOLTS
            },
        ];
        for (cells, start, error) in [
            (&WRONG_UNIT, 0, CellError::Unit),
            (&FAR, 0, CellError::Decade),
            (&WIDE, 0, CellError::AbsentPattern),
            (&PAST, 0, CellError::OutsideBlock),
            (&[VOLTS], 1, CellError::OutsideBlock),
        ] {
            assert_eq!(
                Block::try_new(Function::ReadInput, start, 2, cells),
                Err(BlockError::Cell { index: 0, error }),
                "{:?}",
                cells[0]
            );
        }
        assert!(Block::try_new(Function::ReadInput, 0, 3, &EDGE).is_ok());
    }

    #[test]
    fn a_plausible_range_that_is_empty_or_outside_its_kind_s_fails_checked_construction() {
        const SOC: Cell = cell(
            0,
            Kind::StateOfCharge,
            SignalDomain::Live,
            -1,
            Provenance::Counted,
        );
        static EMPTY: [Cell; 1] = [Cell {
            plausible: Some(Plausible { low: 10, high: 9 }),
            ..VOLTS
        }];
        static BELOW: [Cell; 1] = [Cell {
            plausible: Some(Plausible {
                low: -1,
                high: 1000,
            }),
            ..SOC
        }];
        static ABOVE: [Cell; 1] = [Cell {
            plausible: Some(Plausible { low: 0, high: 1001 }),
            ..SOC
        }];
        static INSIDE: [Cell; 2] = [
            Cell {
                plausible: Some(Plausible { low: 0, high: 1000 }),
                ..SOC
            },
            Cell {
                register: 1,
                plausible: Some(Plausible { low: 7, high: 7 }),
                ..VOLTS
            },
        ];
        for cells in [&EMPTY, &BELOW, &ABOVE] {
            assert_eq!(
                Block::try_new(Function::ReadInput, 0, 1, cells),
                Err(BlockError::Cell {
                    index: 0,
                    error: CellError::Plausible
                })
            );
        }
        assert!(Block::try_new(Function::ReadInput, 0, 2, &INSIDE).is_ok());
    }

    #[test]
    fn a_value_outside_the_vendor_s_documented_range_is_out_of_range_and_the_edges_are_not() {
        // A probe the vendor documents from −40.0 to 125.0 °C, built by hand.
        static CELLS: [Cell; 1] = [Cell {
            sign: Sign::Signed,
            plausible: Some(Plausible {
                low: -400,
                high: 1250,
            }),
            ..cell(
                0,
                Kind::Temperature,
                SignalDomain::Live,
                -1,
                Provenance::Measured,
            )
        }];
        const BLOCK: Block = crate::block!(Function::ReadInput, 0, 1, &CELLS);
        for (raw, expected) in [
            (1250u16, Some(1250)),
            ((-400i16).cast_unsigned(), Some(-400)),
            (1251, None),
            ((-401i16).cast_unsigned(), None),
        ] {
            let seen = one(&BLOCK, &[raw]);
            assert_eq!(seen.reading(), expected, "{raw:#06x}");
            if expected.is_none() {
                assert_eq!(seen.quality().validity_of(), Validity::OutOfRange);
            }
        }
    }

    #[test]
    fn a_tank_level_past_full_or_below_empty_is_out_of_range() {
        static CELLS: [Cell; 1] = [Cell {
            sign: Sign::Signed,
            ..cell(
                0,
                Kind::TankLevel,
                SignalDomain::Live,
                -1,
                Provenance::Measured,
            )
        }];
        const BLOCK: Block = crate::block!(Function::ReadInput, 0, 1, &CELLS);
        assert_eq!(one(&BLOCK, &[1000]).reading(), Some(1000));
        assert_eq!(one(&BLOCK, &[0]).reading(), Some(0));
        for raw in [1001u16, (-1i16).cast_unsigned()] {
            let seen = one(&BLOCK, &[raw]);
            assert_eq!(seen.reading(), None, "{raw}");
            assert_eq!(seen.quality().validity_of(), Validity::OutOfRange);
        }
    }

    #[test]
    fn a_block_with_no_cells_or_an_impossible_read_is_refused() {
        static ONE: [Cell; 1] = [cell(
            0,
            Kind::DcVoltage,
            SignalDomain::Live,
            -2,
            Provenance::Measured,
        )];
        assert_eq!(
            Block::try_new(Function::ReadInput, 0, 1, &[]),
            Err(BlockError::Empty)
        );
        assert_eq!(
            Block::try_new(Function::ReadInput, 0, 0, &ONE),
            Err(BlockError::Read)
        );
        assert_eq!(
            Block::try_new(Function::ReadInput, 0, 126, &ONE),
            Err(BlockError::Read)
        );
        assert_eq!(
            Block::try_new(Function::ReadInput, 0xFFFF, 2, &ONE),
            Err(BlockError::Read)
        );
    }

    /// A table built by hand in the shape the charger rows of #191 will take;
    /// the registers and decades are illustrative, not a vendor's map.
    static FIXTURE_CELLS: [Cell; 3] = [
        cell(
            0x10,
            Kind::DcVoltage,
            SignalDomain::Live,
            -2,
            Provenance::Measured,
        ),
        cell(
            0x11,
            Kind::StateOfCharge,
            SignalDomain::Live,
            0,
            Provenance::Estimated,
        ),
        cell(
            0x12,
            Kind::DcCurrent,
            SignalDomain::LimitUpper,
            -2,
            Provenance::Reported,
        ),
    ];
    const FIXTURE: Block = crate::block!(Function::ReadInput, 0x10, 3, &FIXTURE_CELLS);

    #[test]
    fn f_052_decoding_writes_each_cell_s_declared_provenance_and_counted_only_refuses_the_estimate()
    {
        let read = FIXTURE.read(Address::new(1).unwrap());
        let (frame, len) = reply(1, 0x04, &[1325, 64, 5000]);
        let registers = parse(read, &frame[..len]).unwrap();

        let mut store = Signals::<3>::new();
        let limits = Limits::new(Millis::from_millis(60_000), None).unwrap();
        let ids = [1, 2, 3].map(|n| km43::Id::new(n).unwrap());
        for id in ids {
            store.register(id, limits).unwrap();
        }
        for (id, seen) in ids.iter().zip(FIXTURE.decode(&registers)) {
            store.write(*id, Tick::ZERO, seen.unwrap()).unwrap();
        }

        let volts = store.sample(ids[0], Tick::ZERO).unwrap();
        assert_eq!(volts.value(), Some(13_250));
        assert_eq!(volts.q.provenance_of(), Provenance::Measured);

        let soc = store.sample(ids[1], Tick::ZERO).unwrap();
        assert_eq!(soc.value(), Some(640));
        assert_eq!(soc.q.provenance_of(), Provenance::Estimated);
        assert!(
            store
                .current(ids[1], Tick::ZERO, ChargeSource::CountedOnly.accepts())
                .is_err()
        );
        assert!(
            store
                .current(ids[1], Tick::ZERO, ChargeSource::EstimateAccepted.accepts())
                .is_ok()
        );

        let limit = store.sample(ids[2], Tick::ZERO).unwrap();
        assert_eq!(limit.value(), Some(50_000));
        assert_eq!(limit.q.provenance_of(), Provenance::Reported);
    }

    #[test]
    fn the_vendor_s_absent_pattern_publishes_unsupported_with_no_value() {
        static CELLS: [Cell; 1] = [Cell {
            absent: Some(0xFFFF),
            ..cell(
                0,
                Kind::Temperature,
                SignalDomain::Live,
                -2,
                Provenance::Measured,
            )
        }];
        const BLOCK: Block = crate::block!(Function::ReadInput, 0, 1, &CELLS);
        let seen = one(&BLOCK, &[0xFFFF]);
        assert_eq!(seen.reading(), None);
        assert_eq!(seen.quality().validity_of(), Validity::Unsupported);
        // One count below the pattern is a reading.
        assert_eq!(one(&BLOCK, &[0xFFFE]).reading(), Some(6553));
    }

    #[test]
    fn signed_spans_and_word_orders_decode_exactly() {
        static CELLS: [Cell; 3] = [
            Cell {
                sign: Sign::Signed,
                ..cell(
                    0,
                    Kind::DcCurrent,
                    SignalDomain::Live,
                    -2,
                    Provenance::Measured,
                )
            },
            Cell {
                sign: Sign::Signed,
                span: Span::TwoLowFirst,
                ..cell(
                    1,
                    Kind::DcPower,
                    SignalDomain::Live,
                    -1,
                    Provenance::Measured,
                )
            },
            Cell {
                span: Span::TwoHighFirst,
                ..cell(
                    3,
                    Kind::AcEnergy,
                    SignalDomain::Lifetime,
                    0,
                    Provenance::Counted,
                )
            },
        ];
        const BLOCK: Block = crate::block!(Function::ReadHolding, 0, 5, &CELLS);
        let read = BLOCK.read(Address::new(1).unwrap());
        // −1.50 A; −70000 × 0.1 W, low word first; 0x0001_86A0 Wh.
        let power = (-70_000i32).to_le_bytes();
        let low = u16::from_le_bytes([power[0], power[1]]);
        let high = u16::from_le_bytes([power[2], power[3]]);
        let (frame, len) = reply(1, 0x03, &[0xFF6A, low, high, 0x0001, 0x86A0]);
        let registers = parse(read, &frame[..len]).unwrap();
        let mut values = BLOCK.decode(&registers).map(|seen| seen.unwrap().reading());
        assert_eq!(values.next(), Some(Some(-1_500)));
        assert_eq!(values.next(), Some(Some(-70_000)));
        assert_eq!(values.next(), Some(Some(100_000)));
        assert_eq!(values.next(), None);
    }

    #[test]
    fn p_185_a_value_past_an_i32_at_the_kind_s_scale_is_out_of_range_and_not_clamped() {
        static CELLS: [Cell; 1] = [Cell {
            span: Span::TwoLowFirst,
            ..cell(
                0,
                Kind::DcVoltage,
                SignalDomain::Live,
                0,
                Provenance::Measured,
            )
        }];
        const BLOCK: Block = crate::block!(Function::ReadInput, 0, 2, &CELLS);
        // 2 147 484 V is 2 147 484 000 at −3: one step past i32::MAX.
        let seen = one(&BLOCK, &[0xC49C, 0x0020]);
        assert_eq!(seen.reading(), None);
        assert_eq!(seen.quality().validity_of(), Validity::OutOfRange);
        // 2 147 483 V fits.
        assert_eq!(
            one(&BLOCK, &[0xC49B, 0x0020]).reading(),
            Some(2_147_483_000)
        );
    }

    #[test]
    fn a_vendor_finer_than_the_registry_rounds_half_away_from_zero() {
        assert_eq!(rescale(2_345, -2, -1), Some(235));
        assert_eq!(rescale(2_344, -2, -1), Some(234));
        assert_eq!(rescale(-2_345, -2, -1), Some(-235));
        assert_eq!(rescale(7, 0, 0), Some(7));
        assert_eq!(rescale(i64::MAX, 6, -3), None);
    }

    #[test]
    fn a_cell_whose_register_is_not_in_the_reply_is_missing_rather_than_zero() {
        static CELLS: [Cell; 1] = [cell(
            5,
            Kind::DcVoltage,
            SignalDomain::Live,
            -2,
            Provenance::Measured,
        )];
        let other = Read::new(Address::new(1).unwrap(), Function::ReadInput, 0, 1).unwrap();
        let (frame, len) = reply(1, 0x04, &[1]);
        let registers = parse(other, &frame[..len]).unwrap();
        assert_eq!(decode(&CELLS[0], &registers), Err(DecodeError::Missing(5)));
    }

    #[test]
    fn every_register_map_is_a_distinct_dialect() {
        for (i, map) in REGISTER_MAPS.iter().enumerate() {
            assert!(
                REGISTER_MAPS[..i]
                    .iter()
                    .all(|other| other.dialect != map.dialect)
            );
            assert!(
                map.cells().next().is_some(),
                "{:?} decodes nothing",
                map.dialect
            );
        }
    }
}
