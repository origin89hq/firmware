//! The buses board A has, one per connector, and the number each goes by.
//!
//! A bus is a connector on the board: configuration sets how a bus runs and
//! what is on it, and never adds, removes or renumbers one (P-261). So the
//! list is fixed here, with the number the inventory's `BusRow` and the
//! `0x0003 buses and devices` section both name it by, its transport, the
//! task that owns it, and how many configured devices it carries. Bus 0 is
//! the controller's own inputs, which no configuration writes a device on.
//!
//! cites: P-261

use km43::{BoardBus, Transport};

use crate::rollcall::Task;
use crate::topology::SiteBus;
use crate::{Bus, Port};

/// One bus the board has, by the connector it leaves the board on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Connector {
    /// The controller's own inputs: the ADC channels.
    Local,
    /// An RS-485 channel.
    Rs485(Bus),
    /// A VE.Direct port, receive only.
    VeDirect(Port),
    /// CAN on CN5.
    Can,
    /// The 1-Wire line on CN8 and CN11.
    OneWire,
}

/// How many buses the board has.
pub const CONNECTORS: usize = 8;

/// The most devices a configuration may put on one RS-485 channel: the
/// table its task polls in turn.
pub const RS485_DEVICES: usize = 8;

/// The most probes a configuration may put on the 1-Wire line, the most a
/// search on it collects.
pub const ONEWIRE_DEVICES: usize = 8;

/// The most devices any one bus carries.
pub const BUS_DEVICES: usize = if RS485_DEVICES > ONEWIRE_DEVICES {
    RS485_DEVICES
} else {
    ONEWIRE_DEVICES
};

impl Connector {
    /// Every bus, in bus-number order.
    pub const ALL: [Self; CONNECTORS] = [
        Self::Local,
        Self::Rs485(Bus::One),
        Self::Rs485(Bus::Two),
        Self::Rs485(Bus::Three),
        Self::VeDirect(Port::One),
        Self::VeDirect(Port::Two),
        Self::Can,
        Self::OneWire,
    ];

    /// The number the inventory and the configuration name it by.
    #[must_use]
    pub const fn bus(self) -> u8 {
        match self {
            Self::Local => 0,
            Self::Rs485(Bus::One) => 1,
            Self::Rs485(Bus::Two) => 2,
            Self::Rs485(Bus::Three) => 3,
            Self::VeDirect(Port::One) => 4,
            Self::VeDirect(Port::Two) => 5,
            Self::Can => 6,
            Self::OneWire => 7,
        }
    }

    /// The bus numbered `bus`, or `None` for one the board does not have.
    #[must_use]
    pub const fn from_bus(bus: u8) -> Option<Self> {
        match bus {
            0 => Some(Self::Local),
            1 => Some(Self::Rs485(Bus::One)),
            2 => Some(Self::Rs485(Bus::Two)),
            3 => Some(Self::Rs485(Bus::Three)),
            4 => Some(Self::VeDirect(Port::One)),
            5 => Some(Self::VeDirect(Port::Two)),
            6 => Some(Self::Can),
            7 => Some(Self::OneWire),
            _ => None,
        }
    }

    /// Its transport.
    #[must_use]
    pub const fn transport(self) -> Transport {
        match self {
            Self::Local => Transport::LocalIo,
            Self::Rs485(_) => Transport::Rs485,
            Self::VeDirect(_) => Transport::VeDirect,
            Self::Can => Transport::Can,
            Self::OneWire => Transport::Onewire,
        }
    }

    /// The task that owns it.
    #[must_use]
    pub const fn task(self) -> Task {
        match self {
            Self::Local => Task::Adc,
            Self::Rs485(Bus::One) => Task::Rs485One,
            Self::Rs485(Bus::Two) => Task::Rs485Two,
            Self::Rs485(Bus::Three) => Task::Rs485Three,
            Self::VeDirect(Port::One) => Task::VeDirectOne,
            Self::VeDirect(Port::Two) => Task::VeDirectTwo,
            Self::Can => Task::Can,
            Self::OneWire => Task::OneWire,
        }
    }

    /// How many configured devices it carries; one more is refused.
    ///
    /// A VE.Direct port is point to point; the CAN driver reads one BMS at
    /// address 0; the controller's own inputs are no configured device.
    #[must_use]
    pub const fn capacity(self) -> usize {
        match self {
            Self::Local => 0,
            Self::Rs485(_) => RS485_DEVICES,
            Self::VeDirect(_) | Self::Can => 1,
            Self::OneWire => ONEWIRE_DEVICES,
        }
    }

    /// The bus as the configuration checks against it.
    #[must_use]
    pub const fn board(self) -> BoardBus {
        BoardBus {
            bus: self.bus(),
            transport: self.transport(),
        }
    }

    /// Its inventory row, at `rate` where the bus has one.
    #[must_use]
    pub const fn row(self, rate: Option<u32>) -> SiteBus {
        SiteBus {
            bus: self.bus(),
            transport: self.transport(),
            rate,
        }
    }
}

/// The buses as `0x0003 buses and devices` is checked against them.
pub const BOARD_BUSES: [BoardBus; CONNECTORS] = [
    Connector::Local.board(),
    Connector::Rs485(Bus::One).board(),
    Connector::Rs485(Bus::Two).board(),
    Connector::Rs485(Bus::Three).board(),
    Connector::VeDirect(Port::One).board(),
    Connector::VeDirect(Port::Two).board(),
    Connector::Can.board(),
    Connector::OneWire.board(),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_261_every_bus_has_one_number_and_the_numbers_are_the_inventory_s() {
        for (at, connector) in Connector::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(connector.bus()), at);
            assert_eq!(Connector::from_bus(connector.bus()), Some(connector));
            assert_eq!(BOARD_BUSES[at].bus, connector.bus());
            assert_eq!(BOARD_BUSES[at].transport, connector.transport());
        }
        assert_eq!(CONNECTORS, crate::topology::SITE_BUSES);
    }

    #[test]
    fn p_261_a_bus_the_board_does_not_have_is_none() {
        assert_eq!(Connector::from_bus(8), None);
        assert_eq!(Connector::from_bus(u8::MAX), None);
    }

    #[test]
    fn each_bus_is_its_own_task_s_and_carries_what_its_transport_can() {
        for (at, a) in Connector::ALL.into_iter().enumerate() {
            for b in Connector::ALL.iter().skip(at + 1) {
                assert_ne!(a.task(), b.task());
            }
        }
        assert_eq!(Connector::Local.capacity(), 0);
        assert_eq!(Connector::VeDirect(Port::One).capacity(), 1);
        assert_eq!(Connector::Can.capacity(), 1);
        assert_eq!(Connector::Rs485(Bus::Two).capacity(), RS485_DEVICES);
        assert_eq!(Connector::OneWire.capacity(), ONEWIRE_DEVICES);
        assert!(Connector::ALL.iter().all(|c| c.capacity() <= BUS_DEVICES));
        assert_eq!(Connector::Local.row(None).transport, Transport::LocalIo);
        assert_eq!(
            Connector::Rs485(Bus::One).row(Some(115_200)).rate,
            Some(115_200)
        );
    }
}
