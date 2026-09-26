//! The comms processor's station DHCP configuration.
//!
//! The comms firmware builds for the ESP32-C6 alone, so a configuration it
//! built for itself could be timed on the host only by a copy, and a copy
//! passes when the firmware's drifts (firmware #150). The firmware and
//! `o89-sim`'s test of the DHCP resends both call [`station_dhcp`].
//!
//! Apart from `o89-comms-core` because this crate carries embassy-net, and
//! `o89-comms-core` is also cross-compiled for the controller's target.
//! `no_std` and no `alloc`.

#![no_std]

use embassy_net::DhcpConfig;
use o89_comms_core::DHCP_DISCOVER_RESEND;

/// A hostname longer than embassy-net's DHCP client carries, 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostnameTooLong;

/// The station's DHCP client configuration: `hostname` offered to the server
/// (option 12), and a lost DISCOVER resent after
/// [`DHCP_DISCOVER_RESEND`], inside the `no_ip` bound (F-092), rather than
/// after smoltcp's 10 s.
///
/// Refuses a hostname over 32 bytes rather than truncating it: mDNS
/// announces the same name, and the two must agree.
pub fn station_dhcp(hostname: &str) -> Result<DhcpConfig, HostnameTooLong> {
    let mut dhcp = DhcpConfig::default();
    dhcp.hostname = Some(hostname.try_into().map_err(|_| HostnameTooLong)?);
    dhcp.retry_config.discover_timeout =
        smoltcp::time::Duration::from_millis(DHCP_DISCOVER_RESEND.as_millis());
    Ok(dhcp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 bytes, embassy-net's longest hostname and KM43's.
    const LONGEST: &str = "o89-abcdefghijklmnopqrstuvwxyz01";

    #[test]
    fn f_092_the_station_resends_a_lost_discover_after_the_configured_wait() {
        let dhcp = station_dhcp("o89").expect("a short hostname");
        assert_eq!(
            dhcp.retry_config.discover_timeout.total_millis(),
            DHCP_DISCOVER_RESEND.as_millis()
        );
        assert_ne!(
            dhcp.retry_config.discover_timeout,
            DhcpConfig::default().retry_config.discover_timeout,
            "the wait is smoltcp's default"
        );
        assert_eq!(dhcp.hostname.as_deref(), Some("o89"));
    }

    #[test]
    fn a_hostname_of_32_bytes_is_carried_whole() {
        assert_eq!(LONGEST.len(), 32);
        let dhcp = station_dhcp(LONGEST).expect("32 bytes fit");
        assert_eq!(dhcp.hostname.as_deref(), Some(LONGEST));
    }

    #[test]
    fn a_hostname_of_33_bytes_is_refused_not_truncated() {
        let longer = "o89-abcdefghijklmnopqrstuvwxyz012";
        assert_eq!(longer.len(), 33);
        assert_eq!(station_dhcp(longer).err(), Some(HostnameTooLong));
    }

    #[test]
    fn a_multibyte_hostname_is_measured_in_bytes() {
        // Sixteen two-byte characters fill the 32 bytes; one more does not fit.
        assert!(station_dhcp("éééééééééééééééé").is_ok());
        assert_eq!(
            station_dhcp("ééééééééééééééééé").err(),
            Some(HostnameTooLong)
        );
    }
}
