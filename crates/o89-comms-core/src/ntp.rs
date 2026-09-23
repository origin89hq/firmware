//! NTP packet validation and the monotonic time-offer rate limit.
use crate::Tick;

/// NTP's fixed header. Extensions are not requested or consumed.
pub const NTP_BYTES: usize = 48;
/// Minimum separation between offers, including offers the controller refuses.
pub const OFFER_INTERVAL_MS: u64 = 900_000;
const UNIX_OFFSET: u64 = 2_208_988_800;

/// One request's unpredictable transmit timestamp, echoed as the response origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpRequest([u8; 8]);

impl NtpRequest {
    /// A nonzero nonce drawn by the target's random source.
    #[must_use]
    pub const fn new(nonce: [u8; 8]) -> Self {
        Self(nonce)
    }

    /// Version four, client mode; no local wall clock is set or claimed.
    #[must_use]
    pub fn packet(self) -> [u8; NTP_BYTES] {
        let mut packet = [0; NTP_BYTES];
        if let Some(first) = packet.first_mut() {
            *first = 0x23;
        }
        if let Some(stamp) = packet.get_mut(40..48) {
            stamp.copy_from_slice(&self.0);
        }
        packet
    }

    /// Accept only a synchronized server response to this request. Era one is
    /// selected for timestamps below the Unix offset (the 2036 rollover).
    #[must_use]
    pub fn unix_ms(self, response: &[u8]) -> Option<u64> {
        if response.len() != NTP_BYTES || self.0 == [0; 8] {
            return None;
        }
        let flags = *response.first()?;
        let version = (flags >> 3) & 7;
        if flags >> 6 == 3
            || flags & 7 != 4
            || !(3..=4).contains(&version)
            || !(1..=15).contains(response.get(1)?)
            || response.get(24..32)? != self.0
        {
            return None;
        }
        let seconds = u64::from(u32::from_be_bytes(response.get(40..44)?.try_into().ok()?));
        let fraction = u64::from(u32::from_be_bytes(response.get(44..48)?.try_into().ok()?));
        if seconds == 0 && fraction == 0 {
            return None;
        }
        let seconds = if seconds < UNIX_OFFSET {
            seconds.checked_add(1u64 << 32)?
        } else {
            seconds
        };
        seconds
            .checked_sub(UNIX_OFFSET)?
            .checked_mul(1_000)?
            .checked_add(fraction.checked_mul(1_000)? >> 32)
    }
}

/// Rate accounting survives link loss and controller refusal within this boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OfferRate {
    last: Option<Tick>,
}
impl OfferRate {
    /// No offer has been attempted this boot.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }
    /// Take permission immediately before attempting a send; a failed send also
    /// consumes the interval. Protocol retries retain the same request and sample.
    pub fn take(&mut self, now: Tick) -> bool {
        if let Some(last) = self.last
            && now
                .since(last)
                .is_none_or(|elapsed| elapsed.as_millis() < OFFER_INTERVAL_MS)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response() -> (NtpRequest, [u8; 48]) {
        let request = NtpRequest::new([1; 8]);
        let mut response = [0; 48];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&[1; 8]);
        response[40..44].copy_from_slice(&3_908_988_800u32.to_be_bytes());
        response[44..48].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        (request, response)
    }
    #[test]
    fn ntp_response_converts_seconds_and_fraction_without_setting_a_clock() {
        let (request, response) = response();
        assert_eq!(request.unix_ms(&response), Some(1_700_000_000_500));
        assert_eq!(request.packet()[0], 0x23);
    }
    #[test]
    fn ntp_refuses_unsynchronized_kiss_of_death_wrong_mode_and_wrong_origin() {
        let (request, response) = response();
        for (offset, value) in [(0, 0xe4), (0, 0x23), (0, 0x14), (1, 0), (1, 16), (24, 2)] {
            let mut bad = response;
            bad[offset] = value;
            assert_eq!(request.unix_ms(&bad), None);
        }
        for len in 0..48 {
            assert_eq!(request.unix_ms(&response[..len]), None);
        }
    }
    #[test]
    fn ntp_handles_era_rollover_and_refuses_zero_timestamp() {
        let (request, mut response) = response();
        response[40..44].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(request.unix_ms(&response), Some(2_085_978_497_500));
        response[40..48].fill(0);
        assert_eq!(request.unix_ms(&response), None);
    }
    #[test]
    fn time_offer_rate_is_fifteen_minutes_including_refusal_or_failed_send() {
        let mut rate = OfferRate::default();
        assert!(rate.take(Tick::from_millis(100)));
        assert!(!rate.take(Tick::from_millis(100)));
        assert!(!rate.take(Tick::from_millis(900_099)));
        assert!(rate.take(Tick::from_millis(900_100)));
        assert!(!rate.take(Tick::ZERO));
        assert!(rate.take(Tick::from_millis(u64::MAX)));
        assert!(!rate.take(Tick::from_millis(u64::MAX)));
    }
}
