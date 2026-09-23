//! Gregorian UTC conversion for the RTC's two-digit year, 2000 through 2099.

use crate::UnixMillis;

const EPOCH_2000: u64 = 946_684_800_000;
const DAY_MS: u64 = 86_400_000;

/// A calendar reading in the RTC's representable century.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calendar {
    /// Gregorian year, 2000 through 2099.
    pub year: u16,
    /// Month, January is one.
    pub month: u8,
    /// Day within the month.
    pub day: u8,
    /// Hour, on a 24-hour clock.
    pub hour: u8,
    /// Minute within the hour.
    pub minute: u8,
    /// Second within the minute; leap seconds are not represented.
    pub second: u8,
}

fn month_days(year: u16, month: u8) -> Option<u64> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if year.is_multiple_of(4) { 29 } else { 28 }),
        _ => None,
    }
}

impl Calendar {
    /// Convert milliseconds to the calendar's second precision. Refuse dates
    /// outside the hardware century rather than wrapping the year.
    #[must_use]
    pub fn from_unix(at: UnixMillis) -> Option<Self> {
        let elapsed = at.as_millis().checked_sub(EPOCH_2000)?;
        let mut days = elapsed.checked_div(DAY_MS)?;
        let seconds = elapsed.checked_rem(DAY_MS)?.checked_div(1_000)?;
        for year in 2000..=2099 {
            for month in 1..=12 {
                let count = month_days(year, month)?;
                if days < count {
                    return Some(Self {
                        year,
                        month,
                        day: u8::try_from(days.checked_add(1)?).ok()?,
                        hour: u8::try_from(seconds.checked_div(3_600)?).ok()?,
                        minute: u8::try_from(seconds.checked_div(60)?.checked_rem(60)?).ok()?,
                        second: u8::try_from(seconds.checked_rem(60)?).ok()?,
                    });
                }
                days = days.checked_sub(count)?;
            }
        }
        None
    }

    /// Validate a hardware reading, including month lengths and leap days.
    #[must_use]
    pub fn unix(self) -> Option<UnixMillis> {
        if !(2000..=2099).contains(&self.year)
            || self.day == 0
            || u64::from(self.day) > month_days(self.year, self.month)?
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return None;
        }
        let mut days = 0u64;
        for year in 2000..self.year {
            days = days.checked_add(if year.is_multiple_of(4) { 366 } else { 365 })?;
        }
        for month in 1..self.month {
            days = days.checked_add(month_days(self.year, month)?)?;
        }
        days = days.checked_add(u64::from(self.day).checked_sub(1)?)?;
        let seconds = u64::from(self.hour)
            .checked_mul(3_600)?
            .checked_add(u64::from(self.minute).checked_mul(60)?)?
            .checked_add(u64::from(self.second))?;
        UnixMillis::new(
            EPOCH_2000
                .checked_add(days.checked_mul(DAY_MS)?)?
                .checked_add(seconds.checked_mul(1_000)?)?,
        )
    }

    /// ISO weekday, Monday one through Sunday seven.
    #[must_use]
    pub fn weekday(self) -> Option<u8> {
        let days = self.unix()?.as_millis().checked_div(DAY_MS)?;
        u8::try_from(days.checked_add(3)?.checked_rem(7)?.checked_add(1)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtc_epoch_leap_day_and_last_second() {
        for (at, calendar, weekday) in [
            (
                946_684_800_000,
                Calendar {
                    year: 2000,
                    month: 1,
                    day: 1,
                    hour: 0,
                    minute: 0,
                    second: 0,
                },
                6,
            ),
            (
                1_709_164_800_000,
                Calendar {
                    year: 2024,
                    month: 2,
                    day: 29,
                    hour: 0,
                    minute: 0,
                    second: 0,
                },
                4,
            ),
            (
                4_102_444_799_000,
                Calendar {
                    year: 2099,
                    month: 12,
                    day: 31,
                    hour: 23,
                    minute: 59,
                    second: 59,
                },
                4,
            ),
        ] {
            assert_eq!(
                Calendar::from_unix(UnixMillis::new(at + 999).unwrap()),
                Some(calendar)
            );
            assert_eq!(calendar.unix(), UnixMillis::new(at));
            assert_eq!(calendar.weekday(), Some(weekday));
        }
    }

    #[test]
    fn rtc_refuses_dates_that_wrap_its_century() {
        for at in [946_684_799_999, 4_102_444_800_000, u64::MAX] {
            assert_eq!(Calendar::from_unix(UnixMillis::new(at).unwrap()), None);
        }
    }

    #[test]
    fn rtc_refuses_invalid_register_dates() {
        let good = Calendar {
            year: 2023,
            month: 2,
            day: 28,
            hour: 0,
            minute: 0,
            second: 0,
        };
        for bad in [
            Calendar { day: 29, ..good },
            Calendar { month: 13, ..good },
            Calendar { day: 0, ..good },
            Calendar { hour: 24, ..good },
            Calendar { minute: 60, ..good },
            Calendar { second: 60, ..good },
            Calendar { year: 2100, ..good },
        ] {
            assert_eq!(bad.unix(), None);
        }
    }
}
