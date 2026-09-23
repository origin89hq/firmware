//! LSE calendar and the five-word TAMP journal for unfinished `TimeSet` records.
use embassy_stm32::rtc::{DateTime, DayOfWeek, Rtc, RtcConfig, RtcError, RtcTimeProvider};
use embassy_stm32::{Peri, peripherals};
use o89_core::{
    BackupDomain, CLOCK_BACKUP_WORDS, Calendar, CalendarStore, ClockChange, ClockJournal,
    JournalError, RtcClock, UnixMillis,
};

#[derive(Debug, defmt::Format)]
pub enum CalendarError {
    UntrustedSource,
    InvalidDate,
    Read(RtcError),
    Write(RtcError),
}

struct Device {
    rtc: Rtc,
    reader: RtcTimeProvider,
    _tamp: Peri<'static, peripherals::TAMP>,
}

pub struct CalendarClock {
    device: Option<Device>,
    journal: ClockJournal,
}

impl CalendarClock {
    pub fn new(
        peripheral: Peri<'static, peripherals::RTC>,
        tamp: Peri<'static, peripherals::TAMP>,
        source: RtcClock,
        backup: BackupDomain,
    ) -> Self {
        if !source.calendar_enabled() {
            return Self {
                device: None,
                journal: ClockJournal::UNKNOWN,
            };
        }
        let (rtc, reader) = Rtc::new(peripheral, RtcConfig::default());
        let device = Device {
            rtc,
            reader,
            _tamp: tamp,
        };
        let journal = match backup {
            BackupDomain::Valid => ClockJournal::load(&device),
            BackupDomain::Invalid => ClockJournal::UNKNOWN,
        };
        Self {
            device: Some(device),
            journal,
        }
    }

    pub fn now(&self) -> Option<UnixMillis> {
        match self.read() {
            Ok(at) => at,
            Err(error) => {
                defmt::error!("clock: calendar unavailable: {}", error);
                None
            }
        }
    }

    pub fn read(&self) -> Result<Option<UnixMillis>, CalendarError> {
        if self.device.is_none() {
            return Err(CalendarError::UntrustedSource);
        }
        let Some(fraction) = self.journal.fraction() else {
            return Ok(None);
        };
        self.read_known(fraction).map(Some)
    }
    fn read_known(&self, fraction: u32) -> Result<UnixMillis, CalendarError> {
        let device = self.device.as_ref().ok_or(CalendarError::UntrustedSource)?;
        let date = device.reader.now().map_err(CalendarError::Read)?;
        let seconds = Calendar {
            year: date.year(),
            month: date.month(),
            day: date.day(),
            hour: date.hour(),
            minute: date.minute(),
            second: date.second(),
        }
        .unix()
        .ok_or(CalendarError::InvalidDate)?;
        let at = seconds
            .as_millis()
            .checked_add(u64::from(
                date.microsecond()
                    .checked_div(1_000)
                    .ok_or(CalendarError::InvalidDate)?,
            ))
            .and_then(|at| at.checked_add(u64::from(fraction)))
            .and_then(UnixMillis::new);
        at.ok_or(CalendarError::InvalidDate)
    }

    pub fn pending(&self) -> Option<ClockChange> {
        self.journal.pending()
    }

    pub fn set(&mut self, change: ClockChange) -> Result<(), JournalError<CalendarError>> {
        let device = self
            .device
            .as_mut()
            .ok_or(JournalError::Calendar(CalendarError::UntrustedSource))?;
        self.journal.apply(device, change)
    }

    pub fn recorded(&mut self) -> Result<(), JournalError<CalendarError>> {
        let device = self
            .device
            .as_mut()
            .ok_or(JournalError::Calendar(CalendarError::UntrustedSource))?;
        self.journal.recorded(device)
    }
}

impl CalendarStore for Device {
    type Error = CalendarError;
    fn read_word(&self, index: usize) -> Option<u32> {
        if index >= CLOCK_BACKUP_WORDS {
            return None;
        }
        Some(stm32_metapac::TAMP.bkpr(index).read().bkp())
    }
    fn write_word(&mut self, index: usize, value: u32) {
        if index < CLOCK_BACKUP_WORDS {
            stm32_metapac::TAMP
                .bkpr(index)
                .write(|word| word.set_bkp(value));
        }
    }
    fn set_calendar(&mut self, at: UnixMillis) -> Result<(), CalendarError> {
        let calendar = Calendar::from_unix(at).ok_or(CalendarError::InvalidDate)?;
        let weekday = match calendar.weekday().ok_or(CalendarError::InvalidDate)? {
            1 => DayOfWeek::Monday,
            2 => DayOfWeek::Tuesday,
            3 => DayOfWeek::Wednesday,
            4 => DayOfWeek::Thursday,
            5 => DayOfWeek::Friday,
            6 => DayOfWeek::Saturday,
            7 => DayOfWeek::Sunday,
            _ => return Err(CalendarError::InvalidDate),
        };
        let date = DateTime::from(
            calendar.year,
            calendar.month,
            calendar.day,
            weekday,
            calendar.hour,
            calendar.minute,
            calendar.second,
            0,
        )
        .map_err(|_| CalendarError::InvalidDate)?;
        self.rtc.set_datetime(date).map_err(CalendarError::Write)
    }
}
