//! `FEEDBACK` from board B: how it is read, and what it means.
//!
//! Neither board carries a pull-up on the line (`B-09b`), so the controller
//! reads it through its own internal pull-up, and low means both relays are
//! closed. The pull and the meaning are declared here so the adapter that
//! configures the pin in M8 and the behaviour that reads the contact read
//! one contract, and a board that changes either changes it in one place.
//!
//! cites: F-013

/// What the controller pulls an input to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Pull {
    /// The part's internal pull-up.
    Up,
    /// Nothing: the board owns the level.
    None,
}

/// The generator's start contact, as `FEEDBACK` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Contact {
    /// Both relays are closed: the contact makes.
    Closed,
    /// At least one relay is open.
    Open,
}

/// The line's contract.
pub struct Feedback;

impl Feedback {
    /// The pull the adapter configures: the internal one, because no board
    /// provides one.
    pub const PULL: Pull = Pull::Up;

    /// What a level means: low is both relays closed.
    #[must_use]
    pub const fn contact(level_high: bool) -> Contact {
        if level_high {
            Contact::Open
        } else {
            Contact::Closed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f_013_feedback_is_read_through_the_internal_pull_up() {
        assert_eq!(Feedback::PULL, Pull::Up);
    }

    #[test]
    fn f_013_low_is_both_relays_closed_and_high_is_open() {
        assert_eq!(Feedback::contact(false), Contact::Closed);
        assert_eq!(Feedback::contact(true), Contact::Open);
    }
}
