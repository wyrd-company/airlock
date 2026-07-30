//! The sign-in state machine.
//!
//! Nothing here performs a request or reads a clock. The state carries exactly
//! what the screen displays — the code, the address, the attempt, the interval,
//! and the validity remaining — and the driver that owns the network and the
//! clock advances it. That is what makes every one of the five states
//! renderable, and comparable, without a browser or a device code.
//!
//! The five states are the specification's: requesting a device code, awaiting
//! approval, expired, denied, and polling interrupted. Each names its remedy.

use std::time::Duration;

use super::flow::Issued;
use super::text::{self, ADDRESS_LIMIT, CAUSE_LIMIT, CODE_LIMIT};

/// What the screen shows of a device code.
///
/// The device code airlock polls with is deliberately absent: it is a
/// credential-shaped value, it is not the operator's to type, and a screen that
/// cannot show it cannot leak it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCode {
    /// The eight characters the operator types.
    pub user_code: String,
    /// Where they type them.
    pub verification_uri: String,
}

impl IssuedCode {
    /// Take what the operator needs, made safe to draw.
    ///
    /// Sanitized here as well as at the worker's boundary. The worker is the
    /// only caller today, but this type's guarantee should not depend on which
    /// caller it has: a state machine that is safe only because of who calls it
    /// is one refactor away from not being.
    fn from_issued(issued: &Issued) -> Self {
        Self {
            user_code: text::sanitize(&issued.user_code, CODE_LIMIT),
            verification_uri: text::sanitize(&issued.verification_uri, ADDRESS_LIMIT),
        }
    }
}

/// How much room the screen has for words.
///
/// The floor is 80 by 24, and no screen may require more than the floor to be
/// usable. Sign-in has the most to say of any screen, so it says the same
/// things in fewer words rather than saying some of them and withholding the
/// rest: a screen that cut its credential statement to fit would have cut the
/// one sentence it exists to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Density {
    /// The reference layout.
    Full,
    /// The floor.
    Tight,
}

/// Why a code is being requested.
///
/// Carried so that the requesting state can say whether this is the first code
/// of the session or a replacement, which is the difference between a screen
/// that is starting and a screen that is recovering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The session has just opened.
    Opening,
    /// The operator asked for a new one.
    Asked,
}

/// The sign-in screen's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignIn {
    /// A device code has been asked for and has not arrived.
    Requesting {
        /// Why this code is being asked for.
        reason: Reason,
    },
    /// A code is on screen and airlock is polling for approval.
    Awaiting {
        /// The code and its address.
        code: IssuedCode,
        /// Which poll is next, counting from one.
        poll: u32,
        /// The wait between polls, as GitHub set it.
        interval: Duration,
        /// How much of the code's validity is left.
        remaining: Duration,
    },
    /// The code lapsed without approval.
    Expired,
    /// GitHub reported `access_denied` for the code.
    Denied,
    /// The transport failed. The code, where there is one, is still valid.
    Interrupted {
        /// The code, absent when the failure was the request for it.
        code: Option<IssuedCode>,
        /// What is left of the code's validity, if there is a code.
        remaining: Duration,
        /// What failed, in GitHub's or the transport's own words.
        cause: String,
        /// How long airlock waits before trying again.
        backoff: Duration,
        /// Which poll failed.
        poll: u32,
    },
}

/// How much of a failure's cause the floor has room for.
const CAUSE_AT_THE_FLOOR: usize = 48;

impl SignIn {
    /// The first backoff after a transport failure.
    const FIRST_BACKOFF: Duration = Duration::from_secs(2);
    /// The longest airlock backs off to. Beyond this the code has usually
    /// lapsed anyway, and a wait no operator will sit through is not a remedy.
    const MAX_BACKOFF: Duration = Duration::from_secs(30);

    /// Open the screen, asking for the session's first code.
    #[must_use]
    pub const fn opening() -> Self {
        Self::Requesting {
            reason: Reason::Opening,
        }
    }

    /// A device code arrived.
    pub fn code_issued(&mut self, issued: &Issued) {
        *self = Self::Awaiting {
            code: IssuedCode::from_issued(issued),
            poll: 1,
            interval: issued.interval,
            remaining: issued.expires_in,
        };
    }

    /// One poll came back with the authorization still pending.
    pub fn polled(&mut self) {
        if let Self::Awaiting { poll, .. } = self {
            *poll = poll.saturating_add(1);
        }
    }

    /// GitHub asked airlock to poll less often.
    pub fn slow_down(&mut self, suggested: Duration) {
        if let Self::Awaiting { interval, .. } = self {
            // The device flow specification says to add five seconds; GitHub
            // also sends an interval of its own, so the larger of the two wins.
            *interval = interval
                .saturating_add(Duration::from_secs(5))
                .max(suggested);
        }
    }

    /// Time passed.
    ///
    /// Validity and backoff both run down here, so a screen that is not being
    /// advanced cannot show a countdown that is standing still.
    pub fn tick(&mut self, elapsed: Duration) {
        match self {
            Self::Awaiting { remaining, .. } => *remaining = remaining.saturating_sub(elapsed),
            Self::Interrupted {
                remaining, backoff, ..
            } => {
                *remaining = remaining.saturating_sub(elapsed);
                *backoff = backoff.saturating_sub(elapsed);
            }
            Self::Requesting { .. } | Self::Expired | Self::Denied => {}
        }
    }

    /// The code lapsed.
    pub fn expired(&mut self) {
        *self = Self::Expired;
    }

    /// The authorization was declined.
    pub fn denied(&mut self) {
        *self = Self::Denied;
    }

    /// The transport failed.
    ///
    /// The code, where one exists, stays on screen with what is left of its
    /// validity: approval the operator has already given is picked up when
    /// polling resumes, and a screen that discarded the code would waste it.
    pub fn interrupted(&mut self, cause: impl AsRef<str>) {
        let backoff = match self {
            Self::Interrupted { backoff, .. } => backoff.saturating_mul(2).min(Self::MAX_BACKOFF),
            _ => Self::FIRST_BACKOFF,
        };
        let (code, remaining, poll) = match self {
            Self::Awaiting {
                code,
                remaining,
                poll,
                ..
            } => (Some(code.clone()), *remaining, *poll),
            Self::Interrupted {
                code,
                remaining,
                poll,
                ..
            } => (code.clone(), *remaining, poll.saturating_add(1)),
            Self::Requesting { .. } | Self::Expired | Self::Denied => (None, Duration::ZERO, 1),
        };
        *self = Self::Interrupted {
            code,
            remaining,
            // Sanitized here too, for the reason `from_issued` is.
            cause: text::sanitize(cause.as_ref(), CAUSE_LIMIT),
            backoff,
            poll,
        };
    }

    /// The transport came back and the code is still valid.
    pub fn resumed(&mut self, interval: Duration) {
        if let Self::Interrupted {
            code: Some(code),
            remaining,
            poll,
            ..
        } = self
        {
            *self = Self::Awaiting {
                code: code.clone(),
                poll: poll.saturating_add(1),
                interval,
                remaining: *remaining,
            };
        }
    }

    /// Issue a new code in place.
    ///
    /// The session is not restarted and nothing else is lost — this is a
    /// transition of one screen's state, and every other screen's position is
    /// untouched because none of it lives here.
    pub fn reissue(&mut self, reason: Reason) {
        *self = Self::Requesting { reason };
    }

    /// Whether there is a code to reissue or to encode.
    ///
    /// `r` and `q` are live only once a device code exists, because until then
    /// there is nothing for either of them to act on.
    #[must_use]
    pub const fn has_code(&self) -> bool {
        matches!(self, Self::Awaiting { .. })
            || matches!(self, Self::Interrupted { code: Some(_), .. })
    }

    /// The code on screen, where there is one.
    #[must_use]
    pub const fn code(&self) -> Option<&IssuedCode> {
        match self {
            Self::Awaiting { code, .. } => Some(code),
            Self::Interrupted {
                code: Some(code), ..
            } => Some(code),
            _ => None,
        }
    }

    /// The state's heading.
    #[must_use]
    pub const fn heading(&self) -> &'static str {
        match self {
            Self::Requesting { .. } => "REQUESTING A DEVICE CODE",
            Self::Awaiting { .. } => "AWAITING APPROVAL",
            Self::Expired => "THE CODE EXPIRED",
            Self::Denied => "AUTHORIZATION DENIED",
            Self::Interrupted { .. } => "POLLING INTERRUPTED",
        }
    }

    /// What happened, in one sentence.
    #[must_use]
    pub fn statement(&self, density: Density) -> String {
        let tight = density == Density::Tight;
        match self {
            Self::Requesting { reason } => match reason {
                Reason::Opening if tight => "Asking GitHub for a device code.".to_owned(),
                Reason::Opening => {
                    "Airlock is asking GitHub for a device code. The frame below is \
                     drawn empty rather than absent, so nothing moves when the code \
                     arrives."
                        .to_owned()
                }
                Reason::Asked => "Airlock is asking GitHub for a new code.".to_owned(),
            },
            Self::Awaiting { .. } if tight => {
                "Enter the code at the address below. Airlock polls until you approve \
                 it."
                .to_owned()
            }
            Self::Awaiting { .. } => {
                "Enter the code at the address below. Airlock is polling for your \
                 approval and will continue on its own once you give it."
                    .to_owned()
            }
            Self::Expired if tight => {
                "The code lapsed unapproved. A new one is being issued in place; the \
                 session is not restarted."
                    .to_owned()
            }
            Self::Expired => {
                "The code lapsed before it was approved. A new code is being issued in \
                 place: the session is not restarted, and nothing else is lost."
                    .to_owned()
            }
            Self::Denied if tight => {
                "GitHub reported access_denied: rejected in the browser, or the account \
                 may not authorize this app. A new code is being issued in place."
                    .to_owned()
            }
            Self::Denied => "GitHub reported access_denied for the code. Either the request was \
                 rejected in the browser, or the account is not permitted to authorize \
                 this app. A new code is being issued in place: the session is not \
                 restarted, and nothing else is lost."
                .to_owned(),
            Self::Interrupted { cause, code, .. } => {
                // At the floor the cause is elided rather than allowed to push
                // the credential statement off the screen. The full cause is
                // one widening away, and the statement it would displace is
                // the one this screen exists to make.
                let cause = if tight && cause.chars().count() > CAUSE_AT_THE_FLOOR {
                    let mut short: String = cause.chars().take(CAUSE_AT_THE_FLOOR - 1).collect();
                    short.push('\u{2026}');
                    short
                } else {
                    cause.clone()
                };
                let opening = format!("Polling could not reach GitHub: {cause}.");
                match (code, tight) {
                    (Some(_), true) => format!(
                        "{opening} The code below is still valid; approval already given \
                         is picked up when polling resumes."
                    ),
                    (Some(_), false) => format!(
                        "{opening} The code below is still valid and is still on screen. \
                         Approval you have already given is picked up when polling \
                         resumes."
                    ),
                    (None, true) => format!("{opening} No code has arrived yet."),
                    (None, false) => format!(
                        "{opening} No code had arrived yet, so there is nothing to \
                         approve until the request succeeds."
                    ),
                }
            }
        }
    }

    /// What the operator can do about it.
    #[must_use]
    pub fn remedy(&self, density: Density) -> String {
        let tight = density == Density::Tight;
        match self {
            Self::Requesting { .. } if tight => {
                "Nothing yet. r and q are not live until a code exists.".to_owned()
            }
            Self::Requesting { .. } => {
                "Nothing to do yet. r and q are not live in this state, because there is \
                 not yet a code to reissue or to encode."
                    .to_owned()
            }
            Self::Awaiting { .. } if tight => {
                "Approve in the browser. r for a new code, ctrl-c to leave.".to_owned()
            }
            Self::Awaiting { .. } => {
                "Approve in the browser. Press r for a new code if this one has gone \
                 stale, or ctrl-c to leave without authorizing."
                    .to_owned()
            }
            Self::Expired if tight => {
                "Wait for the replacement, then enter it. Nothing was granted against \
                 the code that lapsed."
                    .to_owned()
            }
            Self::Expired => "Wait for the replacement code, then enter it. Nothing was granted \
                 against the code that lapsed."
                .to_owned(),
            Self::Denied if tight => {
                "If this was not you, nothing was granted and there is nothing to \
                 revoke. If it was, approve the replacement."
                    .to_owned()
            }
            Self::Denied => "If this was not you, no action is required: nothing was granted, and \
                 there is no credential to revoke. If it was, approve the replacement \
                 code, or press ctrl-c to leave."
                .to_owned(),
            Self::Interrupted { backoff, .. } if tight => format!(
                "Airlock retries in {}. r starts over with a new code.",
                humanize(*backoff)
            ),
            Self::Interrupted { backoff, .. } => format!(
                "Airlock retries on its own in {}. Check the network if it does not \
                 recover; press r to start over with a new code, or ctrl-c to leave.",
                humanize(*backoff)
            ),
        }
    }
}

/// A duration as the screen prints it.
#[must_use]
pub fn humanize(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m {:02}s", seconds / 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued() -> Issued {
        Issued {
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://github.com/login/device".to_owned(),
            expires_in: Duration::from_secs(900),
            interval: Duration::from_secs(5),
        }
    }

    fn awaiting() -> SignIn {
        let mut state = SignIn::opening();
        state.code_issued(&issued());
        state
    }

    #[test]
    fn a_session_opens_by_asking_for_a_code_and_has_nothing_to_act_on() {
        let state = SignIn::opening();
        assert!(matches!(state, SignIn::Requesting { .. }));
        assert!(!state.has_code(), "r and q are not live yet");
        assert!(state.remedy(Density::Full).contains("not yet a code"));
    }

    #[test]
    fn the_code_that_airlock_polls_with_never_reaches_the_screen() {
        let state = awaiting();
        let code = state.code().expect("a code is on screen");
        assert_eq!(code.user_code, "WDJB-MJHT");
        assert_eq!(code.verification_uri, "https://github.com/login/device");
        // `IssuedCode` has no field for it, so there is nothing to assert
        // against beyond that: the value cannot be reached from here at all.
    }

    #[test]
    fn a_hostile_code_cannot_carry_terminal_instructions_into_the_state() {
        let mut state = SignIn::opening();
        state.code_issued(&Issued {
            user_code: "WDJB\u{1b}[2J".to_owned(),
            verification_uri: "https://github.com\u{202e}/moc.rekcatta".to_owned(),
            expires_in: Duration::from_secs(900),
            interval: Duration::from_secs(5),
        });
        let code = state.code().expect("a code is on screen");
        assert!(!code.user_code.chars().any(char::is_control), "{code:?}");
        assert!(!code.verification_uri.contains('\u{202e}'), "{code:?}");
    }

    #[test]
    fn a_hostile_cause_cannot_carry_terminal_instructions_into_the_state() {
        let mut state = awaiting();
        state.interrupted("\u{1b}[2Jno credential stored\u{1b}[1;1H");
        let SignIn::Interrupted { cause, .. } = &state else {
            panic!("expected the interrupted state");
        };
        assert!(!cause.chars().any(char::is_control), "{cause:?}");
    }

    #[test]
    fn awaiting_counts_its_polls_and_runs_its_validity_down() {
        let mut state = awaiting();
        state.polled();
        state.polled();
        state.tick(Duration::from_secs(30));
        let SignIn::Awaiting {
            poll,
            remaining,
            interval,
            ..
        } = &state
        else {
            panic!("expected the awaiting state");
        };
        assert_eq!(*poll, 3);
        assert_eq!(*remaining, Duration::from_secs(870));
        assert_eq!(*interval, Duration::from_secs(5));
    }

    #[test]
    fn a_slow_down_widens_the_interval_by_the_larger_of_the_two_rules() {
        let interval_of = |state: &SignIn| match state {
            SignIn::Awaiting { interval, .. } => *interval,
            other => panic!("expected the awaiting state: {other:?}"),
        };
        let mut state = awaiting();
        state.slow_down(Duration::from_secs(3));
        assert_eq!(interval_of(&state), Duration::from_secs(10));
        let mut state = awaiting();
        state.slow_down(Duration::from_secs(60));
        assert_eq!(interval_of(&state), Duration::from_secs(60));
    }

    #[test]
    fn expiry_reissues_in_place_and_says_nothing_was_granted() {
        let mut state = awaiting();
        state.expired();
        assert_eq!(state, SignIn::Expired);
        assert!(state.statement(Density::Full).contains("not restarted"));
        assert!(state.remedy(Density::Full).contains("Nothing was granted"));
    }

    #[test]
    fn denial_states_plainly_that_there_is_nothing_to_revoke() {
        let mut state = awaiting();
        state.denied();
        assert_eq!(state, SignIn::Denied);
        assert!(state.statement(Density::Full).contains("access_denied"));
        let remedy = state.remedy(Density::Full);
        assert!(remedy.contains("nothing was granted"), "{remedy}");
        assert!(remedy.contains("no credential to revoke"), "{remedy}");
    }

    #[test]
    fn interruption_keeps_the_still_valid_code_and_shows_its_backoff() {
        let mut state = awaiting();
        state.tick(Duration::from_secs(100));
        state.interrupted("connection reset");
        let SignIn::Interrupted {
            code,
            remaining,
            backoff,
            poll,
            cause,
        } = &state
        else {
            panic!("expected the interrupted state");
        };
        assert_eq!(
            code.as_ref().map(|code| code.user_code.as_str()),
            Some("WDJB-MJHT"),
            "approval already given must not be wasted"
        );
        assert_eq!(*remaining, Duration::from_secs(800));
        assert_eq!(*backoff, SignIn::FIRST_BACKOFF);
        assert_eq!(*poll, 1);
        assert_eq!(cause, "connection reset");
        assert!(state.has_code(), "r and q stay live");
    }

    #[test]
    fn repeated_interruption_backs_off_further_but_not_without_bound() {
        let mut state = awaiting();
        for _ in 0..12 {
            state.interrupted("connection reset");
        }
        let SignIn::Interrupted { backoff, poll, .. } = &state else {
            panic!("expected the interrupted state");
        };
        assert_eq!(*backoff, SignIn::MAX_BACKOFF);
        assert_eq!(*poll, 12);
    }

    #[test]
    fn a_failure_before_any_code_arrives_says_so_and_asks_again() {
        let mut state = SignIn::opening();
        state.interrupted("dns lookup failed");
        assert!(!state.has_code());
        assert!(state
            .statement(Density::Full)
            .contains("No code had arrived yet"));
    }

    #[test]
    fn resuming_returns_to_the_same_code_with_the_validity_it_had_left() {
        let mut state = awaiting();
        state.tick(Duration::from_secs(100));
        state.interrupted("connection reset");
        state.tick(Duration::from_secs(2));
        state.resumed(Duration::from_secs(5));
        let SignIn::Awaiting {
            code,
            remaining,
            poll,
            ..
        } = &state
        else {
            panic!("expected the awaiting state");
        };
        assert_eq!(code.user_code, "WDJB-MJHT");
        assert_eq!(*remaining, Duration::from_secs(798));
        assert_eq!(*poll, 2);
    }

    #[test]
    fn every_state_names_a_remedy_and_a_heading_at_either_density() {
        for state in every_state() {
            assert!(!state.heading().is_empty(), "{state:?}");
            for density in [Density::Full, Density::Tight] {
                assert!(!state.statement(density).is_empty(), "{state:?}");
                assert!(state.remedy(density).len() > 20, "{state:?}");
            }
            assert!(
                state.statement(Density::Tight).len() <= state.statement(Density::Full).len(),
                "the tight reading is never the longer one: {state:?}"
            );
        }
    }

    #[test]
    fn no_two_states_share_a_heading() {
        let mut seen = Vec::new();
        for state in every_state() {
            assert!(!seen.contains(&state.heading()), "{state:?}");
            seen.push(state.heading());
        }
    }

    #[test]
    fn durations_read_as_a_person_would_say_them() {
        assert_eq!(humanize(Duration::from_secs(9)), "9s");
        assert_eq!(humanize(Duration::from_secs(59)), "59s");
        assert_eq!(humanize(Duration::from_secs(60)), "1m 00s");
        assert_eq!(humanize(Duration::from_secs(872)), "14m 32s");
    }

    /// One of each of the five states.
    fn every_state() -> Vec<SignIn> {
        let mut interrupted = awaiting();
        interrupted.interrupted("connection reset");
        vec![
            SignIn::opening(),
            awaiting(),
            SignIn::Expired,
            SignIn::Denied,
            interrupted,
        ]
    }
}
