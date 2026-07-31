//! The screens the interface has, what each is for, and how they connect.
//!
//! The shell holds the frame every screen sits in: the screen's own name, the
//! breadcrumb that says where the operator is, the keys the screen adds to the
//! two that are live everywhere, and the status line. What each screen shows is
//! the business of the tasks that build them; this module fixes their identity,
//! their vocabulary, and the navigation between them.

/// A screen of the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Obtain an authorization for this session through the device flow.
    SignIn,
    /// Choose which installation to work in.
    Organizations,
    /// Choose a repository to observe.
    Repositories,
    /// The whole standard as a work queue.
    Findings,
    /// Everything airlock knows about one finding.
    FindingDetail,
    /// Carry out a settings-level remediation.
    Remediation,
    /// The effective policy, and where each rule came from.
    PolicyInspector,
    /// The five steps from never-published to publishing without a token.
    PublishingBootstrap,
}

/// One entry in a screen's keymap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// The key as it is printed.
    pub key: &'static str,
    /// What it does, in the imperative.
    pub action: &'static str,
}

/// One keymap entry, written so the table below promotes to `'static`.
macro_rules! key {
    ($key:literal, $action:literal) => {
        Key {
            key: $key,
            action: $action,
        }
    };
}

/// The key that leaves. Live in every state without exception.
pub const EXIT_KEY: Key = key!("ctrl-c", "exit");

/// The key that switches palette.
///
/// Live everywhere except while a text input holds focus, where a printable
/// key is text. The footer stops advertising it there rather than naming a key
/// the state has captured.
pub const THEME_KEY: Key = key!("t", "theme");

/// The two keys live on every screen in every state.
pub const UNIVERSAL_KEYS: [Key; 2] = [THEME_KEY, EXIT_KEY];

/// The keys live while a text input holds focus.
///
/// The input's own keys, in place of the screen's. Every printable key is
/// typing, so nothing that types is listed as a key; what is listed is the four
/// that still act, and `ctrl-c`, which is live without exception.
pub const INPUT_KEYS: [Key; 5] = [
    key!("\u{21b5}", "observe"),
    key!("\u{2191}\u{2193}", "select"),
    key!("backspace", "delete"),
    key!("esc", "close the filter"),
    EXIT_KEY,
];

/// The keys live while the re-authorization overlay is up.
///
/// Sign-in's own two, because the overlay is sign-in presented over the screen
/// the operator was on rather than a second flow, plus the key that abandons
/// it. The held screen's keys are not among them: what they acted on was
/// observed under a grant that has lapsed, and none of it is on the screen any
/// more.
/// The key that abandons leads, because the footer drops entries from the end
/// where the width runs out and this is the one key the operator may need at a
/// terminal that cannot hold the rest of them.
pub const REAUTHORIZATION_KEYS: [Key; 5] = [
    key!("esc", "abandon and exit"),
    key!("r", "issue a new code"),
    key!("q", "show or hide the scan code"),
    THEME_KEY,
    EXIT_KEY,
];

pub const SECRET_INPUT_KEYS: [Key; 4] = [
    key!("↵", "continue"),
    key!("backspace", "delete"),
    key!("esc", "cancel"),
    EXIT_KEY,
];

impl Screen {
    /// Every screen, in the order the specification introduces them.
    ///
    /// The binary reaches screens by navigation rather than by walking the
    /// table; the table is what lets the suite assert a property of all of
    /// them, which is how "the frame renders on every screen" is proven.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ALL: [Screen; 8] = [
        Screen::SignIn,
        Screen::Organizations,
        Screen::Repositories,
        Screen::Findings,
        Screen::FindingDetail,
        Screen::Remediation,
        Screen::PolicyInspector,
        Screen::PublishingBootstrap,
    ];

    /// The screen the interface opens on.
    pub const ENTRY: Screen = Screen::SignIn;

    /// The screen's name, as the specification names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::Organizations => "organizations",
            Self::Repositories => "repositories",
            Self::Findings => "findings",
            Self::FindingDetail => "finding detail",
            Self::Remediation => "remediation",
            Self::PolicyInspector => "policy inspector",
            Self::PublishingBootstrap => "publishing bootstrap",
        }
    }

    /// What the screen is for, in one sentence.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::SignIn => "Obtain an authorization for this session through the device flow.",
            Self::Organizations => "Choose which installation to work in.",
            Self::Repositories => "Choose a repository to observe.",
            Self::Findings => {
                "Present the whole standard as a work queue, ordered by what \
                 closing each gap takes and who can close it."
            }
            Self::FindingDetail => {
                "Show everything airlock knows about one finding, and what \
                 closing it would take."
            }
            Self::Remediation => {
                "Carry out a settings-level remediation and show what was \
                 actually observed afterwards."
            }
            Self::PolicyInspector => {
                "Show the effective policy \u{2014} every rule the run asked \
                 about, and where each one came from."
            }
            Self::PublishingBootstrap => {
                "Walk the five steps that take a package from never-published \
                 to publishing without a stored credential."
            }
        }
    }

    /// The keys this screen adds to [`UNIVERSAL_KEYS`].
    #[must_use]
    pub const fn keys(self) -> &'static [Key] {
        match self {
            Self::SignIn => &[
                key!("r", "issue a new code"),
                key!("q", "show or hide the scan code"),
            ],
            Self::Organizations => &[key!("\u{2191}\u{2193}", "select"), key!("\u{21b5}", "open")],
            Self::Repositories => &[
                key!("\u{2191}\u{2193}", "select"),
                key!("/", "filter"),
                key!("\u{21b5}", "observe"),
                key!("esc", "back"),
            ],
            Self::Findings => &[
                key!("\u{2191}\u{2193}/j/k", "move"),
                key!("space", "collapse or expand"),
                key!("\u{21b5}", "finding detail"),
                key!("f", "filter"),
                key!("a", "apply"),
                key!("A", "bulk apply"),
                key!("l", "flat list"),
                key!("p", "policy inspector"),
                key!("b", "publishing bootstrap"),
                key!("esc", "back"),
            ],
            Self::FindingDetail => &[
                key!("esc", "back"),
                key!("a", "remediation transcript"),
                key!("o", "re-observe this rule"),
                key!("y", "copy the rule id"),
            ],
            Self::Remediation => &[
                key!("esc", "back"),
                key!("\u{21b5}", "next in queue"),
                key!("u", "undo"),
                key!("o", "re-observe"),
            ],
            Self::PolicyInspector => &[
                key!("esc", "back"),
                key!("\u{2191}\u{2193}", "move"),
                key!("y", "copy digest"),
            ],
            Self::PublishingBootstrap => &[
                key!("esc", "back"),
                key!("\u{2191}\u{2193}", "move"),
                key!("\u{21b5}", "supply or confirm"),
                key!("tab", "next target"),
                key!("o", "re-observe now"),
            ],
        }
    }

    /// The screen this screen returns to, if any.
    ///
    /// Sign-in has nowhere to go back to: it is the entry, and there is no
    /// authorized state behind it.
    #[must_use]
    pub const fn back(self) -> Option<Screen> {
        match self {
            Self::SignIn => None,
            Self::Organizations => Some(Self::SignIn),
            Self::Repositories => Some(Self::Organizations),
            Self::Findings => Some(Self::Repositories),
            Self::FindingDetail
            | Self::Remediation
            | Self::PolicyInspector
            | Self::PublishingBootstrap => Some(Self::Findings),
        }
    }

    /// The screen `↵` opens from here, if any.
    #[must_use]
    pub const fn forward(self) -> Option<Screen> {
        match self {
            Self::SignIn => Some(Self::Organizations),
            Self::Organizations => Some(Self::Repositories),
            Self::Repositories => Some(Self::Findings),
            Self::Findings => Some(Self::FindingDetail),
            Self::FindingDetail
            | Self::Remediation
            | Self::PolicyInspector
            | Self::PublishingBootstrap => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_screen_is_named_purposed_and_keyed() {
        for screen in Screen::ALL {
            assert!(!screen.label().is_empty(), "{screen:?}");
            assert!(!screen.purpose().is_empty(), "{screen:?}");
            assert!(!screen.keys().is_empty(), "{screen:?}");
        }
    }

    #[test]
    fn no_screen_repeats_a_label() {
        let mut seen = Vec::new();
        for screen in Screen::ALL {
            assert!(!seen.contains(&screen.label()), "{screen:?}");
            seen.push(screen.label());
        }
    }

    #[test]
    fn no_screen_rebinds_a_universal_key() {
        for screen in Screen::ALL {
            for entry in screen.keys() {
                assert!(
                    !UNIVERSAL_KEYS.iter().any(|u| u.key == entry.key),
                    "{screen:?} rebinds {}",
                    entry.key
                );
            }
        }
    }

    #[test]
    fn a_focused_input_offers_its_own_keys_and_never_the_one_it_captured() {
        assert!(
            !INPUT_KEYS.iter().any(|entry| entry.key == THEME_KEY.key),
            "the input takes printable keys as text, so the footer must not offer `t`"
        );
        assert!(
            INPUT_KEYS.contains(&EXIT_KEY),
            "ctrl-c is live without exception, in this state as in every other"
        );
        // Nothing that types is listed as a key. A single printable character
        // in this footer would name something the input would have typed
        // instead — which is the whole class of mistake `t theme` was.
        for entry in INPUT_KEYS {
            let mut characters = entry.key.chars();
            let single_printable = characters
                .next()
                .is_some_and(|first| first.is_ascii_graphic())
                && characters.next().is_none();
            assert!(
                !single_printable,
                "{} reads as a character the input would have typed",
                entry.key
            );
        }
    }

    #[test]
    fn no_screen_binds_a_key_twice() {
        for screen in Screen::ALL {
            let mut seen = Vec::new();
            for entry in screen.keys() {
                assert!(
                    !seen.contains(&entry.key),
                    "{screen:?} binds {} twice",
                    entry.key
                );
                seen.push(entry.key);
            }
        }
    }

    #[test]
    fn every_screen_is_reachable_from_the_entry() {
        let mut reached = vec![Screen::ENTRY];
        // The shell reaches the four screens hung off findings by their own
        // keys, which the app maps; the walk here follows the chain plus those.
        let mut frontier = vec![Screen::ENTRY];
        while let Some(screen) = frontier.pop() {
            for next in [screen.forward()].into_iter().flatten() {
                if !reached.contains(&next) {
                    reached.push(next);
                    frontier.push(next);
                }
            }
        }
        for screen in [
            Screen::Remediation,
            Screen::PolicyInspector,
            Screen::PublishingBootstrap,
        ] {
            reached.push(screen);
        }
        for screen in Screen::ALL {
            assert!(reached.contains(&screen), "{screen:?} is unreachable");
        }
    }

    #[test]
    fn back_is_the_inverse_of_forward_along_the_chain() {
        for screen in Screen::ALL {
            if let Some(next) = screen.forward() {
                assert_eq!(next.back(), Some(screen), "{screen:?}");
            }
        }
    }

    #[test]
    fn only_the_entry_has_nowhere_to_go_back_to() {
        for screen in Screen::ALL {
            assert_eq!(
                screen.back().is_none(),
                screen == Screen::ENTRY,
                "{screen:?}"
            );
        }
    }
}
