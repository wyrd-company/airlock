//! The pieces more than one screen draws: labelled fields, the credential
//! region, and the rule that decides how much prose a width can carry.
//!
//! The credential region is here rather than on one screen because two screens
//! show it and they must show the same thing. What it holds is the identity —
//! a compile-time constant — and never the credential: the grant is printed by
//! permission list and by source, and there is no value in scope to print.

use ratatui::text::{Line, Span};

use crate::admin::identity::WriteIdentity;
use crate::admin::sign_in::Density;

use super::chrome::wrap;
use super::theme::{Role, Styles};

/// The column a labelled field's value starts in.
pub const LABEL_WIDTH: usize = 14;

/// The width below which prose is written tightly.
///
/// The reference layout carries the full sentences and the floor does not. The
/// threshold is where the fuller readings stop fitting on one line each, and a
/// screen that wrapped them instead would spend rows it needs for its list.
pub const FULL_PROSE_NEEDS_WIDTH: usize = 100;

/// How much room there is for words.
#[must_use]
pub const fn density(width: usize) -> Density {
    if width < FULL_PROSE_NEEDS_WIDTH {
        Density::Tight
    } else {
        Density::Full
    }
}

/// A labelled field, wrapped under its value rather than under its label.
#[must_use]
pub fn field(styles: Styles, label: &str, text: &str, width: usize) -> Vec<Line<'static>> {
    let room = width.saturating_sub(LABEL_WIDTH).max(1);
    wrap(text, room)
        .into_iter()
        .enumerate()
        .map(|(index, part)| {
            let label = if index == 0 { label } else { "" };
            Line::from(vec![
                Span::styled(format!("{label:<LABEL_WIDTH$}"), styles.of(Role::Faint)),
                Span::styled(part, styles.of(Role::Dim)),
            ])
        })
        .collect()
}

/// The credential region: what the grant is and where it came from.
///
/// Never a value. The source names the app and the flow, the grant names every
/// permission the app registration declares, and the storage line states that
/// there is nothing to display and nowhere it is kept.
#[must_use]
pub fn credential(
    styles: Styles,
    identity: WriteIdentity,
    width: usize,
    density: Density,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "CREDENTIAL",
        styles.bold(Role::Text),
    ))];
    lines.extend(field(styles, "source", &identity.source(), width));
    lines.extend(field(styles, "grant", &grant(identity, density), width));
    lines.extend(field(
        styles,
        "storage",
        match density {
            Density::Full => {
                "none. No credential of any kind is stored: not in a file, not in \
                 the environment, not in a child process, and not after this \
                 session ends. Its value is never displayed."
            }
            Density::Tight => {
                "none. No credential of any kind is stored, anywhere, ever. Its \
                 value is never displayed."
            }
        },
        width,
    ));
    lines
}

/// The grant, by permission and level.
///
/// Every permission is named at both densities, because the grant is the
/// screen's answer to what this credential can do and a summary of it is not
/// that answer. What the tight reading drops is the repetition: the permissions
/// are gathered under their level instead of each carrying it.
#[must_use]
pub fn grant(identity: WriteIdentity, density: Density) -> String {
    if density == Density::Full {
        return identity
            .grant
            .iter()
            .map(|permission| format!("{} {}", permission.name, permission.level))
            .collect::<Vec<_>>()
            .join(" \u{b7} ");
    }
    let mut levels: Vec<(&str, Vec<&str>)> = Vec::new();
    for permission in identity.grant {
        match levels
            .iter_mut()
            .find(|(level, _)| *level == permission.level)
        {
            Some((_, names)) => names.push(permission.name),
            None => levels.push((permission.level, vec![permission.name])),
        }
    }
    levels
        .into_iter()
        .map(|(level, names)| format!("{level}: {}", names.join(", ")))
        .collect::<Vec<_>>()
        .join(" \u{b7} ")
}

/// The slice of a list to draw, and whether anything sits outside it.
///
/// A list longer than the rows it has is windowed rather than cut at the top:
/// the selected row is always in view, and the caller says how many rows are
/// outside the window so a short list is never read as the whole one.
#[must_use]
pub fn window(selected: usize, len: usize, room: usize) -> (usize, usize) {
    if room == 0 || len == 0 {
        return (0, 0);
    }
    if len <= room {
        return (0, len);
    }
    let half = room / 2;
    let start = selected.saturating_sub(half).min(len - room);
    (start, start + room)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::identity;
    use crate::tui::theme::{ColorMode, Theme};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn the_credential_region_names_every_permission_and_no_value() {
        for density in [Density::Full, Density::Tight] {
            let rendered = text(&credential(styles(), identity::bound(), 120, density));
            for permission in identity::bound().grant {
                assert!(rendered.contains(permission.name), "{}", permission.name);
            }
            assert!(rendered.contains("device flow"), "{rendered}");
            assert!(
                !rendered.contains(identity::bound().client_id),
                "{rendered}"
            );
            assert!(rendered.contains("never displayed"), "{rendered}");
        }
    }

    #[test]
    fn a_window_always_contains_the_selected_row() {
        for selected in 0..20 {
            let (start, end) = window(selected, 20, 5);
            assert!(start <= selected && selected < end, "{selected}");
            assert_eq!(end - start, 5);
        }
    }

    #[test]
    fn a_list_that_fits_is_never_windowed() {
        assert_eq!(window(0, 3, 10), (0, 3));
        assert_eq!(window(0, 0, 10), (0, 0));
        assert_eq!(window(0, 5, 0), (0, 0));
    }
}
