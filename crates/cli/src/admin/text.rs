//! Making a server's words safe to put on a terminal.
//!
//! Every string the sign-in screen draws that airlock did not write itself came
//! off the wire: the user code, the address, and the text of whatever GitHub or
//! the transport reported. A terminal is an interpreter, and a string carrying
//! `\u{1b}[2J` or `\u{1b}]0;…\u{7}` is a program for it — one that can clear the
//! screen, retitle the window, move the cursor over the statement that no
//! credential is stored, or reorder a line with bidirectional overrides so the
//! address reads as one host and resolves as another.
//!
//! So nothing server-supplied reaches a cell unexamined. This is the one place
//! that examines it, and it is applied where the data leaves the worker, so
//! there is no second path for it to arrive by.

/// What an unsafe character is replaced with.
///
/// Replaced rather than dropped: a character that vanished silently would let a
/// server compose a string that reads as one thing here and another in a log,
/// and the operator would have no sign that anything was removed.
const REPLACEMENT: char = '\u{fffd}';

/// The most a device code may be.
///
/// GitHub's is eight characters and a hyphen. The bound is generous and its
/// point is only that a code cannot become a paragraph.
pub const CODE_LIMIT: usize = 32;

/// The most an address may be.
pub const ADDRESS_LIMIT: usize = 200;

/// The most a reported cause may be.
pub const CAUSE_LIMIT: usize = 300;

/// Whether a character may be drawn.
///
/// The refused set is everything that is not text: the C0 controls including
/// escape, delete, the C1 range, and the Unicode format characters that reorder
/// or hide what surrounds them.
fn is_drawable(character: char) -> bool {
    if character.is_control() {
        return false;
    }
    !matches!(
        character,
        // Bidirectional marks, embeddings, overrides, and isolates.
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            // Zero-width joiners and the byte-order mark, which hide a
            // difference between two strings that look identical.
            | '\u{200b}'..='\u{200d}'
            | '\u{feff}'
            // Unassigned-plane and interlinear annotation controls.
            | '\u{fff9}'..='\u{fffb}'
    )
}

/// Make a server-supplied string safe to draw, and bound its length.
///
/// `char::is_control` covers the C0 range, delete, and C1, which is every byte
/// a terminal reads as an instruction rather than as text. Tabs and newlines are
/// included deliberately: this interface lays out its own lines, and a string
/// that could introduce one could push a row out of the column its meaning
/// depends on.
#[must_use]
pub fn sanitize(text: &str, limit: usize) -> String {
    let mut out = String::with_capacity(text.len().min(limit));
    for (index, character) in text.chars().enumerate() {
        if index == limit {
            out.push('\u{2026}');
            break;
        }
        out.push(if is_drawable(character) {
            character
        } else {
            REPLACEMENT
        });
    }
    out
}

/// Whether an address is at the origin airlock asked, and so is safe to encode.
///
/// The rule is not that the address looks like a link. It is that the server
/// does not get to choose where the scanner sends the operator. A scan code is
/// followed without being read — that is the whole of what it is for — so
/// encoding an address only because a response carried it would hand the
/// destination to whoever wrote the response. `https://attacker.example` is a
/// perfectly well-formed web address, and that is exactly why looking like one
/// is not the test.
///
/// So the address must sit at the origin airlock sent its own request to:
/// GitHub in a shipped run, and the validated loopback origin when the suite
/// has pointed the flow at its own server. Anything else is printed as the text
/// it is — which is what a suspicious operator needs to see — and never encoded.
///
/// The comparison is on origin rather than on the whole address. A path is
/// GitHub's to change and a host is not, and an attacker who can already choose
/// a path on `github.com` has not gained anything a scan code adds.
#[must_use]
pub fn is_at_origin(address: &str, expected_origin: &str) -> bool {
    if expected_origin.is_empty() {
        return false;
    }
    url::Url::parse(address).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            // `Origin::ascii_serialization` is scheme, host, and port, with the
            // host normalised, so `GitHub.com` and a default port compare equal
            // and `github.com.attacker.example` does not.
            && url.origin().ascii_serialization() == expected_origin
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub's origin, which is what a shipped run expects.
    const GITHUB: &str = "https://github.com";

    #[test]
    fn only_an_address_at_the_expected_origin_is_encodable() {
        for address in [
            "https://github.com/login/device",
            // A path GitHub may change, and a case and a default port the
            // parser normalises away.
            "https://github.com/login/device/other",
            "https://GitHub.com/login/device",
            "https://github.com:443/login/device",
        ] {
            assert!(is_at_origin(address, GITHUB), "{address}");
        }
    }

    #[test]
    fn a_host_the_server_chose_is_never_encodable() {
        // The finding: a well-formed web address is still a destination
        // somebody else picked, and a scan code is followed without being read.
        for refused in [
            "https://attacker.example",
            "https://attacker.example/login/device",
            // The near misses, which are the ones a reader would not catch.
            "https://github.com.attacker.example/login/device",
            "https://attacker.example/https://github.com/login/device",
            "https://github.com@attacker.example/login/device",
            "https://user:pass@attacker.example/login/device",
            "https://githubb.com/login/device",
            "https://raw.github.com/login/device",
            // The same host over a scheme airlock did not use.
            "http://github.com/login/device",
            // A port that is not the origin's.
            "https://github.com:8443/login/device",
            // Not a web address at all.
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>",
            "github.com/login/device",
            "not an address at all",
            "",
        ] {
            assert!(!is_at_origin(refused, GITHUB), "{refused}");
        }
    }

    #[test]
    fn the_loopback_origin_the_suite_uses_is_expected_on_its_own_terms() {
        // The test profile points the flow at its own server, and the address
        // that server hands back is then the expected one — but only that one.
        let loopback = "http://127.0.0.1:8080";
        assert!(is_at_origin("http://127.0.0.1:8080/login/device", loopback));
        assert!(!is_at_origin("https://github.com/login/device", loopback));
        assert!(!is_at_origin(
            "http://127.0.0.1:9090/login/device",
            loopback
        ));
        assert!(!is_at_origin("https://attacker.example", loopback));
    }

    #[test]
    fn an_expected_origin_that_could_not_be_read_encodes_nothing() {
        // Fail closed. An origin airlock cannot state is not one it can hold a
        // response to, and a scan code is the thing that would be followed
        // unread.
        assert!(!is_at_origin("https://github.com/login/device", ""));
        assert!(!is_at_origin("https://github.com/login/device", "null"));
    }

    #[test]
    fn ordinary_text_is_returned_as_it_stands() {
        assert_eq!(sanitize("WDJB-MJHT", CODE_LIMIT), "WDJB-MJHT");
        assert_eq!(
            sanitize("https://github.com/login/device", ADDRESS_LIMIT),
            "https://github.com/login/device"
        );
        assert_eq!(
            sanitize("connection reset by peer", CAUSE_LIMIT),
            "connection reset by peer"
        );
    }

    #[test]
    fn an_escape_sequence_cannot_survive_as_one() {
        // The three shapes that matter: a cursor move, a screen clear, and an
        // operating-system command that retitles the window.
        for hostile in [
            "\u{1b}[2J\u{1b}[H",
            "\u{1b}]0;pwned\u{7}",
            "code\u{1b}[1;1Hno credential stored",
        ] {
            let safe = sanitize(hostile, CAUSE_LIMIT);
            assert!(!safe.contains('\u{1b}'), "an escape survived: {safe:?}");
            assert!(!safe.chars().any(char::is_control), "{safe:?}");
        }
    }

    #[test]
    fn a_newline_or_a_carriage_return_cannot_move_a_row() {
        let safe = sanitize("WDJB\r\n\tMJHT", CODE_LIMIT);
        assert!(!safe.chars().any(char::is_control), "{safe:?}");
        assert_eq!(safe.chars().count(), "WDJB\r\n\tMJHT".chars().count());
    }

    #[test]
    fn a_bidirectional_override_cannot_reorder_an_address() {
        // The attack this refuses: an address that reads as github.com and
        // resolves as something else, because an override reversed the run
        // between them.
        let safe = sanitize(
            "https://github.com\u{202e}/moc.rekcatta//:sptth\u{202c}",
            ADDRESS_LIMIT,
        );
        assert!(!safe.contains('\u{202e}'), "{safe:?}");
        assert!(!safe.contains('\u{202c}'), "{safe:?}");
        assert!(
            safe.contains(REPLACEMENT),
            "the removal is visible: {safe:?}"
        );
    }

    #[test]
    fn a_zero_width_character_cannot_hide_inside_a_code() {
        let safe = sanitize("WDJB\u{200b}-MJHT", CODE_LIMIT);
        assert!(!safe.contains('\u{200b}'), "{safe:?}");
    }

    #[test]
    fn an_overlong_value_is_cut_and_says_so() {
        let safe = sanitize(&"x".repeat(500), CODE_LIMIT);
        assert_eq!(safe.chars().count(), CODE_LIMIT + 1);
        assert!(safe.ends_with('\u{2026}'), "{safe:?}");
    }

    #[test]
    fn a_value_of_exactly_the_limit_is_untouched() {
        let exact = "x".repeat(CODE_LIMIT);
        assert_eq!(sanitize(&exact, CODE_LIMIT), exact);
    }

    #[test]
    fn nothing_drawable_is_refused() {
        // Text airlock has no opinion about, including scripts it does not
        // read, passes through: this refuses instructions, not languages.
        for ordinary in ["Ünicode", "日本語", "emoji \u{1f600}", "a b\u{a0}c"] {
            assert_eq!(sanitize(ordinary, CAUSE_LIMIT), ordinary);
        }
    }
}
