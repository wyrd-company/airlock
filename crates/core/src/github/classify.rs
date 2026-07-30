//! Classification of GitHub API failures.
//!
//! Classification happens once, here, so every check inherits the same
//! interpretation of a response. It reads stable signals first — status code,
//! rate limit headers, `Retry-After`, `X-Accepted-GitHub-Permissions`,
//! `documentation_url` — and only then consults a versioned table of message
//! hints. A message hint can promote an otherwise unknown failure into a known
//! class; it is never allowed to override a stable signal, because GitHub's
//! prose is not a contract.

use std::collections::BTreeMap;

/// The version of the message-hint table below.
///
/// Bump it whenever a hint is added, removed, or reworded. It travels in the
/// machine output so a surprising classification can be traced to the table
/// that produced it.
pub const MESSAGE_HINTS_VERSION: u32 = 1;

/// Why a request failed, in terms an audit can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorCause {
    /// The credential was rejected outright.
    Unauthenticated,
    /// The credential is valid but lacks the permission the endpoint needs.
    Permission,
    /// The account's plan does not include the feature.
    PlanLimitation,
    /// The rate limit was exhausted.
    RateLimit,
    /// The resource does not exist, or is not visible to this credential.
    NotFound,
    /// A 403 or 404 that matched no known class.
    UnknownAccess,
    /// The request could not be made or the response could not be read.
    Transport,
    /// The response was not the shape the endpoint documents.
    Malformed,
    /// A configured resource budget was reached before the answer was known.
    Budget,
}

impl ErrorCause {
    /// The stable machine-readable name of the cause.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            ErrorCause::Unauthenticated => "unauthenticated",
            ErrorCause::Permission => "permission",
            ErrorCause::PlanLimitation => "plan_limitation",
            ErrorCause::RateLimit => "rate_limit",
            ErrorCause::NotFound => "not_found",
            ErrorCause::UnknownAccess => "unknown_access",
            ErrorCause::Transport => "transport",
            ErrorCause::Malformed => "malformed_response",
            ErrorCause::Budget => "budget_exhausted",
        }
    }
}

/// The headers a classification decision may read, lower-cased.
///
/// Multi-valued: HTTP allows a field to repeat, and a security decision made
/// from whichever repetition happened to survive a map insert is not a
/// decision. Callers that need certainty use [`Response::single_header`],
/// which answers only when there is exactly one value.
pub type Headers = BTreeMap<String, Vec<String>>;

pub(crate) fn single_header<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    match headers.get(name)?.as_slice() {
        [only] => Some(only.as_str()),
        _ => None,
    }
}

pub(crate) fn all_headers<'a>(headers: &'a Headers, name: &str) -> &'a [String] {
    headers.get(name).map_or(&[], Vec::as_slice)
}

/// The parts of a failed response classification depends on.
#[derive(Debug, Clone, Default)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response headers, lower-cased names.
    pub headers: Headers,
    /// `message` from the JSON body, if the body had one.
    pub message: Option<String>,
    /// `documentation_url` from the JSON body, if the body had one.
    pub documentation_url: Option<String>,
}

impl Response {
    /// The value of a header that appeared exactly once.
    ///
    /// A repeated header answers `None`: "which one" has no safe default.
    #[must_use]
    pub fn single_header(&self, name: &str) -> Option<&str> {
        single_header(&self.headers, name)
    }

    /// Whether the header appeared at all, however many times.
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }
}

/// A message hint: a substring that GitHub has been observed to use, and the
/// class it suggests. Hints are matched case-insensitively.
struct MessageHint {
    needle: &'static str,
    cause: ErrorCause,
}

/// The versioned hint table. Ordered most specific first.
const MESSAGE_HINTS: &[MessageHint] = &[
    // Plan gates.
    MessageHint {
        needle: "upgrade to github pro",
        cause: ErrorCause::PlanLimitation,
    },
    MessageHint {
        needle: "make this repository public to enable this feature",
        cause: ErrorCause::PlanLimitation,
    },
    MessageHint {
        needle: "advanced security is not enabled",
        cause: ErrorCause::PlanLimitation,
    },
    MessageHint {
        needle: "not available for your plan",
        cause: ErrorCause::PlanLimitation,
    },
    // Permission gates.
    MessageHint {
        needle: "resource not accessible by integration",
        cause: ErrorCause::Permission,
    },
    MessageHint {
        needle: "resource not accessible by personal access token",
        cause: ErrorCause::Permission,
    },
    MessageHint {
        needle: "must have admin rights",
        cause: ErrorCause::Permission,
    },
    // Rate limiting, when the headers were stripped by a proxy.
    MessageHint {
        needle: "api rate limit exceeded",
        cause: ErrorCause::RateLimit,
    },
    MessageHint {
        needle: "secondary rate limit",
        cause: ErrorCause::RateLimit,
    },
];

/// Classify a failed response.
///
/// Only responses that are not success statuses reach this function.
#[must_use]
pub fn classify(response: &Response) -> ErrorCause {
    // 401 is unambiguous: the credential itself was rejected.
    if response.status == 401 {
        return ErrorCause::Unauthenticated;
    }

    // Rate limiting is decided from headers before anything else, because a
    // throttled response and a permission failure share a status code and a
    // retry on a permission failure is pure waste.
    if is_rate_limited(response) {
        return ErrorCause::RateLimit;
    }

    if response.status == 403 {
        // The strongest available signal: GitHub naming the permission the
        // endpoint wanted.
        if response.has_header("x-accepted-github-permissions") {
            return ErrorCause::Permission;
        }
        return match_hint(response).unwrap_or(ErrorCause::UnknownAccess);
    }

    if response.status == 404 {
        return match_hint(response).unwrap_or(ErrorCause::NotFound);
    }

    if response.status == 429 {
        return ErrorCause::RateLimit;
    }

    if (500..600).contains(&response.status) {
        return ErrorCause::Transport;
    }

    ErrorCause::UnknownAccess
}

fn is_rate_limited(response: &Response) -> bool {
    if response.status != 403 && response.status != 429 {
        return false;
    }
    if response.single_header("x-ratelimit-remaining") == Some("0") {
        return true;
    }
    if response.has_header("retry-after") {
        return true;
    }
    matches!(match_hint(response), Some(ErrorCause::RateLimit))
}

fn match_hint(response: &Response) -> Option<ErrorCause> {
    let message = response.message.as_ref()?.to_lowercase();
    MESSAGE_HINTS
        .iter()
        .find(|hint| message.contains(hint.needle))
        .map(|hint| hint.cause)
}

/// How long to wait before retrying, in seconds, if the response says.
#[must_use]
pub fn retry_delay_seconds(response: &Response, now_epoch_seconds: u64) -> Option<u64> {
    if let Some(after) = response
        .single_header("retry-after")
        .and_then(|v| v.parse().ok())
    {
        return Some(after);
    }
    let reset: u64 = response.single_header("x-ratelimit-reset")?.parse().ok()?;
    Some(reset.saturating_sub(now_epoch_seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: &[(&str, &str)], message: Option<&str>) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .fold(Headers::new(), |mut map, (name, value)| {
                    map.entry((*name).to_owned())
                        .or_default()
                        .push((*value).to_owned());
                    map
                }),
            message: message.map(ToOwned::to_owned),
            documentation_url: None,
        }
    }

    #[test]
    fn bad_credentials_are_unauthenticated() {
        let response = response(401, &[], Some("Bad credentials"));
        assert_eq!(classify(&response), ErrorCause::Unauthenticated);
    }

    #[test]
    fn exhausted_rate_limit_wins_over_a_permission_message() {
        // A throttled response can carry prose that looks like anything. The
        // header is the contract.
        let response = response(
            403,
            &[("x-ratelimit-remaining", "0")],
            Some("Resource not accessible by integration"),
        );
        assert_eq!(classify(&response), ErrorCause::RateLimit);
    }

    #[test]
    fn retry_after_marks_a_secondary_rate_limit() {
        let response = response(403, &[("retry-after", "60")], None);
        assert_eq!(classify(&response), ErrorCause::RateLimit);
        assert_eq!(retry_delay_seconds(&response, 0), Some(60));
    }

    #[test]
    fn accepted_permissions_header_marks_a_permission_failure() {
        let response = response(
            403,
            &[
                ("x-accepted-github-permissions", "administration=read"),
                ("x-ratelimit-remaining", "4999"),
            ],
            None,
        );
        assert_eq!(classify(&response), ErrorCause::Permission);
    }

    #[test]
    fn documented_permission_bodies_are_permission_failures() {
        for message in [
            "Resource not accessible by integration",
            "Resource not accessible by personal access token",
        ] {
            let response = response(403, &[("x-ratelimit-remaining", "4999")], Some(message));
            assert_eq!(classify(&response), ErrorCause::Permission, "{message}");
        }
    }

    #[test]
    fn plan_limitation_bodies_are_plan_limitations() {
        for message in [
            "Upgrade to GitHub Pro or make this repository public to enable this feature.",
            "Advanced Security is not enabled for this repository",
        ] {
            let response = response(403, &[("x-ratelimit-remaining", "4999")], Some(message));
            assert_eq!(classify(&response), ErrorCause::PlanLimitation, "{message}");
        }
    }

    #[test]
    fn an_unmatched_403_is_never_guessed_into_another_class() {
        let response = response(
            403,
            &[("x-ratelimit-remaining", "4999")],
            Some("Something entirely new from an org policy"),
        );
        assert_eq!(classify(&response), ErrorCause::UnknownAccess);
    }

    #[test]
    fn a_plain_404_is_not_found() {
        let response = response(404, &[], Some("Not Found"));
        assert_eq!(classify(&response), ErrorCause::NotFound);
    }

    #[test]
    fn rate_limit_reset_computes_a_delay() {
        let response = response(403, &[("x-ratelimit-reset", "1000")], None);
        assert_eq!(retry_delay_seconds(&response, 940), Some(60));
        assert_eq!(retry_delay_seconds(&response, 2000), Some(0));
    }

    #[test]
    fn a_repeated_header_is_not_read_as_a_single_value() {
        // Two rate-limit remainders cannot both be the answer, so neither is.
        let response = response(
            403,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-remaining", "9"),
            ],
            Some("Resource not accessible by integration"),
        );
        assert_eq!(classify(&response), ErrorCause::Permission);
        assert_eq!(response.single_header("x-ratelimit-remaining"), None);
        assert!(response.has_header("x-ratelimit-remaining"));
    }

    #[test]
    fn a_repeated_accepted_permissions_header_still_marks_a_permission_failure() {
        // Presence is what classifies here, not the value, so repetition is
        // not a reason to fall through to `unknown_access`.
        let response = response(
            403,
            &[
                ("x-accepted-github-permissions", "administration=read"),
                ("x-accepted-github-permissions", "contents=read"),
                ("x-ratelimit-remaining", "4999"),
            ],
            None,
        );
        assert_eq!(classify(&response), ErrorCause::Permission);
    }

    #[test]
    fn an_unprocessable_entity_is_never_reported_as_a_permission_failure() {
        // The trap: an organisation-secret endpoint answers 422 on a
        // user-owned repository, because there is no owning organisation for
        // the question to be about. That is the absence of an organisation,
        // not the absence of a grant, and a grant is what an operator would go
        // and widen if airlock said permission.
        let response = response(
            422,
            &[("x-ratelimit-remaining", "4999")],
            Some("Validation Failed"),
        );
        assert_ne!(classify(&response), ErrorCause::Permission);
        assert_eq!(classify(&response), ErrorCause::UnknownAccess);
    }

    #[test]
    fn server_errors_are_transport_failures() {
        assert_eq!(classify(&response(502, &[], None)), ErrorCause::Transport);
    }
}
