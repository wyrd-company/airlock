//! The write credential, and the only way one comes to exist.
//!
//! The credential has exactly one source: the device flow, approved by an
//! operator in a browser. There is no config file entry, no environment
//! variable, and no command-line flag, because the type below cannot be built
//! from any of them — its only constructor consumes a device grant. That is the
//! structural form of the prohibition, and it is why a test can assert the
//! absence of a path rather than the correctness of a check.
//!
//! The credential is held in memory for the session only. It is never written
//! anywhere, never placed in a child process environment, never displayed, and
//! its bytes are zeroized when it drops.

use zeroize::Zeroize as _;

use super::identity::{self, WriteIdentity};
use crate::device::TokenGrant;

/// What the interface may know about the session's grant.
///
/// A duration, or the statement that GitHub gave none. It is the drawable half
/// of a credential and carries nothing else: there is no field here a token
/// could travel in, which is why the countdown can be handed to the rendering
/// layer when the credential itself never is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// GitHub stated how long the grant is good for, and this is what is left.
    Until(std::time::Duration),
    /// GitHub stated no expiry, so there is no countdown to draw.
    ///
    /// Said rather than guessed at. An expiry airlock invented would be a
    /// re-authorization it demanded for no observed reason, and an expiry it
    /// assumed away would be a lapse the operator was not warned about.
    Unstated,
}

/// A write credential, alive for as long as the session and no longer.
///
/// It has no `Debug`, no `Display`, no `Serialize`, and no `Clone`. A value
/// that cannot be formatted cannot be logged by accident, and one that cannot
/// be cloned has exactly one owner to reason about.
pub struct SessionCredential {
    token: String,
    /// Kept beside the token so that the screens which will present the grant
    /// read it from the credential rather than from a constant they happen to
    /// import — a displayed grant must be the grant this credential has.
    #[cfg_attr(not(test), allow(dead_code))]
    identity: WriteIdentity,
    /// How long GitHub said this grant is good for, read from the grant it was
    /// built from. Held here for the same reason the identity is: what the
    /// interface counts down must be what this credential actually has.
    validity: Validity,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SessionCredential {
    /// Take ownership of a device grant.
    ///
    /// The grant arrives by value and leaves cleared: GitHub sends a refresh
    /// token alongside the access token when expiry is enabled, and a refresh
    /// token is the one thing here that could outlive the session if it were
    /// kept. Nothing keeps it, and it is zeroized on the way past rather than
    /// merely dropped.
    #[must_use]
    pub fn from_device_grant(mut grant: TokenGrant) -> Self {
        let validity = grant.expires_in.map_or(Validity::Unstated, |seconds| {
            Validity::Until(std::time::Duration::from_secs(seconds))
        });
        Self {
            token: strip(&mut grant),
            identity: identity::bound(),
            validity,
        }
    }

    /// How long this grant is good for, as GitHub stated it.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The identity this credential was issued by, as the build binds it.
    #[must_use]
    pub const fn identity(&self) -> WriteIdentity {
        self.identity
    }

    /// The token, for an authorization header and nothing else.
    ///
    /// Named to read wrongly at a call site that is not one of those: anything
    /// that persists, prints, or exports what this returns is a defect, and the
    /// name is there so a reviewer sees it.
    #[must_use]
    pub fn expose_for_authorization_header(&self) -> &str {
        &self.token
    }

    /// Whether the credential still holds anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.token.is_empty()
    }

    /// Overwrite the token's bytes and forget it.
    ///
    /// Separate from `Drop` so that zeroization is observable while the
    /// allocation is still owned. A test that read the buffer after the drop
    /// would be reading freed memory, and a proof that relies on undefined
    /// behaviour proves nothing.
    fn clear(&mut self) {
        self.token.zeroize();
    }
}

/// Take the access token out of a grant and clear everything else it carries.
///
/// Separate from the constructor so a test can hold the emptied grant and read
/// it, which is the only way to assert that nothing was left in it.
fn strip(grant: &mut TokenGrant) -> String {
    if let Some(refresh) = grant.refresh_token.as_mut() {
        refresh.zeroize();
    }
    grant.refresh_token = None;
    grant.refresh_token_expires_in = None;
    std::mem::take(&mut grant.access_token)
}

impl Drop for SessionCredential {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> TokenGrant {
        TokenGrant {
            access_token: "ghu_session_only".to_owned(),
            expires_in: Some(28_800),
            refresh_token: Some("ghr_would_outlive_the_session".to_owned()),
            refresh_token_expires_in: Some(15_897_600),
        }
    }

    #[test]
    fn a_credential_carries_the_identity_this_build_is_bound_to() {
        let credential = SessionCredential::from_device_grant(grant());
        assert_eq!(credential.identity(), identity::bound());
        assert_eq!(
            credential.expose_for_authorization_header(),
            "ghu_session_only"
        );
    }

    #[test]
    fn stripping_a_grant_leaves_nothing_in_it() {
        let mut supplied = grant();
        assert!(
            supplied.refresh_token.is_some(),
            "the fixture carries one to begin with"
        );

        let token = strip(&mut supplied);

        assert_eq!(token, "ghu_session_only");
        assert_eq!(
            supplied.refresh_token, None,
            "a refresh token is the one thing that could outlive the session"
        );
        assert_eq!(supplied.refresh_token_expires_in, None);
        assert!(supplied.access_token.is_empty());
    }

    #[test]
    fn a_credential_states_the_validity_the_grant_stated_and_never_invents_one() {
        let credential = SessionCredential::from_device_grant(grant());
        assert_eq!(
            credential.validity(),
            Validity::Until(std::time::Duration::from_secs(28_800))
        );

        // GitHub sends no expiry when token expiry is disabled for the app.
        // An interval airlock made up would be a re-authorization demanded for
        // no observed reason.
        let credential = SessionCredential::from_device_grant(TokenGrant {
            access_token: "ghu_session_only".to_owned(),
            expires_in: None,
            refresh_token: None,
            refresh_token_expires_in: None,
        });
        assert_eq!(credential.validity(), Validity::Unstated);
    }

    #[test]
    fn a_credential_never_carries_a_refresh_token() {
        let credential = SessionCredential::from_device_grant(grant());
        assert!(!credential
            .expose_for_authorization_header()
            .contains("ghr_"));
    }

    #[test]
    fn clearing_overwrites_the_token_rather_than_only_dropping_it() {
        let mut credential = SessionCredential::from_device_grant(grant());
        let address = credential.expose_for_authorization_header().as_ptr();
        let length = credential.expose_for_authorization_header().len();

        credential.clear();

        assert!(credential.is_empty());
        // SAFETY: the credential is still alive and still owns this allocation;
        // the bytes were written by the token and then overwritten by `clear`.
        let residue = unsafe { std::slice::from_raw_parts(address, length) };
        assert!(
            residue.iter().all(|byte| *byte == 0),
            "the token survived the clear that should have overwritten it"
        );
    }
}
