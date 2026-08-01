//! The app identity the write path accepts, bound at compile time.
//!
//! The read path binds acceptance to Airlock Safe by both numeric app id and
//! slug. The write path binds the same way, and to a constant rather than to a
//! setting: a flag, an environment variable, or a config entry that named the
//! app would hand anyone a way to point airlock at an app of their choosing,
//! which is the whole thing the binding prevents.
//!
//! Development needs a second identity — Airlock Test, installed only on one
//! account, so that half-written align code cannot reach a production
//! repository. That identity is selected by the `test-identity` cargo feature,
//! which is off by default. A shipped binary is built without it and therefore
//! contains no code, and no string, that could accept Airlock Test. The
//! guarantee is structural, in the same way that the absence of a mutating
//! subcommand is structural, rather than a check that might decline to fire.

/// A GitHub App the write path may be bound to.
///
/// Both halves of the trust root are carried. An id survives a rename and a
/// slug does not, so neither alone is sufficient and both are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteIdentity {
    /// The app's display name, for the screen.
    pub name: &'static str,
    /// The app's slug. The mutable half of the trust root.
    pub slug: &'static str,
    /// The app's numeric id. The immutable half.
    pub app_id: u64,
    /// The device flow's client id. Not a secret.
    pub client_id: &'static str,
    /// What the app registration grants, as GitHub names it.
    pub grant: &'static [Permission],
    /// Where the identity may be installed, stated so the screen can say it.
    pub installed_on: &'static str,
}

/// One entry in an app's declared grant.
///
/// The screen shows the grant by permission list and source, never by value,
/// so this is the whole of what a credential display ever holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    /// The permission as GitHub names it.
    pub name: &'static str,
    /// `read`, `write`, or `admin`.
    pub level: &'static str,
}

/// One permission, written so the tables below promote to `'static`.
macro_rules! permission {
    ($name:literal, $level:literal) => {
        Permission {
            name: $name,
            level: $level,
        }
    };
}

/// The grant both write-path identities are registered with.
///
/// Read from the app registrations rather than composed here: this is the
/// declared grant, and the screen prints it as the app's, not as airlock's
/// claim about the app's. `administration: write` is the one that makes the
/// grant write-capable, and GitHub does not subdivide it.
const WRITE_GRANT: &[Permission] = &[
    permission!("metadata", "read"),
    permission!("actions", "read"),
    permission!("administration", "write"),
    permission!("contents", "write"),
    permission!("environments", "write"),
    permission!("secrets", "write"),
    permission!("variables", "write"),
    permission!("organization_administration", "write"),
    permission!("organization_secrets", "write"),
    permission!("organization_custom_properties", "admin"),
];

/// Airlock Admin: the shipped write identity.
#[cfg(not(feature = "test-identity"))]
const BOUND: WriteIdentity = WriteIdentity {
    name: "Airlock Admin",
    slug: "airlock-admin",
    app_id: 4_409_767,
    client_id: "Iv23li6LeVszqbchI9Ah",
    grant: WRITE_GRANT,
    installed_on: "the accounts it has been installed on",
};

/// Airlock Test: the development identity, installed on one account only.
///
/// Its bound is the point of it. The organizations screen lists the reachable
/// installations, so under this identity a production account is not merely
/// inadvisable to select — it is not on the screen.
#[cfg(feature = "test-identity")]
const BOUND: WriteIdentity = WriteIdentity {
    name: "Airlock Test",
    slug: "airlock-test",
    app_id: 4_419_504,
    client_id: "Iv23liTl9KRNwxjFhrfA",
    grant: WRITE_GRANT,
    installed_on: "mmenm only",
};

/// The identity this build accepts.
///
/// There is one, it is a constant, and nothing at runtime can change it.
#[must_use]
pub const fn bound() -> WriteIdentity {
    BOUND
}

/// Whether this build is the shipped one.
///
/// Read by the assertions rather than by the interface: nothing the operator
/// sees branches on it, because a build that behaved differently in more than
/// its bound identity would be a different program.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use]
pub const fn is_shipped_build() -> bool {
    !cfg!(feature = "test-identity")
}

impl WriteIdentity {
    /// Whether an installation GitHub attested is this identity's.
    ///
    /// Both halves must match. A rename moves the slug and keeps the id; a
    /// released slug can be claimed by a different app and keeps neither.
    ///
    /// The screens that enumerate installations are the tasks after this one;
    /// the binding they will check against is here, with the constant it binds
    /// to, so the two cannot drift apart.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn attests(self, app_id: u64, app_slug: &str) -> bool {
        // A zero id is GitHub reporting nothing rather than reporting zero,
        // and the read path refuses it for the same reason.
        app_id != 0 && app_id == self.app_id && app_slug == self.slug
    }

    /// How the screen names where the credential came from.
    #[must_use]
    pub fn source(self) -> String {
        format!("GitHub App {} \u{b7} device flow", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_identity_is_the_one_this_build_profile_names() {
        let identity = bound();
        if is_shipped_build() {
            // Asserted as the exact expected constants rather than as "some id
            // is set": 4409767 and 4419504 differ only in the middle digits, and
            // a transposition would silently bind a test build to the production
            // identity, which is precisely what the test app exists to prevent.
            assert_eq!(identity.app_id, 4_409_767);
            assert_eq!(identity.slug, "airlock-admin");
            assert_eq!(identity.client_id, "Iv23li6LeVszqbchI9Ah");
        } else {
            assert_eq!(identity.app_id, 4_419_504);
            assert_eq!(identity.slug, "airlock-test");
            assert_eq!(identity.client_id, "Iv23liTl9KRNwxjFhrfA");
        }
    }

    #[test]
    fn acceptance_needs_both_halves_of_the_trust_root() {
        let identity = bound();
        assert!(identity.attests(identity.app_id, identity.slug));
        assert!(
            !identity.attests(identity.app_id, "something-else"),
            "a released slug can be claimed by a different app"
        );
        assert!(
            !identity.attests(identity.app_id + 1, identity.slug),
            "an id survives a rename and a slug does not"
        );
        assert!(!identity.attests(0, identity.slug), "zero is not an id");
    }

    #[test]
    fn the_shipped_build_carries_no_trace_of_the_test_identity() {
        // The complement of this — that the binary itself carries none of it —
        // is asserted against the built artifact in tests/write_identity.rs,
        // because a constant this module cannot see is the only proof that
        // matters.
        if is_shipped_build() {
            assert_ne!(bound().app_id, 4_419_504);
            assert_ne!(bound().slug, "airlock-test");
        }
    }

    #[test]
    fn the_grant_is_write_capable_and_says_which_permission_makes_it_so() {
        let grant = bound().grant;
        let administration = grant
            .iter()
            .find(|permission| permission.name == "administration")
            .expect("the grant carries repository administration");
        assert_eq!(administration.level, "write");
        assert!(
            grant.iter().any(|permission| permission.level == "read"),
            "a grant that is write everywhere would not be the registered one"
        );
    }

    #[test]
    fn no_permission_is_declared_twice() {
        let mut seen = Vec::new();
        for permission in bound().grant {
            assert!(!seen.contains(&permission.name), "{}", permission.name);
            seen.push(permission.name);
        }
    }

    #[test]
    fn the_source_names_the_app_and_the_flow_and_carries_no_value() {
        let source = bound().source();
        assert!(source.contains(bound().name), "{source}");
        assert!(source.contains("device flow"), "{source}");
        assert!(!source.contains(bound().client_id), "{source}");
    }
}
