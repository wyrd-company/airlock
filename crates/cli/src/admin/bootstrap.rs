//! What the publishing bootstrap observes, and what those observations imply.
//!
//! The ceremony exists because most registries will not accept a trusted
//! publisher for a package that has never been published. A token is minted to
//! produce one release, and that token is the thing the policy is trying to
//! eliminate.
//!
//! Nothing here is a saved position. Every state this module reports is derived
//! from facts observed at the moment it is asked: whether the repository holds
//! the bootstrap secret, whether the package exists on the registry, and — where
//! the registry exposes it at all — whether publishing is already restricted to
//! a trusted publisher. Closing the terminal loses nothing because there is
//! nothing to lose.
//!
//! The module is value-free. It names credentials and never carries one: a
//! [`Credential`] is a name, a scope, and a creation time, and no type here has
//! a field a token could travel in.

use std::collections::BTreeSet;

use crate::admin::text::{self, NAME_LIMIT};

/// Where a released artifact goes, and what its first publication takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    Npm,
    PyPi,
    CratesIo,
    PubDev,
    Ghcr,
}

/// The shape of a registry's first publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// Mint, set, publish, configure, revoke. The five steps.
    Token,
    /// A publisher configured before the package exists, which creates it on
    /// first upload. There is no bootstrap credential to mint or revoke.
    PendingPublisher,
    /// A package published private, then linked to the repository and made
    /// public. No credential, and the last step is irreversible.
    Container,
}

impl Registry {
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ALL: [Self; 5] = [
        Self::Npm,
        Self::PyPi,
        Self::CratesIo,
        Self::PubDev,
        Self::Ghcr,
    ];

    /// The registry's own name, as it writes it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPi => "PyPI",
            Self::CratesIo => "crates.io",
            Self::PubDev => "pub.dev",
            Self::Ghcr => "GHCR",
        }
    }

    /// What the first publication takes on this registry.
    #[must_use]
    pub const fn ceremony(self) -> Ceremony {
        match self {
            Self::Npm | Self::CratesIo | Self::PubDev => Ceremony::Token,
            Self::PyPi => Ceremony::PendingPublisher,
            Self::Ghcr => Ceremony::Container,
        }
    }

    /// The repository secret the ceremony's token is set as.
    ///
    /// The conventional name each ecosystem's publish step reads, so the
    /// presence of the credential is a fact airlock can look up rather than one
    /// the operator has to tell it.
    #[must_use]
    pub const fn bootstrap_secret(self) -> Option<&'static str> {
        match self {
            Self::Npm => Some("NPM_TOKEN"),
            Self::CratesIo => Some("CARGO_REGISTRY_TOKEN"),
            Self::PubDev => Some("PUB_TOKEN"),
            Self::PyPi | Self::Ghcr => None,
        }
    }

    /// Why the ceremony is skipped, where it is.
    #[must_use]
    pub const fn skipped_because(self) -> Option<&'static str> {
        match self {
            Self::PyPi => Some(
                "PyPI configures a pending publisher against the account before the \
                 project exists, and the first upload creates the project. No token \
                 is minted, set, or revoked, so there is nothing here to bootstrap.",
            ),
            _ => None,
        }
    }

    /// Whether airlock can read this registry's publisher configuration, and
    /// what it can read instead where it cannot.
    #[must_use]
    pub const fn configuration_reading(self) -> &'static str {
        match self {
            Self::Npm => {
                "npm's trusted-publisher configuration is readable only by a package \
                 maintainer holding an OTP, which airlock does not have. This step's \
                 completion is not observable from here."
            }
            Self::CratesIo => {
                "crates.io gates the configuration read on crate ownership, which \
                 airlock does not have. The public `trustpub_only` bit is read \
                 instead: when true the crate refuses any publish that did not come \
                 through trusted publishing."
            }
            Self::PubDev => {
                "pub.dev exposes no endpoint that reads automated-publishing \
                 configuration, for anyone. This step's completion is not observable \
                 from here or from anywhere."
            }
            Self::PyPi => {
                "PyPI exposes no configuration read, but publishes PEP 740 \
                 attestations that name the repository and workflow that published \
                 each file."
            }
            Self::Ghcr => {
                "GHCR reports a package's visibility and linked repository by name \
                 under the credential this session already holds."
            }
        }
    }

    /// How long a bootstrap token should be minted for, and why.
    ///
    /// The trade-off runs in both directions and neither end is safe: a long
    /// expiry leaves a live credential in a repository somebody forgot to clean
    /// up, and a short one dies before the first release runs and stalls the
    /// ceremony at its external step. Seven days is comfortably longer than the
    /// minutes-to-hours a first release takes while still expiring on its own if
    /// the ceremony is abandoned.
    pub const SUGGESTED_EXPIRY: &'static str =
        "seven days — long enough that the first release cannot outlive it, short \
         enough that an abandoned ceremony expires on its own";
}

/// One thing this repository publishes, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The package name on the registry, taken from the declared release unit.
    pub package: String,
    pub registry: Registry,
}

/// An outstanding bootstrap credential, by name and never by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub name: String,
    /// What the credential reaches, read from the endpoint it was observed on.
    pub scope: String,
    /// When GitHub says it was created.
    pub created: String,
}

/// Whether the package exists on the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    Published { latest: String },
    Absent,
    Undecided { reason: String },
}

/// Whether publishing is restricted to a trusted publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publisher {
    /// A public, credential-free signal says publishing is restricted.
    Restricted,
    /// The registry does not expose the fact to airlock's credential.
    Unobservable { reason: String },
}

/// The container path's state, which is a visibility and a link rather than a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Container {
    Present {
        visibility: String,
        repository: Option<String>,
    },
    Absent,
    Undecided {
        reason: String,
    },
}

/// Everything one bootstrap target was observed to be, at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub unit: Unit,
    /// The bootstrap secret, where the repository holds one.
    pub credential: Option<Credential>,
    pub publication: Publication,
    pub publisher: Publisher,
    /// Present only on the container path.
    pub container: Option<Container>,
}

/// One of the five steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Mint,
    SetSecret,
    AwaitRelease,
    ConfigurePublisher,
    Revoke,
}

impl Step {
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ALL: [Self; 5] = [
        Self::Mint,
        Self::SetSecret,
        Self::AwaitRelease,
        Self::ConfigurePublisher,
        Self::Revoke,
    ];

    #[must_use]
    pub const fn number(self) -> usize {
        match self {
            Self::Mint => 1,
            Self::SetSecret => 2,
            Self::AwaitRelease => 3,
            Self::ConfigurePublisher => 4,
            Self::Revoke => 5,
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Mint => "Mint a registry token",
            Self::SetSecret => "Set it as a repository secret",
            Self::AwaitRelease => "Wait for a release to run and publish",
            Self::ConfigurePublisher => "Configure the trusted publisher",
            Self::Revoke => "Revoke the token and delete the secret",
        }
    }
}

/// The container path's three steps, which are not the five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStep {
    Publish,
    Link,
    MakePublic,
}

impl ContainerStep {
    pub const ALL: [Self; 3] = [Self::Publish, Self::Link, Self::MakePublic];

    #[must_use]
    pub const fn number(self) -> usize {
        match self {
            Self::Publish => 1,
            Self::Link => 2,
            Self::MakePublic => 3,
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Publish => "Publish the package",
            Self::Link => "Link it to this repository",
            Self::MakePublic => "Make it public",
        }
    }

    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Publish => {
                "A newly published package is private. Push it carrying \
                 `org.opencontainers.image.source` and the next two steps collapse \
                 into this one, because a package linked before publication \
                 inherits the repository's access."
            }
            Self::Link => {
                "Connecting a repository afterwards is a settings page, not an \
                 endpoint, and access is not granted retroactively."
            }
            Self::MakePublic => {
                "Visibility has no REST mutation and a public package cannot be \
                 made private again. Airlock reads the state and stops here."
            }
        }
    }
}

/// What a step's state is, once observation has decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepState {
    /// Observed to have happened.
    Done { because: String },
    /// The step to act on now.
    Live { waiting_on: String },
    /// An earlier step has not happened yet.
    Blocked { by: String },
    /// The step's completion is not a fact airlock can observe, so it is
    /// neither claimed nor denied.
    Unobservable { reason: String },
}

impl StepState {
    /// The glyph, which carries the state without colour.
    #[must_use]
    pub const fn glyph(&self) -> &'static str {
        match self {
            Self::Done { .. } => "\u{2713}",
            Self::Live { .. } => "\u{25b6}",
            Self::Blocked { .. } => "\u{00b7}",
            Self::Unobservable { .. } => "\u{25d1}",
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Done { .. } => "done",
            Self::Live { .. } => "live",
            Self::Blocked { .. } => "blocked",
            Self::Unobservable { .. } => "unobservable",
        }
    }

    #[must_use]
    pub fn note(&self) -> &str {
        match self {
            Self::Done { because: text }
            | Self::Live { waiting_on: text }
            | Self::Blocked { by: text }
            | Self::Unobservable { reason: text } => text,
        }
    }

    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }
}

/// Where the observation places the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The five steps, each with the state observation gives it.
    Ceremony(Vec<(Step, StepState)>),
    /// The container path's three.
    Container(Vec<(ContainerStep, StepState)>),
    /// This registry configures a publisher before publication, so there is no
    /// ceremony to be placed in.
    Unnecessary { reason: &'static str },
}

impl Placement {
    /// The step to act on, where there is one.
    #[must_use]
    pub fn live_step(&self) -> Option<usize> {
        match self {
            Self::Ceremony(steps) => steps
                .iter()
                .find(|(_, state)| state.is_live())
                .map(|(step, _)| step.number()),
            Self::Container(steps) => steps
                .iter()
                .find(|(_, state)| state.is_live())
                .map(|(step, _)| step.number()),
            Self::Unnecessary { .. } => None,
        }
    }

    /// What the live step is waiting on, where there is one.
    #[must_use]
    pub fn waiting_on(&self) -> Option<&str> {
        match self {
            Self::Ceremony(steps) => steps
                .iter()
                .find(|(_, state)| state.is_live())
                .map(|(_, state)| state.note()),
            Self::Container(steps) => steps
                .iter()
                .find(|(_, state)| state.is_live())
                .map(|(_, state)| state.note()),
            Self::Unnecessary { .. } => None,
        }
    }

    /// How many steps this path has.
    #[must_use]
    pub fn extent(&self) -> usize {
        match self {
            Self::Ceremony(steps) => steps.len(),
            Self::Container(steps) => steps.len(),
            Self::Unnecessary { .. } => 0,
        }
    }
}

/// Place the operator from what was observed, and from nothing else.
#[must_use]
pub fn place(observation: &Observation) -> Placement {
    match observation.unit.registry.ceremony() {
        Ceremony::PendingPublisher => Placement::Unnecessary {
            reason: observation
                .unit
                .registry
                .skipped_because()
                .unwrap_or("this registry accepts a publisher before publication"),
        },
        Ceremony::Container => Placement::Container(container_steps(observation)),
        Ceremony::Token => Placement::Ceremony(ceremony_steps(observation)),
    }
}

fn ceremony_steps(observation: &Observation) -> Vec<(Step, StepState)> {
    let held = observation.credential.is_some();
    let published = matches!(observation.publication, Publication::Published { .. });
    let undecided = match &observation.publication {
        Publication::Undecided { reason } => Some(reason.clone()),
        _ => None,
    };
    let restricted = observation.publisher == Publisher::Restricted;
    let secret = observation
        .unit
        .registry
        .bootstrap_secret()
        .unwrap_or("the bootstrap secret");

    let mint = if !held && published {
        StepState::Done {
            because: "the package is published and no bootstrap secret remains, so \
                 nothing here needs minting"
                .to_owned(),
        }
    } else if held {
        StepState::Unobservable {
            reason: format!(
                "the repository holds `{secret}`, so a token was minted; the token \
                 itself is the registry's and airlock never sees it. Its expiry is \
                 not observable either, and airlock does not guess one."
            ),
        }
    } else {
        StepState::Live {
            waiting_on: format!(
                "mint a token on {} scoped to publishing `{}`. Expiry: {}.",
                observation.unit.registry.label(),
                observation.unit.package,
                Registry::SUGGESTED_EXPIRY
            ),
        }
    };

    let set_secret = if held {
        StepState::Done {
            because: format!("`{secret}` was re-observed on the repository just now"),
        }
    } else if published {
        StepState::Done {
            because: format!(
                "no `{secret}` is on the repository and the package is published, so \
                 there is nothing left to set"
            ),
        }
    } else {
        StepState::Live {
            waiting_on: format!(
                "supply the token's value; airlock writes it to `{secret}` after you \
                 confirm that named write"
            ),
        }
    };

    let await_release = match (&undecided, published, held) {
        (Some(reason), _, _) => StepState::Unobservable {
            reason: format!(
                "the registry read did not establish whether the package exists: {reason}"
            ),
        },
        (None, true, _) => StepState::Done {
            because: format!(
                "`{}` is on {}",
                observation.unit.package,
                observation.unit.registry.label()
            ),
        },
        (None, false, true) => StepState::Live {
            waiting_on: "a release workflow run publishing the package. This is an \
                 external event that may take hours; leaving is expected, because \
                 nothing here is a saved position."
                .to_owned(),
        },
        (None, false, false) => StepState::Blocked {
            by: "step 2 — the release has no credential to publish with yet".to_owned(),
        },
    };

    let configure = if restricted {
        StepState::Done {
            because: "the registry publicly reports that this package refuses any \
                 publish that did not come through trusted publishing"
                .to_owned(),
        }
    } else if published && held {
        StepState::Live {
            waiting_on: format!(
                "configure the trusted publisher for `{}` on {}. {}",
                observation.unit.package,
                observation.unit.registry.label(),
                observation.unit.registry.configuration_reading()
            ),
        }
    } else if published {
        StepState::Unobservable {
            reason: format!(
                "no bootstrap credential is outstanding, so nothing here is waiting \
                 on you. Whether a trusted publisher is configured is a separate \
                 fact, and not one airlock can read: {}",
                observation.unit.registry.configuration_reading()
            ),
        }
    } else {
        StepState::Blocked {
            by: "step 3 — a publisher cannot be attached to a package that does not \
                 exist"
                .to_owned(),
        }
    };

    let revoke = if !held && published {
        StepState::Done {
            because: format!(
                "no `{secret}` is on the repository, so the credential this ceremony \
                 created no longer exists"
            ),
        }
    } else if published {
        StepState::Live {
            waiting_on: format!(
                "revoke the token on {} and delete `{secret}`. The bootstrap is not \
                 conformant while it exists.",
                observation.unit.registry.label()
            ),
        }
    } else {
        StepState::Blocked {
            by: "step 4 — revoking before a publisher is configured leaves nothing \
                 able to publish"
                .to_owned(),
        }
    };

    vec![
        (Step::Mint, mint),
        (Step::SetSecret, set_secret),
        (Step::AwaitRelease, await_release),
        (Step::ConfigurePublisher, configure),
        (Step::Revoke, revoke),
    ]
}

fn container_steps(observation: &Observation) -> Vec<(ContainerStep, StepState)> {
    let container = observation
        .container
        .clone()
        .unwrap_or(Container::Undecided {
            reason: "the package was not read".to_owned(),
        });
    match container {
        Container::Undecided { reason } => ContainerStep::ALL
            .into_iter()
            .map(|step| {
                (
                    step,
                    StepState::Unobservable {
                        reason: format!("the package read did not establish its state: {reason}"),
                    },
                )
            })
            .collect(),
        Container::Absent => vec![
            (
                ContainerStep::Publish,
                StepState::Live {
                    waiting_on: format!(
                        "push `{}` to GHCR. {}",
                        observation.unit.package,
                        ContainerStep::Publish.note()
                    ),
                },
            ),
            (
                ContainerStep::Link,
                StepState::Blocked {
                    by: "step 1 — there is no package to link yet".to_owned(),
                },
            ),
            (
                ContainerStep::MakePublic,
                StepState::Blocked {
                    by: "step 1 — there is no package to publish yet".to_owned(),
                },
            ),
        ],
        Container::Present {
            visibility,
            repository,
        } => {
            let public = visibility == "public";
            vec![
                (
                    ContainerStep::Publish,
                    StepState::Done {
                        because: format!("the package exists and is {visibility}"),
                    },
                ),
                (
                    ContainerStep::Link,
                    match &repository {
                        Some(name) => StepState::Done {
                            because: format!("the package reports `{name}` as its repository"),
                        },
                        None => StepState::Live {
                            waiting_on: format!(
                                "connect the package to this repository. {}",
                                ContainerStep::Link.note()
                            ),
                        },
                    },
                ),
                (
                    ContainerStep::MakePublic,
                    if public {
                        StepState::Done {
                            because: "the package is public".to_owned(),
                        }
                    } else if repository.is_some() {
                        StepState::Live {
                            waiting_on: format!(
                                "make the package public. {}",
                                ContainerStep::MakePublic.note()
                            ),
                        }
                    } else {
                        StepState::Blocked {
                            by: "step 2 — a package made public before it is linked \
                                 never inherits the repository's access"
                                .to_owned(),
                        }
                    },
                ),
            ]
        }
    }
}

/// What the repository declares it publishes, read from the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declaration {
    /// The release units the repository declares, as id and path.
    pub units: Vec<(String, String)>,
    /// Every path the snapshot established is a file.
    pub files: BTreeSet<String>,
}

/// Derive the bootstrap targets from what the repository declares.
///
/// The package name is the declared release-unit id, and the registry is the
/// manifest observed at that unit's path. Both are facts read from the
/// repository rather than settings the operator types, which is what lets the
/// screen resume from observation alone.
#[must_use]
pub fn units(declaration: &Declaration) -> Vec<Unit> {
    let mut units = Vec::new();
    for (id, path) in &declaration.units {
        let at = |file: &str| {
            let candidate = if path.is_empty() || path == "." {
                file.to_owned()
            } else {
                format!("{path}/{file}")
            };
            declaration.files.contains(&candidate)
        };
        let package = text::sanitize(id, NAME_LIMIT);
        for (manifest, registry) in [
            ("package.json", Registry::Npm),
            ("pyproject.toml", Registry::PyPi),
            ("Cargo.toml", Registry::CratesIo),
            ("pubspec.yaml", Registry::PubDev),
            ("Dockerfile", Registry::Ghcr),
        ] {
            if at(manifest) {
                units.push(Unit {
                    package: package.clone(),
                    registry,
                });
            }
        }
    }
    units
}

/// The path a registry answers a package read on.
fn package_path(unit: &Unit) -> Option<(String, String)> {
    let package = urlencoding(&unit.package);
    match unit.registry {
        Registry::Npm => Some((
            "https://registry.npmjs.org".to_owned(),
            format!("/{package}"),
        )),
        Registry::PyPi => Some((
            "https://pypi.org".to_owned(),
            format!("/pypi/{package}/json"),
        )),
        Registry::CratesIo => Some((
            "https://crates.io".to_owned(),
            format!("/api/v1/crates/{package}"),
        )),
        Registry::PubDev => Some((
            "https://pub.dev".to_owned(),
            format!("/api/packages/{package}"),
        )),
        // The container path is read through GitHub under the session's own
        // credential rather than by an anonymous registry request.
        Registry::Ghcr => None,
    }
}

fn urlencoding(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '@' | '/')
            {
                character.to_string()
            } else {
                format!("%{:02X}", character as u32 as u8)
            }
        })
        .collect()
}

/// Read whether the package exists, and any public publisher signal.
///
/// Every read here is unauthenticated and public. Airlock holds no registry
/// credential, so a fact a registry gates on package ownership is reported as
/// unobservable rather than guessed at.
pub async fn read_package(client: &reqwest::Client, unit: &Unit) -> (Publication, Publisher) {
    read_package_at(client, unit, crate::admin::flow::registry_base()).await
}

/// The same read, with the base stated rather than resolved.
///
/// The base is a parameter so the suite can stand a registry up without
/// reaching for the process environment, which the write path reads in exactly
/// one file and for exactly two overrides.
async fn read_package_at(
    client: &reqwest::Client,
    unit: &Unit,
    base: Option<String>,
) -> (Publication, Publisher) {
    let unobservable = || Publisher::Unobservable {
        reason: unit.registry.configuration_reading().to_owned(),
    };
    let Some((default_base, path)) = package_path(unit) else {
        return (
            Publication::Undecided {
                reason: "this registry is read through GitHub rather than by an \
                         anonymous registry request"
                    .to_owned(),
            },
            unobservable(),
        );
    };
    let base = base.unwrap_or(default_base);
    let response = client
        .get(format!("{}{path}", base.trim_end_matches('/')))
        .header("Accept", "application/json")
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            return (
                Publication::Undecided {
                    reason: text::sanitize(&format!("{error}"), NAME_LIMIT),
                },
                unobservable(),
            )
        }
    };
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return (Publication::Absent, unobservable());
    }
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return (
            Publication::Undecided {
                reason: format!("the registry answered {status}"),
            },
            unobservable(),
        );
    }
    match response.json::<serde_json::Value>().await {
        Ok(document) => (
            Publication::Published {
                latest: latest_version(unit.registry, &document),
            },
            publisher_signal(unit.registry, &document).unwrap_or_else(unobservable),
        ),
        Err(error) => (
            Publication::Undecided {
                reason: text::sanitize(&format!("{error}"), NAME_LIMIT),
            },
            unobservable(),
        ),
    }
}

fn latest_version(registry: Registry, document: &serde_json::Value) -> String {
    let raw = match registry {
        Registry::Npm => document
            .get("dist-tags")
            .and_then(|tags| tags.get("latest"))
            .and_then(serde_json::Value::as_str),
        Registry::PyPi => document
            .get("info")
            .and_then(|info| info.get("version"))
            .and_then(serde_json::Value::as_str),
        Registry::CratesIo => document
            .get("crate")
            .and_then(|package| package.get("max_version"))
            .and_then(serde_json::Value::as_str),
        Registry::PubDev => document
            .get("latest")
            .and_then(|latest| latest.get("version"))
            .and_then(serde_json::Value::as_str),
        Registry::Ghcr => None,
    };
    raw.map_or_else(
        || "version not stated in the response".to_owned(),
        |value| text::sanitize(value, NAME_LIMIT),
    )
}

/// The one public, credential-free publisher signal any registry offers.
fn publisher_signal(registry: Registry, document: &serde_json::Value) -> Option<Publisher> {
    if registry != Registry::CratesIo {
        return None;
    }
    document
        .get("crate")
        .and_then(|package| package.get("trustpub_only"))
        .and_then(serde_json::Value::as_bool)
        .and_then(|restricted| restricted.then_some(Publisher::Restricted))
}

/// Read a container package's state from what GitHub answered.
#[must_use]
pub fn container_of(document: &serde_json::Value) -> Container {
    let Some(visibility) = document
        .get("visibility")
        .and_then(serde_json::Value::as_str)
    else {
        return Container::Undecided {
            reason: "the package response stated no visibility".to_owned(),
        };
    };
    Container::Present {
        visibility: text::sanitize(visibility, NAME_LIMIT),
        repository: document
            .get("repository")
            .and_then(|repository| repository.get("full_name"))
            .and_then(serde_json::Value::as_str)
            .map(|name| text::sanitize(name, NAME_LIMIT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(registry: Registry) -> Observation {
        Observation {
            unit: Unit {
                package: "sample-package".to_owned(),
                registry,
            },
            credential: None,
            publication: Publication::Absent,
            publisher: Publisher::Unobservable {
                reason: "not read".to_owned(),
            },
            container: None,
        }
    }

    fn credential() -> Credential {
        Credential {
            name: "CARGO_REGISTRY_TOKEN".to_owned(),
            scope: "this repository's Actions secrets".to_owned(),
            created: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    fn states(observation: &Observation) -> Vec<StepState> {
        let Placement::Ceremony(steps) = place(observation) else {
            panic!("the token ceremony was expected");
        };
        steps.into_iter().map(|(_, state)| state).collect()
    }

    #[test]
    fn an_unpublished_package_with_no_secret_starts_at_the_mint() {
        let observed = observation(Registry::CratesIo);
        assert_eq!(place(&observed).live_step(), Some(1));
        let states = states(&observed);
        assert!(matches!(states[2], StepState::Blocked { .. }));
        assert!(matches!(states[4], StepState::Blocked { .. }));
    }

    #[test]
    fn a_held_secret_and_no_package_waits_on_the_external_step() {
        let mut observed = observation(Registry::CratesIo);
        observed.credential = Some(credential());
        let placement = place(&observed);
        assert_eq!(placement.live_step(), Some(3));
        assert!(placement
            .waiting_on()
            .is_some_and(|note| note.contains("external event")));
        // The token itself is never claimed to exist or to work.
        assert!(matches!(
            states(&observed)[0],
            StepState::Unobservable { .. }
        ));
    }

    #[test]
    fn a_published_package_still_holding_the_secret_is_not_finished() {
        let mut observed = observation(Registry::CratesIo);
        observed.credential = Some(credential());
        observed.publication = Publication::Published {
            latest: "1.0.0".to_owned(),
        };
        assert_eq!(place(&observed).live_step(), Some(4));
        observed.publisher = Publisher::Restricted;
        assert_eq!(place(&observed).live_step(), Some(5));
        assert!(place(&observed)
            .waiting_on()
            .is_some_and(|note| note.contains("not conformant")));
    }

    #[test]
    fn the_ceremony_is_over_only_when_the_credential_is_gone() {
        let mut observed = observation(Registry::CratesIo);
        observed.publication = Publication::Published {
            latest: "1.0.0".to_owned(),
        };
        let placement = place(&observed);
        assert_eq!(placement.live_step(), None);
        let Placement::Ceremony(steps) = placement else {
            panic!("the token ceremony was expected");
        };
        assert!(matches!(steps[4].1, StepState::Done { .. }));
    }

    #[test]
    fn a_registry_that_configures_before_publication_has_no_ceremony() {
        let placement = place(&observation(Registry::PyPi));
        let Placement::Unnecessary { reason } = placement else {
            panic!("PyPI skips the ceremony entirely");
        };
        assert!(reason.contains("pending publisher"));
    }

    #[test]
    fn the_container_path_is_its_own_three_steps() {
        let mut observed = observation(Registry::Ghcr);
        observed.container = Some(Container::Present {
            visibility: "private".to_owned(),
            repository: None,
        });
        let placement = place(&observed);
        assert_eq!(placement.extent(), 3);
        assert_eq!(placement.live_step(), Some(2));
        observed.container = Some(Container::Present {
            visibility: "private".to_owned(),
            repository: Some("generic-owner/sample-repository".to_owned()),
        });
        assert_eq!(place(&observed).live_step(), Some(3));
    }

    #[test]
    fn an_unread_registry_is_stated_as_unobservable_rather_than_absent() {
        let mut observed = observation(Registry::Npm);
        observed.credential = Some(credential());
        observed.publication = Publication::Undecided {
            reason: "the registry did not answer".to_owned(),
        };
        let states = states(&observed);
        assert!(matches!(states[2], StepState::Unobservable { .. }));
        assert_eq!(place(&observed).live_step(), None);
    }

    #[tokio::test]
    async fn a_public_registry_read_answers_published_absent_or_undecided() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/published-package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "crate": {"max_version": "1.2.3", "trustpub_only": true}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/absent-package"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/unreadable-package"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let read = |package: &str| {
            let unit = Unit {
                package: package.to_owned(),
                registry: Registry::CratesIo,
            };
            let client = client.clone();
            let base = Some(server.uri());
            async move { read_package_at(&client, &unit, base).await }
        };

        let (publication, publisher) = read("published-package").await;
        assert_eq!(
            publication,
            Publication::Published {
                latest: "1.2.3".to_owned()
            }
        );
        // The one public, credential-free publisher signal any registry offers.
        assert_eq!(publisher, Publisher::Restricted);

        let (publication, publisher) = read("absent-package").await;
        assert_eq!(publication, Publication::Absent);
        assert!(matches!(publisher, Publisher::Unobservable { .. }));

        let (publication, _) = read("unreadable-package").await;
        let Publication::Undecided { reason } = publication else {
            panic!("a registry that did not answer is not an absent package");
        };
        assert!(reason.contains("503"), "{reason}");
    }

    #[test]
    fn a_container_package_reads_its_visibility_and_link_and_nothing_else() {
        let container = container_of(&serde_json::json!({
            "visibility": "private",
            "repository": {"full_name": "generic-owner/sample-repository"}
        }));
        assert_eq!(
            container,
            Container::Present {
                visibility: "private".to_owned(),
                repository: Some("generic-owner/sample-repository".to_owned()),
            }
        );
        assert!(matches!(
            container_of(&serde_json::json!({})),
            Container::Undecided { .. }
        ));
    }

    #[test]
    fn units_come_from_the_declared_release_units_and_their_manifests() {
        let declaration = Declaration {
            units: vec![
                ("sample-package".to_owned(), ".".to_owned()),
                ("sample-tool".to_owned(), "tools/sample".to_owned()),
            ],
            files: ["Cargo.toml", "tools/sample/package.json"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        };
        assert_eq!(
            units(&declaration),
            vec![
                Unit {
                    package: "sample-tool".to_owned(),
                    registry: Registry::Npm,
                },
                Unit {
                    package: "sample-package".to_owned(),
                    registry: Registry::CratesIo,
                },
            ]
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_ceremony_is_the_five_steps_in_the_order_the_specification_gives_them() {
        let Placement::Ceremony(steps) = place(&observation(Registry::Npm)) else {
            panic!("the token ceremony was expected");
        };
        assert_eq!(
            steps.iter().map(|(step, _)| *step).collect::<Vec<_>>(),
            Step::ALL.to_vec()
        );
        for (index, (step, _)) in steps.iter().enumerate() {
            assert_eq!(step.number(), index + 1);
            assert!(!step.title().is_empty());
        }
    }

    #[test]
    fn every_token_registry_names_the_secret_its_ceremony_creates() {
        for registry in Registry::ALL {
            assert_eq!(
                registry.ceremony() == Ceremony::Token,
                registry.bootstrap_secret().is_some(),
                "{}",
                registry.label()
            );
        }
    }
}
