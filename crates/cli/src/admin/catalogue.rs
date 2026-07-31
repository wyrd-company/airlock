//! What the operator chooses from: the installations this credential reaches,
//! and the repositories inside each one.
//!
//! The catalogue is a read model. It holds no credential — the worker that
//! fills it owns the only client, and what crosses the channel is text that has
//! already been sanitized. Nothing here can be handed a grant, because no type
//! here has a field for one.
//!
//! Two things this module is deliberately not. It is not a cache: the
//! observations it can report are the ones this session made, it reads nothing
//! from disk and writes nothing to it, so a fresh session has never observed
//! anything and every row says so. And it is not a wrapper over the API: it
//! keeps the installation scoping GitHub reports, because a 404 on a repository
//! outside an installation's selection and a 404 on a repository that does not
//! exist are the same response, and only the catalogue can tell them apart.

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver as SyncReceiver, Sender as SyncSender};
use std::time::Duration;

use airlock_core::github::{
    AccountKind, ErrorCause, GitHub as _, RepositorySelection, RestClient, RestClientConfig,
};

use super::session::SessionCredential;
use super::text::{self, CAUSE_LIMIT, NAME_LIMIT};
use super::{flow, identity};

/// How long the worker is given to notice that the session has gone.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

/// One repository an installation reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// The owner login, sanitized.
    pub owner: String,
    /// The repository name, sanitized.
    pub name: String,
    /// `public`, `private`, or `internal`, sanitized.
    pub visibility: String,
    /// The default branch, when the repository has one.
    pub default_branch: Option<String>,
}

impl Repository {
    /// What the row prints where a default branch would go.
    ///
    /// An empty repository has no branch, which is a fact rather than a blank:
    /// there is nothing yet for a pull request to be opened against.
    #[must_use]
    pub fn branch(&self) -> &str {
        self.default_branch.as_deref().unwrap_or("no branch yet")
    }
}

/// What an installation's repository listing came back as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// The repositories airlock saw, and the count GitHub reported.
    Read {
        /// The repositories collected.
        repositories: Vec<Repository>,
        /// GitHub's count for the installation.
        total: u64,
        /// True when the walk stopped at the page budget.
        truncated: bool,
    },
    /// The listing failed, with a cause safe to draw.
    ///
    /// Kept rather than dropped: an installation whose repositories could not
    /// be listed is still an installation the operator has, and removing it
    /// from the screen would report a failed read as an absent install.
    Refused(String),
}

/// How far a listing got: what airlock has, against what GitHub reported.
///
/// The two are carried together because they answer different questions and
/// only one of them is about the account. A screen holding a hundred rows of a
/// four-hundred-repository installation has seen a prefix, and a count read off
/// the rows it holds would report a page budget as a fact about the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reach {
    /// How many repositories airlock actually collected.
    pub collected: usize,
    /// How many GitHub said the installation reaches.
    pub total: u64,
    /// True when what airlock collected is a prefix rather than the whole.
    pub truncated: bool,
}

impl Reach {
    /// What the count is, against what it is a count of.
    ///
    /// A complete listing says one number because the two are the same one. A
    /// prefix says both, and says which is which.
    #[must_use]
    pub fn against(&self, shown: usize) -> String {
        if self.truncated {
            return format!("{shown} of {} shown, a prefix", self.total);
        }
        format!("{shown} of {} shown", self.total)
    }

    /// What the installation reaches, said in full.
    #[must_use]
    pub fn statement(&self) -> String {
        if self.truncated {
            return format!(
                "{} of {} read \u{2014} the listing stopped at airlock's page budget, so \
                 what is missing is the listing rather than the repositories",
                self.collected, self.total
            );
        }
        match self.total {
            0 => "no repository".to_owned(),
            1 => "all 1 repository".to_owned(),
            total => format!("all {total} repositories"),
        }
    }
}

impl Listing {
    /// The repositories, or nothing when the listing failed.
    #[must_use]
    pub fn repositories(&self) -> &[Repository] {
        match self {
            Self::Read { repositories, .. } => repositories,
            Self::Refused(_) => &[],
        }
    }

    /// How far the listing got.
    ///
    /// A refused listing reaches nothing and is truncated by definition: what
    /// airlock has is not the whole of it, and it does not know what the whole
    /// of it would be.
    #[must_use]
    pub fn reach(&self) -> Reach {
        match self {
            Self::Read {
                repositories,
                total,
                truncated,
            } => Reach {
                collected: repositories.len(),
                total: *total,
                truncated: *truncated,
            },
            Self::Refused(_) => Reach {
                collected: 0,
                total: 0,
                truncated: true,
            },
        }
    }

    /// The count for the row, in the terms the listing can support.
    #[must_use]
    pub fn count(&self) -> String {
        match self {
            // A prefix says both numbers on the row, because the row is where
            // an operator decides whether the screen behind it is the whole
            // installation or the part of it airlock could read.
            Self::Read {
                repositories,
                total,
                truncated: true,
            } => format!("{total} repositories, {} read", repositories.len()),
            Self::Read { total, .. } if *total == 1 => "1 repository".to_owned(),
            Self::Read { total, .. } => format!("{total} repositories"),
            Self::Refused(_) => "repositories not listed".to_owned(),
        }
    }
}

/// One installation the operator can work in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    /// The installation id.
    pub id: u64,
    /// The account it sits on, sanitized.
    pub account: String,
    /// Whether that account is an organization or a personal one.
    pub kind: AccountKind,
    /// Whether the installation reaches every repository of that account.
    pub selection: RepositorySelection,
    /// What its repository listing came back as.
    pub listing: Listing,
}

impl Installation {
    /// What the row says about the installation's reach, where it is not all of
    /// it.
    ///
    /// A scoped installation is one of the three causes of an absent
    /// organization, so a row that is scoped says so on the row rather than
    /// leaving the operator to infer it from a count.
    #[must_use]
    pub fn scope_note(&self) -> Option<String> {
        match (&self.selection, &self.listing) {
            (RepositorySelection::Selected, Listing::Read { total, .. }) => Some(format!(
                "scoped to {total} selected {}; the rest are invisible here",
                if *total == 1 {
                    "repository"
                } else {
                    "repositories"
                }
            )),
            (RepositorySelection::Selected, Listing::Refused(_)) => {
                Some("scoped to a selection airlock could not list".to_owned())
            }
            (RepositorySelection::Unrecognised, _) => {
                Some("github did not state which repositories this installation reaches".to_owned())
            }
            (RepositorySelection::All, _) => None,
        }
    }
}

/// Why a repository is not in the catalogue.
///
/// GitHub answers the same 404 for a repository that does not exist and one an
/// installation cannot see, so the response alone cannot say which. The
/// catalogue is the context that can, and these are the four answers it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Absence {
    /// No installation airlock can see reaches that owner at all.
    NoInstallation,
    /// The installation on that owner is scoped, and this is outside the scope.
    OutsideSelection,
    /// The installation reaches every repository the account has, so the
    /// repository is genuinely absent.
    Absent,
    /// The catalogue cannot answer: the listing was a prefix, failed, or the
    /// selection was one airlock does not recognise.
    Undetermined,
}

impl Absence {
    /// What the interface says about `owner/name` not being here.
    ///
    /// The same sentence serves the empty row and the 404, because they are the
    /// same fact reached two ways: GitHub answers 404 for a repository that
    /// does not exist and for one an installation cannot see, and neither the
    /// response nor an empty list can tell them apart on its own.
    #[must_use]
    pub fn statement(&self, owner: &str, name: &str) -> String {
        match self {
            Self::NoInstallation => format!(
                "airlock has no installation on {owner}, so {owner}/{name} is invisible \
                 from here rather than known to be absent. GitHub answers 404 for both, \
                 and this is installation scope: install airlock on {owner} to see it."
            ),
            Self::OutsideSelection => format!(
                "the installation on {owner} is scoped to selected repositories, and \
                 {name} is not among them. That is installation scope rather than \
                 absence \u{2014} GitHub answers 404 for both. Widen the \
                 installation's repository selection to see it."
            ),
            Self::Absent => format!(
                "the installation on {owner} reaches every repository the account has, \
                 and {name} is not one of them. It is absent rather than out of scope."
            ),
            Self::Undetermined => format!(
                "airlock did not read the whole of what the installation on {owner} \
                 reaches, so it cannot say whether {name} is out of its scope or absent."
            ),
        }
    }
}

/// The installations this credential reaches, and what is in each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalogue {
    installations: Vec<Installation>,
}

impl Catalogue {
    /// Build a catalogue from installations already filtered and sanitized.
    #[must_use]
    pub fn of(installations: Vec<Installation>) -> Self {
        Self { installations }
    }

    /// The installations, in the order GitHub reported them.
    #[must_use]
    pub fn installations(&self) -> &[Installation] {
        &self.installations
    }

    /// Why `owner/name` is not here.
    ///
    /// Read from the catalogue rather than from the failing response, because
    /// the response cannot carry the distinction: the classification airlock
    /// makes of a 404 is `not_found` either way, and which of the two it is
    /// depends on what the installation was scoped to.
    #[must_use]
    pub fn absence(&self, owner: &str, name: &str) -> Absence {
        let Some(installation) = self.reaching(owner) else {
            return Absence::NoInstallation;
        };
        if installation
            .listing
            .repositories()
            .iter()
            .any(|repository| repository.name.eq_ignore_ascii_case(name))
        {
            return Absence::Absent;
        }
        match (&installation.selection, &installation.listing) {
            (_, Listing::Refused(_))
            | (
                _,
                Listing::Read {
                    truncated: true, ..
                },
            ) => Absence::Undetermined,
            (RepositorySelection::Selected, _) => Absence::OutsideSelection,
            (RepositorySelection::All, _) => Absence::Absent,
            (RepositorySelection::Unrecognised, _) => Absence::Undetermined,
        }
    }

    fn reaching(&self, owner: &str) -> Option<&Installation> {
        self.installations
            .iter()
            .find(|installation| installation.account.eq_ignore_ascii_case(owner))
    }
}

/// What the interface asks for when a repository is opened.
///
/// Its whole content is the repository's coordinates. There is no field for a
/// prior verdict and no constructor that takes one, which is what makes
/// "nothing is acted upon from memory" a property of the type rather than a
/// discipline of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observe {
    /// The owner login.
    pub owner: String,
    /// The repository name.
    pub name: String,
}

/// What airlock has previously said about a repository, for orientation only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorAudit {
    /// No observation of it exists.
    ///
    /// The default, and the state a session starts every row in: airlock keeps
    /// no audit history, so the only verdict it can honestly report is one this
    /// session produced.
    NeverObserved,
    /// This session observed it.
    Observed {
        /// When, as the observation reported it.
        at: String,
        /// The verdict it reached, in the audit's own vocabulary.
        verdict: String,
    },
}

impl PriorAudit {
    /// The date column.
    #[must_use]
    pub fn date(&self) -> &str {
        match self {
            Self::NeverObserved => "never",
            Self::Observed { at, .. } => at,
        }
    }

    /// The verdict column.
    ///
    /// A repository never audited says so rather than showing a blank, because
    /// a blank verdict reads as a verdict nobody wrote down.
    #[must_use]
    pub fn verdict(&self) -> &str {
        match self {
            Self::NeverObserved => "never observed",
            Self::Observed { verdict, .. } => verdict,
        }
    }
}

/// What this session has observed.
///
/// Session-scoped and nothing else. Nothing is read from disk, nothing is
/// written to it, and the journal dies with the process — which is why a fresh
/// session shows "never observed" against every row, and why that is the honest
/// reading rather than a placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observations {
    seen: BTreeMap<(String, String), PriorAudit>,
}

impl Observations {
    /// Record what an observation made in this session reached.
    pub fn record(&mut self, observe: &Observe, at: impl Into<String>, verdict: impl Into<String>) {
        self.seen.insert(
            (observe.owner.clone(), observe.name.clone()),
            PriorAudit::Observed {
                at: at.into(),
                verdict: verdict.into(),
            },
        );
    }

    /// What this session has said about a repository.
    #[must_use]
    pub fn prior(&self, owner: &str, name: &str) -> PriorAudit {
        self.seen
            .get(&(owner.to_owned(), name.to_owned()))
            .cloned()
            .unwrap_or(PriorAudit::NeverObserved)
    }
}

/// One line of the repository table: a repository, and what is known about it.
///
/// The prior verdict travels on the row because the row displays it. What the
/// row will not do is let it out again as anything but text: [`Row::observe`]
/// is built from the coordinates alone, so two rows that differ only in their
/// prior ask for exactly the same observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The repository this row is about.
    pub repository: Repository,
    /// What airlock last said about it, for orientation.
    pub prior: PriorAudit,
}

impl Row {
    /// Pair the repositories of an installation with this session's journal.
    #[must_use]
    pub fn of(installation: &Installation, observations: &Observations) -> Vec<Row> {
        installation
            .listing
            .repositories()
            .iter()
            .map(|repository| Row {
                prior: observations.prior(&repository.owner, &repository.name),
                repository: repository.clone(),
            })
            .collect()
    }

    /// What opening this row asks for.
    #[must_use]
    pub fn observe(&self) -> Observe {
        Observe {
            owner: self.repository.owner.clone(),
            name: self.repository.name.clone(),
        }
    }
}

/// Where the catalogue read has got to.
///
/// Four states rather than an `Option`, because "nothing has been asked for",
/// "the answer has not arrived", "there is nothing to show", and "the question
/// failed" are four different things to say, and an empty list that meant any
/// of them would say none of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum State {
    /// No authorization exists yet, so nothing has been asked for.
    #[default]
    Unauthorized,
    /// The read is in flight.
    Reading,
    /// The catalogue, read.
    Ready(Box<Catalogue>),
    /// The read failed, with a cause safe to draw.
    Failed(String),
}

impl State {
    /// The catalogue, where one has been read.
    #[must_use]
    pub fn catalogue(&self) -> Option<&Catalogue> {
        match self {
            Self::Ready(catalogue) => Some(catalogue),
            Self::Unauthorized | Self::Reading | Self::Failed(_) => None,
        }
    }

    /// The installations, or none where there is no catalogue yet.
    #[must_use]
    pub fn installations(&self) -> &[Installation] {
        self.catalogue().map_or(&[], Catalogue::installations)
    }
}

/// What the catalogue worker sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// The catalogue, read whole.
    Ready(Box<Catalogue>),
    /// GitHub rejected the credential itself.
    ///
    /// Its own arm rather than a failure with a recognisable message, because
    /// it is the one failure that is not about the catalogue at all: the grant
    /// this session holds is no longer one, and the remedy is a new device
    /// approval rather than anything the operator can do to this list.
    Unauthorized,
    /// The read failed. The cause is sanitized and carries no credential.
    Failed(String),
}

/// The interface's end of the catalogue worker.
pub struct Reading {
    reports: SyncReceiver<Read>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Reading {
    /// Start reading the catalogue with the session's credential.
    ///
    /// The credential is spent here, into a client that is moved onto the
    /// worker: this function is the last place the token is a value anything
    /// holds, and nothing it returns has a field one could travel in.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP stack or the worker thread cannot start.
    pub fn start(credential: &SessionCredential) -> anyhow::Result<Self> {
        let config = RestClientConfig {
            base_url: flow::api_base(),
            // The console's client carries a write-capable credential, so a
            // redirect would be a server choosing where that credential goes.
            ..RestClientConfig::default().refusing_redirects()
        };
        let client = RestClient::new(credential.expose_for_authorization_header(), config)
            .map_err(|error| anyhow::anyhow!("cannot build the github client: {error}"))?;
        let (reports, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("airlock-catalogue".to_owned())
            .spawn(move || run(&client, &reports))?;
        Ok(Self {
            reports: receiver,
            worker: Some(worker),
        })
    }

    /// Take the next report, if one has arrived.
    pub fn next_report(&self, timeout: Duration) -> Option<Read> {
        self.reports.recv_timeout(timeout).ok()
    }

    fn shut_down(&mut self) {
        if let Some(worker) = self.worker.take() {
            let deadline = std::time::Instant::now() + SHUTDOWN_BUDGET;
            while !worker.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// The worker: read the installations, then what each one reaches.
fn run(client: &RestClient, reports: &SyncSender<Read>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = reports.send(Read::Failed(text::sanitize(
                &format!("the catalogue read could not start: {error}"),
                CAUSE_LIMIT,
            )));
            return;
        }
    };
    let report = runtime.block_on(read(client));
    let _ = reports.send(report);
}

async fn read(client: &RestClient) -> Read {
    let attested = identity::bound();
    let installations = match client.user_installations().await {
        Ok(installations) => installations,
        // 401 is unambiguous: the credential was rejected, not the question.
        Err(error) if error.cause == ErrorCause::Unauthenticated => return Read::Unauthorized,
        Err(error) => return Read::Failed(text::sanitize(&error.to_string(), CAUSE_LIMIT)),
    };
    let mut catalogue = Vec::new();
    for installation in installations {
        // The identity filter, and the reason the test build is safe to run
        // against a production account: an installation of another app is not
        // this app's to work in, so it is not on the screen at all.
        if !attested.attests(installation.app_id, &installation.app_slug) {
            continue;
        }
        let listing = match client.installation_repositories(installation.id).await {
            Ok(listing) => Listing::Read {
                repositories: listing
                    .repositories
                    .iter()
                    .map(|repository| Repository {
                        owner: text::sanitize(&repository.owner, NAME_LIMIT),
                        name: text::sanitize(&repository.name, NAME_LIMIT),
                        visibility: text::sanitize(&repository.visibility, NAME_LIMIT),
                        default_branch: repository
                            .default_branch
                            .as_ref()
                            .map(|branch| text::sanitize(branch, NAME_LIMIT)),
                    })
                    .collect(),
                total: listing.total_count,
                truncated: listing.truncated,
            },
            Err(error) => Listing::Refused(text::sanitize(&error.to_string(), CAUSE_LIMIT)),
        };
        catalogue.push(Installation {
            id: installation.id,
            account: installation.account.as_ref().map_or_else(
                || "an account github did not name".to_owned(),
                |account| text::sanitize(account, NAME_LIMIT),
            ),
            kind: installation.account_kind,
            selection: installation.repository_selection,
            listing,
        });
    }
    Read::Ready(Box::new(Catalogue::of(catalogue)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository(owner: &str, name: &str) -> Repository {
        Repository {
            owner: owner.to_owned(),
            name: name.to_owned(),
            visibility: "private".to_owned(),
            default_branch: Some("main".to_owned()),
        }
    }

    fn installation(
        account: &str,
        kind: AccountKind,
        selection: RepositorySelection,
        names: &[&str],
    ) -> Installation {
        Installation {
            id: 7,
            account: account.to_owned(),
            kind,
            selection,
            listing: Listing::Read {
                repositories: names.iter().map(|name| repository(account, name)).collect(),
                total: names.len() as u64,
                truncated: false,
            },
        }
    }

    #[test]
    fn a_repository_with_no_branch_says_so_rather_than_naming_one() {
        let mut fresh = repository("acme-industries", "widget");
        fresh.default_branch = None;
        assert_eq!(fresh.branch(), "no branch yet");
        assert_eq!(repository("acme-industries", "widget").branch(), "main");
    }

    #[test]
    fn a_scoped_installation_says_so_on_its_own_row() {
        let scoped = installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::Selected,
            &["widget"],
        );
        let note = scoped.scope_note().expect("a scoped row carries a note");
        assert!(note.contains("scoped to 1 selected repository"), "{note}");
        assert!(
            installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &["widget"],
            )
            .scope_note()
            .is_none(),
            "an installation that reaches everything has nothing to qualify"
        );
    }

    #[test]
    fn an_unlisted_installation_is_kept_and_says_its_count_is_unknown() {
        let refused = Installation {
            listing: Listing::Refused("rate_limit on GET /user/installations".to_owned()),
            ..installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &[],
            )
        };
        assert_eq!(refused.listing.count(), "repositories not listed");
        assert!(refused.listing.repositories().is_empty());
    }

    #[test]
    fn a_404_outside_a_scoped_selection_is_scope_rather_than_absence() {
        let catalogue = Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::Selected,
            &["widget"],
        )]);
        assert_eq!(
            catalogue.absence("acme-industries", "sprocket"),
            Absence::OutsideSelection
        );
        let statement = Absence::OutsideSelection.statement("acme-industries", "sprocket");
        assert!(
            statement.contains("installation scope rather than absence"),
            "{statement}"
        );
        assert!(statement.contains("repository selection"), "{statement}");
    }

    #[test]
    fn a_404_where_the_installation_reaches_everything_is_absence() {
        let catalogue = Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &["widget"],
        )]);
        assert_eq!(
            catalogue.absence("acme-industries", "sprocket"),
            Absence::Absent
        );
        assert!(Absence::Absent
            .statement("acme-industries", "sprocket")
            .contains("absent rather than out of scope"));
        assert!(Absence::NoInstallation
            .statement("acme-industries", "sprocket")
            .contains("installation scope"));
        assert!(Absence::Undetermined
            .statement("acme-industries", "sprocket")
            .contains("cannot say"));
    }

    #[test]
    fn a_404_on_an_owner_with_no_installation_is_scope() {
        let catalogue = Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &["widget"],
        )]);
        assert_eq!(
            catalogue.absence("other-account", "widget"),
            Absence::NoInstallation
        );
        assert_eq!(
            Catalogue::default().absence("acme-industries", "widget"),
            Absence::NoInstallation
        );
    }

    #[test]
    fn a_404_read_against_a_prefix_is_neither_answer() {
        // A listing airlock could not walk to the end cannot say a repository
        // is outside it. Undetermined is the honest answer, and it is not
        // rounded to either of the two that sound more decisive.
        let truncated = Installation {
            listing: Listing::Read {
                repositories: vec![repository("acme-industries", "widget")],
                total: 400,
                truncated: true,
            },
            ..installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &[],
            )
        };
        let catalogue = Catalogue::of(vec![truncated]);
        assert_eq!(
            catalogue.absence("acme-industries", "sprocket"),
            Absence::Undetermined
        );
        // What it did see, it can still answer for.
        assert_eq!(
            catalogue.absence("acme-industries", "widget"),
            Absence::Absent
        );
    }

    #[test]
    fn a_selection_github_did_not_state_is_never_guessed_at() {
        let catalogue = Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::Unrecognised,
            &["widget"],
        )]);
        assert_eq!(
            catalogue.absence("acme-industries", "sprocket"),
            Absence::Undetermined
        );
    }

    #[test]
    fn a_session_that_has_observed_nothing_reports_never_observed() {
        let observations = Observations::default();
        let prior = observations.prior("acme-industries", "widget");
        assert_eq!(prior, PriorAudit::NeverObserved);
        assert_eq!(prior.date(), "never");
        assert_eq!(prior.verdict(), "never observed");
    }

    #[test]
    fn an_observation_made_in_this_session_is_what_a_row_reports() {
        let mut observations = Observations::default();
        observations.record(
            &Observe {
                owner: "acme-industries".to_owned(),
                name: "widget".to_owned(),
            },
            "2026-01-02",
            "nonconformant",
        );
        let prior = observations.prior("acme-industries", "widget");
        assert_eq!(prior.date(), "2026-01-02");
        assert_eq!(prior.verdict(), "nonconformant");
        assert_eq!(
            observations.prior("acme-industries", "sprocket"),
            PriorAudit::NeverObserved,
            "a journal entry is about one repository and not its neighbours"
        );
    }

    #[test]
    fn opening_a_repository_asks_for_the_same_observation_whatever_was_remembered() {
        // The definition-of-done's assertion, made against values rather than
        // against the shape of the code: two rows that differ only in what
        // airlock remembers produce byte-identical requests, so no verdict can
        // shorten, skip, or steer the observation that follows.
        let repository = repository("acme-industries", "widget");
        let never = Row {
            repository: repository.clone(),
            prior: PriorAudit::NeverObserved,
        };
        let passed = Row {
            repository: repository.clone(),
            prior: PriorAudit::Observed {
                at: "2026-01-02".to_owned(),
                verdict: "conformant".to_owned(),
            },
        };
        let failed = Row {
            repository,
            prior: PriorAudit::Observed {
                at: "2026-01-02".to_owned(),
                verdict: "nonconformant".to_owned(),
            },
        };
        assert_eq!(never.observe(), passed.observe());
        assert_eq!(never.observe(), failed.observe());
        assert_eq!(
            never.observe(),
            Observe {
                owner: "acme-industries".to_owned(),
                name: "widget".to_owned(),
            }
        );
    }

    #[test]
    fn rows_pair_the_listing_with_this_sessions_journal() {
        let installation = installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &["widget", "sprocket"],
        );
        let mut observations = Observations::default();
        observations.record(
            &Observe {
                owner: "acme-industries".to_owned(),
                name: "sprocket".to_owned(),
            },
            "2026-01-02",
            "conformant",
        );
        let rows = Row::of(&installation, &observations);
        assert_eq!(rows[0].prior, PriorAudit::NeverObserved);
        assert_eq!(rows[1].prior.verdict(), "conformant");
    }

    #[test]
    fn the_api_root_override_is_honoured_only_for_this_machine() {
        // The environment is process-wide, so this asserts the decision the
        // override is made of rather than setting the variable.
        assert!(flow::is_loopback("http://127.0.0.1:8080"));
        assert!(!flow::is_loopback(
            "https://api.github.com.attacker.example"
        ));
        assert_eq!(
            RestClientConfig::default().base_url,
            "https://api.github.com"
        );
    }

    #[test]
    fn the_console_client_refuses_redirects() {
        let config = RestClientConfig::default().refusing_redirects();
        assert!(!config.follow_redirects);
        assert!(
            RestClientConfig::default().follow_redirects,
            "the read path still follows a renamed repository"
        );
    }
}
