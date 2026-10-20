//! The rules.
//!
//! Rule identifiers, statements, and default severities are compiled into the
//! binary rather than loaded from the conformance document, so a released
//! binary always reports what it actually evaluated. A policy may select,
//! parameterise, and re-grade a registered rule; it cannot define one.
//!
//! Rules are grouped into sections selected through capabilities. Each
//! rule declares its observation source and any API, owner, disclosure, or
//! unbuilt boundary. Missing evidence without such a declaration is a run error.
//!
//! The repository-standards skill's conformance reference is generated from
//! these rules. A test in `tests/conformance.rs` parses that projection and
//! proves it preserves every rules-owned field.

use std::fmt;

pub(crate) mod agent;
pub(crate) mod automation;
pub(crate) mod classification;
pub(crate) mod docs;
pub(crate) mod files;
pub(crate) mod git;
pub(crate) mod identity;
pub(crate) mod licensing;
pub(crate) mod readme;
pub(crate) mod release;

use sha2::{Digest, Sha256};

/// The semantic version of the compiled rules.
///
/// It moves when the set of rules, their statements, their default severities,
/// or declared check boundaries change. Policies constrain it with
/// `requires-rules`.
pub const RULES_VERSION: &str = "0.6.0";

/// How severely a failure counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Do not evaluate; list the waiver and its reason.
    None,
    /// Report gaps without failing the Action.
    Advisory,
    /// Report gaps and fail the Action.
    Blocking,
}

impl Severity {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Blocking => "blocking",
        }
    }
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "advisory" => Some(Self::Advisory),
            "blocking" => Some(Self::Blocking),
            _ => None,
        }
    }
    pub const ALL: &'static [Self] = &[Self::Blocking, Self::Advisory, Self::None];
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// The section of the conformance checklist a rule belongs to.
///
/// Sections are what a policy's `capabilities` select. Membership can grow as
/// the rules grow; a policy that wants immunity from that names rule ids
/// explicitly instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// Organisation placement, naming, and declared metadata.
    Identity,
    /// Licence choice and declaration.
    Licensing,
    /// Required and forbidden files.
    Files,
    /// README structure.
    Readme,
    /// Git and platform configuration.
    Git,
    /// Taskfiles, CI, CD, and hooks.
    Automation,
    /// Agent affordances.
    Agent,
    /// Documentation layout.
    Docs,
    /// Release units, changelogs, and release workflows.
    Release,
    /// Custom property classification.
    Classification,
}

impl Section {
    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Section::Identity => "identity",
            Section::Licensing => "licensing",
            Section::Files => "files",
            Section::Readme => "readme",
            Section::Git => "git",
            Section::Automation => "automation",
            Section::Agent => "agent",
            Section::Docs => "docs",
            Section::Release => "release",
            Section::Classification => "classification",
        }
    }

    /// Parse a section from its machine-readable name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Section::ALL
            .iter()
            .copied()
            .find(|section| section.code() == value)
    }

    /// Every section, in rules order.
    pub const ALL: &'static [Section] = &[
        Section::Identity,
        Section::Licensing,
        Section::Files,
        Section::Readme,
        Section::Git,
        Section::Automation,
        Section::Agent,
        Section::Docs,
        Section::Release,
        Section::Classification,
    ];
}

impl fmt::Display for Section {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// What a rule observes: the repository's file tree, or platform state that
/// only the GitHub API can report.
///
/// The domain decides which observation source can answer for the rule. A
/// file-tree rule can be evaluated from the API tree or from a local working
/// tree; a platform rule has no local equivalent and is never inferred from
/// one — without the API the rule is routed with no Met or Gap outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The rule reads committed (or, locally, working-tree) file content.
    FileTree,
    /// The rule reads live platform state: settings, rulesets, tags, history,
    /// secrets, or anything else the API owns.
    Platform,
}

impl Observation {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Observation::FileTree => "file-tree",
            Observation::Platform => "platform",
        }
    }
}

/// A permission a platform credential can carry.
///
/// Declared as typed constants for the same reason fix groups are: a grant
/// airlock reasons about must be one it has named, so an undeclared grant is a
/// compile error rather than a string nobody validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Grant {
    code: &'static str,
    writes: bool,
}

impl Grant {
    /// The stable machine-readable name, as GitHub spells the permission.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Whether holding this grant means holding write access.
    ///
    /// Declared rather than parsed out of the name: what counts as write is a
    /// fact about the permission, and airlock refuses write access, so it is
    /// not something to infer from a string.
    #[must_use]
    pub const fn writes(self) -> bool {
        self.writes
    }
}

impl fmt::Display for Grant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

macro_rules! grants {
    ($($name:ident => $code:literal, writes: $writes:literal),+ $(,)?) => {
        impl Grant {
            $(
                #[doc = concat!("The `", $code, "` permission.")]
                pub const $name: Self = Self { code: $code, writes: $writes };
            )+

            /// Every declared grant.
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
        }
    };
}

grants! {
    ADMINISTRATION_READ => "administration:read", writes: false,
    CONTENTS_WRITE => "contents:write", writes: true,
}

/// What the credential a run presented was enumerated to be able to do.
///
/// Airlock enumerates a credential's whole grant before first use and refuses
/// one it cannot enumerate, so this is a read fact rather than an assumption.
/// It is what decides whether an absent field is evidence of a disclosure gate:
/// a credential that provably cannot hold the required grant explains the
/// absence, and one that might hold it does not.
///
/// `ReadOnly` is therefore the excusing answer, and the two ways of being wrong
/// do not cost the same. A write-capable credential mislabelled `ReadOnly`
/// excuses a field it should have been shown, retiring a real gap; a read-only
/// one mislabelled `WriteCapable` only reports a permanent gap as a blocking
/// one, which overstates what a retry might achieve and hides nothing. Every
/// uncertain grant resolves to `WriteCapable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialCapability {
    /// No credential was presented, so nothing was observed through one.
    Unauthenticated,
    /// Every entry in the enumerated grant is a read.
    ReadOnly,
    /// The enumerated grant carries something that is not a read, or it could
    /// not be read as a whole.
    WriteCapable,
}

impl CredentialCapability {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::ReadOnly => "read-only",
            Self::WriteCapable => "write-capable",
        }
    }
}

/// The surface that verifies a fact the audit's credential is not allowed to
/// read.
///
/// A gated fact requires admin access to verify. Naming the admin-capable
/// verification surface keeps the access requirement explicit, and it is where
/// every surface takes the guidance it prints from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationSurface {
    /// The interactive airlock session, which holds an operator's
    /// write-capable credential and can both read and align the setting.
    InteractiveSession,
}

impl VerificationSurface {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InteractiveSession => "interactive-session",
        }
    }

    /// What a reader should do about a gap this surface verifies.
    ///
    /// Declared once, here. No check, projection, or renderer writes this
    /// sentence itself, so the guidance cannot say different things in
    /// different places.
    #[must_use]
    pub const fn guidance(self) -> &'static str {
        match self {
            Self::InteractiveSession => {
                "run the interactive airlock session to verify and align it"
            }
        }
    }

    /// Every declared verification surface.
    pub const ALL: &'static [Self] = &[Self::InteractiveSession];
}

/// A fact the platform discloses only to a credential the audit surface is not
/// allowed to hold.
///
/// This is rule metadata, not check trivia: it says the read-only audit cannot settle
/// the rule, whatever it retries, and it names the surface that can. The audit
/// derives a routed record from it, and every projection
/// derives what it prints from it. A check may not decide on its own that its
/// missing input was gated — a rule with no declaration whose input is absent
/// is a run that fell short, and stays blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisclosureGate {
    /// The fact the gate withholds, as a phrase a sentence can be built
    /// around, for example `the repository's merge settings`.
    pub fact: &'static str,
    /// The stable evidence code a finding carries when the gate withheld the
    /// fact.
    pub evidence_code: &'static str,
    /// The grant the platform requires before it discloses the fact.
    pub requires: Grant,
    /// Grants that plainly ought to disclose the fact and, as verified
    /// empirically, do not. Naming them is what stops the gate being
    /// "fixed" by a permission change that cannot work.
    pub insufficient: &'static [Grant],
    /// Where the fact is verified instead.
    pub verified_by: VerificationSurface,
}

impl DisclosureGate {
    /// Whether this gate provably withholds the fact from a credential with
    /// `capability`.
    ///
    /// A credential enumerated as read-only cannot hold a grant that writes, so
    /// the absence of the fact is explained and permanent on that surface. A
    /// write-capable credential may hold it, so an absent field is not evidence
    /// of the gate — something else went wrong, and a run that fell short is
    /// a run error, not a routed result. This is what stops the interactive
    /// session, which holds a write-capable credential, from excusing a field it
    /// should have been shown.
    #[must_use]
    pub fn withholds_from(&self, capability: CredentialCapability) -> bool {
        self.requires.writes() && capability != CredentialCapability::WriteCapable
    }

    /// Why the platform withholds the fact, as a sentence built from the
    /// declaration.
    #[must_use]
    pub fn rationale(&self) -> String {
        let mut rationale = format!(
            "GitHub discloses {} only to a credential with {}",
            self.fact, self.requires
        );
        if !self.insufficient.is_empty() {
            let names: Vec<&str> = self.insufficient.iter().map(|grant| grant.code()).collect();
            rationale.push_str(&format!(", and {} does not expose it", names.join(" or ")));
        }
        rationale.push_str(
            ", while the headless audit accepts only a credential it has proved cannot write",
        );
        rationale
    }
}

/// Merge behaviour is disclosed to write-capable credentials only.
///
/// `allow_squash_merge`, `allow_rebase_merge`, `allow_merge_commit`, and
/// `delete_branch_on_merge` are absent from the repository payload unless the
/// credential carries `contents: write`. `administration: read`, which reads as
/// though it should serve settings, does not expose them. The headless audit
/// proves its credential read-only before it runs, so these fields are
/// undisclosed on every headless run by construction rather than by accident.
pub const MERGE_SETTINGS_DISCLOSURE: DisclosureGate = DisclosureGate {
    fact: "a repository's merge settings",
    evidence_code: "merge_settings_unavailable",
    requires: Grant::CONTENTS_WRITE,
    insufficient: &[Grant::ADMINISTRATION_READ],
    verified_by: VerificationSurface::InteractiveSession,
};

/// Every declared disclosure gate.
pub const DISCLOSURE_GATES: &[&DisclosureGate] = &[&MERGE_SETTINGS_DISCLOSURE];

/// A rule's earliest lifecycle rung. This metadata does not select checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lifecycle {
    /// Before the end-of-seeding tag.
    Seeded,
    /// Development has started.
    Building,
    /// At least one release exists.
    Released,
    /// A stable release exists.
    Stable,
}

/// One configurable parameter and its compiled default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameter {
    /// The policy parameter name.
    pub name: &'static str,
    /// The literal default; strings permit only `{owner}` substitution.
    pub default: ParameterDefault,
}

/// Literal parameter defaults, with no predicates or executable computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterDefault {
    /// An unsigned integer.
    Integer(u64),
    /// A string, optionally containing `{owner}`.
    String(&'static str),
    /// A literal list of strings.
    Strings(&'static [&'static str]),
}

/// One registered rule definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleDefinition {
    /// The check definition id, for example `REPO-LIC-01`.
    pub id: &'static str,
    /// The check definition statement.
    pub statement: &'static str,
    /// The default severity.
    pub severity: Severity,
    /// The section the rule belongs to.
    pub section: Section,
    /// The parameters a policy may set, with their compiled defaults.
    pub params: &'static [Parameter],
    /// Inspection guidance authored with this rule.
    pub guidance: &'static str,
    /// The declared fix, including its delivery fix kind.
    pub fix: crate::fix::FixAvailability,
    /// The earliest lifecycle rung; existing rules apply from seeding.
    pub lifecycle: Lifecycle,
    observation: Observation,
    disclosure_gate: Option<&'static DisclosureGate>,
    unbuilt_reason: Option<&'static str>,
    api_gate: bool,
    owner_gate: bool,
    /// A check branch can require declared release units before it evaluates.
    release_units_gate: bool,
    /// Topic reference data required to enable this rule; an empty slice requires the map only.
    required_topic_categories: Option<&'static [&'static str]>,
}

/// Every registered rule definition, in conformance document order.
pub const RULES: &[RuleDefinition] = &[
    identity::repo_org_01::RULE,
    identity::repo_org_02::RULE,
    identity::repo_name_01::RULE,
    identity::repo_name_02::RULE,
    identity::repo_name_03::RULE,
    identity::repo_name_04::RULE,
    identity::repo_meta_01::RULE,
    identity::repo_meta_02::RULE,
    identity::repo_meta_03::RULE,
    identity::repo_meta_04::RULE,
    identity::repo_meta_05::RULE,
    identity::repo_meta_06::RULE,
    identity::repo_meta_07::RULE,
    identity::repo_meta_08::RULE,
    identity::repo_meta_09::RULE,
    identity::repo_meta_10::RULE,
    identity::repo_meta_11::RULE,
    identity::repo_meta_12::RULE,
    identity::repo_meta_13::RULE,
    licensing::repo_lic_01::RULE,
    licensing::repo_lic_02::RULE,
    licensing::repo_lic_03::RULE,
    licensing::repo_lic_04::RULE,
    licensing::repo_lic_05::RULE,
    licensing::repo_lic_06::RULE,
    files::repo_file_01::RULE,
    files::repo_file_02::RULE,
    files::repo_file_03::RULE,
    files::repo_file_04::RULE,
    files::repo_file_05::RULE,
    files::repo_file_06::RULE,
    files::repo_file_07::RULE,
    files::repo_file_08::RULE,
    files::repo_file_16::RULE,
    files::repo_file_17::RULE,
    files::repo_file_09::RULE,
    files::repo_file_10::RULE,
    files::repo_file_11::RULE,
    files::repo_file_12::RULE,
    files::repo_file_13::RULE,
    files::repo_file_14::RULE,
    files::repo_file_15::RULE,
    readme::repo_readme_01::RULE,
    readme::repo_readme_02::RULE,
    readme::repo_readme_03::RULE,
    readme::repo_readme_04::RULE,
    readme::repo_readme_05::RULE,
    readme::repo_readme_06::RULE,
    readme::repo_readme_07::RULE,
    readme::repo_readme_08::RULE,
    readme::repo_readme_09::RULE,
    git::repo_git_01::RULE,
    git::repo_git_02::RULE,
    git::repo_git_03::RULE,
    git::repo_git_13::RULE,
    git::repo_git_14::RULE,
    git::repo_git_04::RULE,
    git::repo_git_05::RULE,
    git::repo_git_06::RULE,
    git::repo_git_07::RULE,
    git::repo_git_08::RULE,
    git::repo_git_09::RULE,
    git::repo_git_10::RULE,
    automation::repo_task_01::RULE,
    automation::repo_task_02::RULE,
    automation::repo_task_03::RULE,
    automation::repo_task_04::RULE,
    automation::repo_task_05::RULE,
    automation::repo_task_06::RULE,
    automation::repo_ci_01::RULE,
    automation::repo_ci_02::RULE,
    automation::repo_ci_03::RULE,
    automation::repo_ci_04::RULE,
    automation::repo_ci_05::RULE,
    automation::repo_ci_06::RULE,
    automation::repo_ci_07::RULE,
    automation::repo_ci_08::RULE,
    automation::repo_ci_09::RULE,
    automation::repo_ci_10::RULE,
    automation::repo_cd_01::RULE,
    automation::repo_cd_02::RULE,
    automation::repo_cd_03::RULE,
    automation::repo_cd_04::RULE,
    automation::repo_cd_05::RULE,
    automation::repo_cd_06::RULE,
    automation::repo_cd_07::RULE,
    automation::repo_hook_01::RULE,
    automation::repo_hook_02::RULE,
    automation::repo_hook_03::RULE,
    automation::repo_hook_04::RULE,
    agent::repo_agent_01::RULE,
    agent::repo_agent_02::RULE,
    agent::repo_agent_03::RULE,
    agent::repo_agent_04::RULE,
    agent::repo_agent_05::RULE,
    docs::repo_docs_01::RULE,
    docs::repo_docs_02::RULE,
    docs::repo_docs_03::RULE,
    docs::repo_docs_04::RULE,
    docs::repo_docs_05::RULE,
    release::repo_rel_01::RULE,
    release::repo_rel_02::RULE,
    release::repo_rel_03::RULE,
    release::repo_rel_04::RULE,
    release::repo_rel_05::RULE,
    release::repo_rel_06::RULE,
    release::repo_rel_07::RULE,
    release::repo_rel_08::RULE,
    release::repo_tpl_01::RULE,
    classification::repo_prop_03::RULE,
    classification::repo_prop_04::RULE,
];

/// Look a check definition up by id.
#[must_use]
pub fn find(id: &str) -> Option<&'static RuleDefinition> {
    RULES.iter().find(|check| check.id == id)
}

/// Every rule definition in a section, in rules order.
#[must_use]
pub fn in_section(section: Section) -> Vec<&'static RuleDefinition> {
    RULES
        .iter()
        .filter(|check| check.section == section)
        .collect()
}

impl RuleDefinition {
    /// Whether the repository may override the organization rule.
    #[must_use]
    pub fn allow_override(&self) -> bool {
        self.id != "REPO-TPL-01"
    }

    #[must_use]
    pub fn needs_release_units(&self) -> bool {
        self.release_units_gate
    }

    #[must_use]
    pub fn required_topic_categories(&self) -> Option<&'static [&'static str]> {
        self.required_topic_categories
    }

    #[must_use]
    pub fn needs_repository_owner(&self) -> bool {
        self.owner_gate
    }
    /// API-only facts cannot be inferred from local file content.
    #[must_use]
    pub fn needs_github_api(&self) -> bool {
        self.observation == Observation::Platform || self.api_gate
    }

    /// The compiled default for a named parameter.
    #[must_use]
    pub fn parameter_default(&self, name: &str) -> Option<ParameterDefault> {
        self.params
            .iter()
            .find(|parameter| parameter.name == name)
            .map(|parameter| parameter.default)
    }

    /// The declared gate for a check that cannot yet decide the whole requirement.
    #[must_use]
    pub fn unbuilt_reason(&self) -> Option<&'static str> {
        self.unbuilt_reason
    }

    /// The platform disclosure gate standing between this rule and the audit's
    /// credential, when there is one.
    ///
    /// Declared here, per rule, so the classification has one home: the checks
    /// derive a routed record from this rather than knowing
    /// privately that they are special, the projections derive what they print
    /// from it, and a policy author reading `--list-rules` can see which rules
    /// no scheduled run will ever settle.
    ///
    /// Like [`Self::observation`] and fix classification, a gate is not
    /// part of the rules digest: it says which credential can look, not what
    /// the rule means, and a rule's statement is the same whoever is allowed to
    /// read the answer.
    #[must_use]
    pub fn disclosure_gate(&self) -> Option<&'static DisclosureGate> {
        self.disclosure_gate
    }

    /// What the rule observes.
    ///
    /// Declared here, per rule, and read everywhere — the audit gates
    /// platform rules on API availability from this, and every finding's
    /// `source` is derived from it. Like fix classification, the
    /// domain is not part of the rules digest: it describes where airlock
    /// looks, not what the rule means.
    #[must_use]
    pub fn observation(&self) -> Observation {
        self.observation
    }
}

/// The rules content digest.
///
/// SHA-256 over the sorted compiled requirement identities: id, statement,
/// severity, unbuilt reason, release-unit scope, and required topic categories.
/// Observation sources and credential boundaries are not part of this digest.
/// It travels in every audit result.
#[must_use]
pub fn digest() -> String {
    let mut tuples: Vec<String> = RULES.iter().map(requirement_identity).collect();
    tuples.sort();

    let mut hasher = Sha256::new();
    for tuple in tuples {
        hasher.update(tuple.as_bytes());
        hasher.update(b"\x1e");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn requirement_identity(check: &RuleDefinition) -> String {
    let topics = check
        .required_topic_categories
        .map_or("none".to_owned(), |categories| {
            format!("topics:{}", categories.join(","))
        });
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        check.id,
        check.statement,
        check.severity.code(),
        check.unbuilt_reason().unwrap_or_default(),
        check.release_units_gate,
        topics
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn requirement_identity_includes_scope_and_required_configuration() {
        let mut rule = *find("REPO-LIC-04").unwrap();
        let before = requirement_identity(&rule);
        rule.release_units_gate = false;
        assert_ne!(requirement_identity(&rule), before);
        let mut rule = *find("REPO-META-07").unwrap();
        let before = requirement_identity(&rule);
        rule.required_topic_categories = Some(&[]);
        let catalogue_only = requirement_identity(&rule);
        assert_ne!(catalogue_only, before);
        rule.required_topic_categories = None;
        assert_ne!(requirement_identity(&rule), catalogue_only);
    }

    #[test]
    fn every_check_definition_id_is_unique() {
        let ids: BTreeSet<&str> = RULES.iter().map(|check| check.id).collect();
        assert_eq!(ids.len(), RULES.len());
    }

    #[test]
    fn platform_rules_are_exactly_the_api_owned_facts() {
        let platform: Vec<&str> = RULES
            .iter()
            .filter(|check| check.observation() == Observation::Platform)
            .map(|check| check.id)
            .collect();
        assert_eq!(
            platform,
            [
                "REPO-ORG-01",
                "REPO-ORG-02",
                "REPO-NAME-01",
                "REPO-NAME-02",
                "REPO-NAME-03",
                "REPO-NAME-04",
                "REPO-META-13",
                "REPO-GIT-01",
                "REPO-GIT-02",
                "REPO-GIT-03",
                "REPO-GIT-14",
                "REPO-GIT-04",
                "REPO-GIT-05",
                "REPO-GIT-06",
                "REPO-GIT-07",
                "REPO-GIT-08",
                "REPO-GIT-09",
                "REPO-GIT-10",
                "REPO-REL-08",
            ]
        );
    }

    #[test]
    fn exactly_the_merge_behaviour_rules_declare_a_disclosure_gate() {
        // The drift guard. A rule joining this list stops being able to fail a
        // scheduled audit, so the list is stated here and a change to it is a
        // deliberate edit rather than a side effect.
        let gated: Vec<&str> = RULES
            .iter()
            .filter(|check| check.disclosure_gate().is_some())
            .map(|check| check.id)
            .collect();
        assert_eq!(
            gated,
            ["REPO-META-13", "REPO-GIT-04", "REPO-GIT-05", "REPO-GIT-06"]
        );
    }

    #[test]
    fn a_gated_rule_reads_platform_state_and_is_evaluated_mechanically() {
        // A gate is about which credential the platform answers. A judgment
        // rule has no credential in the story, and a file-tree rule is not
        // asking the platform anything, so either would be a declaration that
        // could not be true.
        for check in RULES {
            if check.disclosure_gate().is_some() {
                assert_eq!(check.observation(), Observation::Platform, "{}", check.id);
            }
        }
    }

    #[test]
    fn every_declared_gate_names_a_reachable_destination_and_a_grant_it_lacks() {
        for gate in DISCLOSURE_GATES {
            assert!(!gate.fact.trim().is_empty());
            assert!(!gate.evidence_code.trim().is_empty());
            assert!(Grant::ALL.contains(&gate.requires));
            assert!(VerificationSurface::ALL.contains(&gate.verified_by));
            assert!(
                !gate.verified_by.guidance().trim().is_empty(),
                "a destination with no guidance names nowhere to go"
            );
            for grant in gate.insufficient {
                assert!(Grant::ALL.contains(grant));
                assert_ne!(
                    *grant, gate.requires,
                    "a grant cannot both suffice and not suffice"
                );
            }
        }
    }

    #[test]
    fn a_gate_withholds_only_from_a_credential_that_cannot_hold_its_grant() {
        let gate = &MERGE_SETTINGS_DISCLOSURE;
        assert!(gate.requires.writes());
        assert!(gate.withholds_from(CredentialCapability::ReadOnly));
        assert!(gate.withholds_from(CredentialCapability::Unauthenticated));
        assert!(
            !gate.withholds_from(CredentialCapability::WriteCapable),
            "a credential that may hold the grant is not excused by the gate"
        );
    }

    #[test]
    fn a_gates_rationale_is_built_from_its_declaration() {
        let rationale = MERGE_SETTINGS_DISCLOSURE.rationale();
        assert!(rationale.contains(MERGE_SETTINGS_DISCLOSURE.fact));
        assert!(rationale.contains(Grant::CONTENTS_WRITE.code()));
        assert!(
            rationale.contains(Grant::ADMINISTRATION_READ.code()),
            "the grant that reads as though it should serve settings is named: {rationale}"
        );
    }

    #[test]
    fn a_disclosure_gate_is_not_part_of_the_rules_digest() {
        // The digest attests what every rule means, which is the contract a
        // policy binds to with `requires-rules`. Who is allowed to read the
        // answer is not part of the statement, exactly as the observation
        // domain and the fix classification are not.
        let before = digest();
        assert!(RULES.iter().any(|check| check.disclosure_gate().is_some()));
        assert_eq!(before, digest());
        for check in RULES {
            let tuple = requirement_identity(check);
            if let Some(gate) = check.disclosure_gate() {
                assert!(
                    !tuple.contains(gate.evidence_code),
                    "{} contributes its gate to the digest",
                    check.id
                );
            }
        }
    }

    #[test]
    fn grants_and_verification_surfaces_are_uniquely_coded() {
        let grants: BTreeSet<&str> = Grant::ALL.iter().map(|grant| grant.code()).collect();
        assert_eq!(grants.len(), Grant::ALL.len());
        let surfaces: BTreeSet<&str> = VerificationSurface::ALL
            .iter()
            .map(|surface| surface.code())
            .collect();
        assert_eq!(surfaces.len(), VerificationSurface::ALL.len());
    }

    #[test]
    fn every_check_definition_has_a_statement() {
        for check in RULES {
            assert!(!check.statement.trim().is_empty(), "{}", check.id);
        }
    }

    #[test]
    fn all_rules_keep_their_identity_and_lifecycle() {
        assert_eq!(RULES.len(), 111);
        assert!(RULES.iter().all(|rule| rule.lifecycle
            == match rule.id {
                "REPO-REL-08" => Lifecycle::Released,
                "REPO-TPL-01" => Lifecycle::Building,
                _ => Lifecycle::Seeded,
            }));
    }

    #[test]
    fn parameter_names_are_unique_within_each_rule() {
        for rule in RULES {
            let names: BTreeSet<_> = rule.params.iter().map(|parameter| parameter.name).collect();
            assert_eq!(names.len(), rule.params.len(), "{}", rule.id);
        }
    }

    #[test]
    fn the_digest_is_stable_and_prefixed() {
        let first = digest();
        assert!(first.starts_with("sha256:"));
        assert_eq!(first, digest());
    }

    #[test]
    fn sections_round_trip_through_their_codes() {
        for section in Section::ALL {
            assert_eq!(Section::parse(section.code()), Some(*section));
        }
    }

    #[test]
    fn severities_round_trip_through_their_codes() {
        for severity in Severity::ALL {
            assert_eq!(Severity::parse(severity.code()), Some(*severity));
        }
    }

    #[test]
    fn every_section_has_at_least_one_rule() {
        for section in Section::ALL {
            assert!(!in_section(*section).is_empty(), "{section}");
        }
    }
}
