//! The remediation model.
//!
//! Every registered rule declares, as data, what closing its gap takes: a
//! remediation with a stable code, the change it would make, whether that
//! change is reversible, and the lane it travels in — or an explicit
//! statement that airlock offers no remediation, with the reason. The lane is
//! declared in each standard module. Release-record model Gaps refine that
//! default by their compiled reason during report assembly; consumers read the
//! resulting classification without inferring a lane themselves.
//!
//! Classifying is not doing. Nothing in this module writes anything; it
//! describes what a remediation *would* change so that the findings output,
//! the findings screen, and an agent work-list can all agree on what closing
//! each gap takes.
//!
//! Remediation classification is deliberately *not* part of the registry
//! content digest. The digest attests what every rule means and how it is
//! evaluated — the contract a policy binds to with `requires-registry`.
//! Remediation is airlock's answer to a gap, and a better answer must not
//! invalidate policy compatibility. Two binaries that agree on the digest
//! agree on what every rule means; they may still differ on how they would
//! close it.

use std::fmt::{self, Display};

use serde::{Serialize, Serializer};

/// A declared family of contextual actions that can address an observation.
///
/// Action groups support display and cross-rule grouping. They are not the
/// consumer join key for a rule's remediation: that identity and its delivery
/// lane live on [`RemediationDefinition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActionGroup(&'static str);

impl ActionGroup {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl Display for ActionGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Serialize for ActionGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.code())
    }
}

macro_rules! action_groups {
    ($($name:ident => $code:literal),+ $(,)?) => {
        impl ActionGroup {
            $(
                #[doc = concat!("The `", $code, "` action group.")]
                pub const $name: Self = Self($code);
            )+

            /// Every declared action group.
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
        }

        #[cfg(test)]
        const DECLARED_ACTION_GROUPS: &[(&str, ActionGroup)] = &[
            $((stringify!($name), ActionGroup::$name)),+
        ];
    };
}

action_groups! {
    APPLY_ACCEPTED_TEMPLATE => "apply_accepted_template",
    ADD_CD_CONCURRENCY => "add_cd_concurrency",
    ADD_CHANGELOG => "add_changelog",
    ADD_CI_WORKFLOW => "add_ci_workflow",
    ADD_COMMIT_MSG => "add_commit_msg",
    ADD_CONCURRENCY => "add_concurrency",
    ADD_DEVCONTAINER => "add_devcontainer",
    ADD_FILE => "add_file",
    ADD_LEFTHOOK => "add_lefthook",
    ADD_PRE_COMMIT => "add_pre_commit",
    ADD_AUDIT_WORKFLOW => "add_audit_workflow",
    ADD_SYMLINK => "add_symlink",
    ADD_TASKFILE => "add_taskfile",
    ADD_TITLE_CHECK => "add_title_check",
    ADD_TOPIC => "add_topic",
    ADD_UNIT_TASKFILE => "add_unit_taskfile",
    ADJUST_TOPICS => "adjust_topics",
    ALIGN_INCLUDE_NAMESPACES => "align_include_namespaces",
    APPLY_ORG_RULESET => "apply_org_ruleset",
    CATALOGUE_TOPIC => "catalogue_topic",
    CHANGE_REPOSITORY_SETTING => "change_repository_setting",
    CHOOSE_ONE_LICENSE => "choose_one_license",
    COMPLETE_PRE_COMMIT => "complete_pre_commit",
    CORRECT_MERGE_SETTINGS => "correct_merge_settings",
    CORRECT_TAG_PATTERN => "correct_tag_pattern",
    DECLARE_DESCRIPTION => "declare_description",
    DECLARE_JOB_PERMISSIONS => "declare_job_permissions",
    DECLARE_LICENSE => "declare_license",
    DECLARE_MERGE_SETTINGS => "declare_merge_settings",
    DECLARE_RELEASE_UNITS => "declare_release_units",
    DECLARE_TOPICS => "declare_topics",
    DEFAULT_DENY_PERMISSIONS => "default_deny_permissions",
    DEFINE_TASKS => "define_tasks",
    DISPATCH_ON_PINNED_SHA => "dispatch_on_pinned_sha",
    DISPATCH_PUBLICATION => "dispatch_publication",
    DO_NOT_CANCEL_DELIVERY => "do_not_cancel_delivery",
    EXTEND_ORG_PRESET => "extend_org_preset",
    GRANT_PERMISSION => "grant_permission",
    LIGHTEN_PRE_PUSH => "lighten_pre_push",
    MOVE_APP_IDENTITY => "move_app_identity",
    MOVE_ROOT_UNIT => "move_root_unit",
    NORMALISE_LINE_ENDINGS => "normalise_line_endings",
    PIN_ACTION => "pin_action",
    PLAN_GATE => "plan_gate",
    RELINK_CLAUDE_MD => "relink_claude_md",
    REMOVE_CODEOWNERS => "remove_codeowners",
    REMOVE_CUSTOM_PROPERTIES => "remove_custom_properties",
    REMOVE_HARNESS_CONFIG => "remove_harness_config",
    REMOVE_ORG_TOPIC => "remove_org_topic",
    REMOVE_PROPERTY_WRITES => "remove_property_writes",
    REMOVE_PULL_REQUEST_TARGET => "remove_pull_request_target",
    REMOVE_ROOT_CHANGELOG => "remove_root_changelog",
    REMOVE_VISIBILITY => "remove_visibility",
    RENAME_DEFAULT_BRANCH => "rename_default_branch",
    RENAME_REPOSITORY => "rename_repository",
    RENAME_TASKFILE => "rename_taskfile",
    REPLACE_ENTRY => "replace_entry",
    REPLACE_SYMLINK => "replace_symlink",
    REPLACE_WITH_SYMLINK => "replace_with_symlink",
    RETAG_WITHOUT_PREFIX => "retag_without_prefix",
    REWRITE_OR_PREVENT_MERGES => "rewrite_or_prevent_merges",
    RUN_ALIGN => "run_align",
    SCOPE_TAGS => "scope_tags",
    SUPPLY_AIRLOCK_TOKEN => "supply_airlock_token",
    SET_INCLUDE_DIR => "set_include_dir",
    SHORTEN_DESCRIPTION => "shorten_description",
    SINGLE_SENTENCE_DESCRIPTION => "single_sentence_description",
    SPLIT_RELEASE_FROM_DELIVERY => "split_release_from_delivery",
    TIGHTEN_RULESET => "tighten_ruleset",
    TRIGGER_ON_PULL_REQUEST => "trigger_on_pull_request",
    WRAP_IN_TASK => "wrap_in_task",
}

/// The lane a remediation travels in: who can perform it, and through what
/// surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// The same gap resolves to the same content in every repository. Airlock
    /// can close it headlessly and deliver the change as a pull request.
    DeterministicFile,
    /// The fix is repository-specific file content — prose, configuration
    /// wired to this repository's toolchain. An agent authors it; a human
    /// reviews it.
    JudgmentFile,
    /// The fix is a repository or organisation setting behind the
    /// administration API. `administration: write` is indivisible, so this
    /// lane is human-only, behind the TUI.
    OperatorSetting,
}

impl Lane {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Lane::DeterministicFile => "deterministic-file",
            Lane::JudgmentFile => "judgment-file",
            Lane::OperatorSetting => "operator-setting",
        }
    }

    /// Parse a lane from its machine-readable name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Lane::ALL.iter().copied().find(|lane| lane.code() == value)
    }

    /// Every lane.
    pub const ALL: &'static [Lane] = &[
        Lane::DeterministicFile,
        Lane::JudgmentFile,
        Lane::OperatorSetting,
    ];
}

/// One rule's declared remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemediationDefinition {
    /// The per-rule consumer join key, unique across the registry.
    pub code: &'static str,
    /// The rule this remediation closes.
    pub rule: &'static str,
    /// The lane the remediation travels in.
    pub lane: Lane,
    /// What the remediation would change.
    pub change: &'static str,
    /// Whether the change can be undone by a later change of mind.
    pub reversible: bool,
}

/// What airlock declares about closing one rule's gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Airlock declares a remediation for the rule.
    Remediation(RemediationDefinition),
    /// Airlock declares no remediation for the rule, and says why.
    NotRemediable {
        /// The rule the declaration is about.
        rule: &'static str,
        /// Why no remediation is offered.
        reason: &'static str,
    },
}

impl Classification {
    /// The rule this classification is about.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Classification::Remediation(definition) => definition.rule,
            Classification::NotRemediable { rule, .. } => rule,
        }
    }

    /// The declared remediation, when there is one.
    #[must_use]
    pub const fn remediation(&self) -> Option<&RemediationDefinition> {
        match self {
            Classification::Remediation(definition) => Some(definition),
            Classification::NotRemediable { .. } => None,
        }
    }
}

pub(crate) const fn remediation(
    code: &'static str,
    rule: &'static str,
    lane: Lane,
    change: &'static str,
    reversible: bool,
) -> Classification {
    Classification::Remediation(RemediationDefinition {
        code,
        rule,
        lane,
        change,
        reversible,
    })
}

pub(crate) const fn not_remediable(rule: &'static str, reason: &'static str) -> Classification {
    Classification::NotRemediable { rule, reason }
}

/// Every rule's remediation classification, in registry order.
///
/// A test asserts this table and [`crate::registry::CHECKS`] name exactly the
/// same rules in the same order: a rule cannot be registered without being
/// classified in its standard module.
pub const CLASSIFICATIONS: &[Classification] = &classifications();

const fn classifications() -> [Classification; crate::registry::CHECKS.len()] {
    let checks = crate::registry::CHECKS;
    let mut output = [checks[0].remediation; crate::registry::CHECKS.len()];
    let mut index = 0;
    while index < checks.len() {
        output[index] = checks[index].remediation;
        index += 1;
    }
    output
}

/// Look a rule's classification up by rule id.
#[must_use]
pub fn classify(rule: &str) -> Option<&'static Classification> {
    CLASSIFICATIONS
        .iter()
        .find(|classification| classification.rule() == rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::CHECKS;
    use std::collections::BTreeSet;

    #[test]
    fn action_group_codes_are_unique_and_lower_snake() {
        let codes: Vec<&str> = ActionGroup::ALL
            .iter()
            .map(|action_group| action_group.code())
            .collect();
        let unique: BTreeSet<&str> = codes.iter().copied().collect();

        assert_eq!(codes.len(), unique.len());
        for code in codes {
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{code}"
            );
        }
    }

    #[test]
    fn every_declared_action_group_is_used_by_a_check() {
        let check_sources = [
            include_str!("checks/mod.rs"),
            include_str!("checks/classification.rs"),
            include_str!("checks/files.rs"),
            include_str!("checks/git.rs"),
            include_str!("checks/identity.rs"),
            include_str!("checks/licensing.rs"),
            include_str!("checks/release.rs"),
            include_str!("checks/template_identity.rs"),
            include_str!("checks/automation/delivery.rs"),
            include_str!("checks/automation/hooks.rs"),
            include_str!("checks/automation/taskfile.rs"),
            include_str!("checks/automation/workflows.rs"),
        ]
        .join("\n");

        for (constant, action_group) in DECLARED_ACTION_GROUPS {
            assert!(
                check_sources.contains(&format!("ActionGroup::{constant}")),
                "{constant} ({action_group}) is declared but unused"
            );
        }
    }

    #[test]
    fn every_rule_is_classified_and_nothing_else_is() {
        let registered: Vec<&str> = CHECKS.iter().map(|check| check.id).collect();
        let classified: Vec<&str> = CLASSIFICATIONS.iter().map(Classification::rule).collect();
        assert_eq!(
            classified, registered,
            "the classification table and the registry must name the same rules in the same order"
        );
    }

    #[test]
    fn remediation_codes_are_unique() {
        let codes: Vec<&str> = CLASSIFICATIONS
            .iter()
            .filter_map(|classification| classification.remediation())
            .map(|definition| definition.code)
            .collect();
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn remediation_codes_are_lower_kebab() {
        for definition in CLASSIFICATIONS
            .iter()
            .filter_map(Classification::remediation)
        {
            assert!(
                definition
                    .code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{}",
                definition.code
            );
        }
    }

    #[test]
    fn every_classification_says_something() {
        for classification in CLASSIFICATIONS {
            match classification {
                Classification::Remediation(definition) => {
                    assert!(!definition.change.trim().is_empty(), "{}", definition.rule);
                    assert!(!definition.code.trim().is_empty(), "{}", definition.rule);
                }
                Classification::NotRemediable { rule, reason } => {
                    assert!(!reason.trim().is_empty(), "{rule}");
                }
            }
        }
    }

    #[test]
    fn lanes_round_trip_through_their_codes() {
        for lane in Lane::ALL {
            assert_eq!(Lane::parse(lane.code()), Some(*lane));
        }
    }

    #[test]
    fn classify_finds_by_rule_id() {
        let classification = classify("REPO-LIC-01").expect("REPO-LIC-01 is registered");
        let definition = classification.remediation().expect("has a remediation");
        assert_eq!(definition.code, "add-license-file");
        assert_eq!(definition.lane, Lane::DeterministicFile);
        assert!(classify("REPO-NOPE-99").is_none());
    }
}
