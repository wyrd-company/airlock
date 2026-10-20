//! The fix model.
//!
//! Every registered rule declares, as data, what closing its gap takes: a
//! fix with a stable code, the change it would make, whether that
//! change is reversible, and the fix kind it travels in — or an explicit
//! statement that airlock offers no fix, with the reason. The fix kind is
//! declared in each rule module. Release-record model Gaps refine that
//! default by their compiled reason during report assembly; consumers read the
//! resulting classification without inferring a fix kind themselves.
//!
//! Classifying is not doing. Nothing in this module writes anything; it
//! describes what a fix *would* change so that the findings output,
//! the findings screen, and an agent work-list can all agree on what closing
//! each gap takes.
//!
//! Fix classification is deliberately *not* part of the rules
//! content digest. The digest attests what every rule means and how it is
//! evaluated — the contract a policy binds to with `requires-rules`.
//! Fix is airlock's answer to a gap, and a better answer must not
//! invalidate policy compatibility. Two binaries that agree on the digest
//! agree on what every rule means; they may still differ on how they would
//! close it.

use std::fmt::{self, Display};

use serde::{Serialize, Serializer};

/// A declared family of contextual actions that can address an observation.
///
/// Fix groups support display and cross-rule grouping. They are not the
/// consumer join key for a rule's fix: that identity and its delivery
/// fix kind live on [`FixDefinition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FixGroup(&'static str);

impl FixGroup {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl Display for FixGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Serialize for FixGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.code())
    }
}

macro_rules! fix_groups {
    ($($name:ident => $code:literal),+ $(,)?) => {
        impl FixGroup {
            $(
                #[doc = concat!("The `", $code, "` fix group.")]
                pub const $name: Self = Self($code);
            )+

            /// Every declared fix group.
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
        }

        #[cfg(test)]
        const DECLARED_ACTION_GROUPS: &[(&str, FixGroup)] = &[
            $((stringify!($name), FixGroup::$name)),+
        ];
    };
}

fix_groups! {
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

/// The fix kind a fix travels in: who can perform it, and through what
/// surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixKind {
    /// The same gap resolves to the same content in every repository. Airlock
    /// can close it headlessly and deliver the change as a pull request.
    Airlock,
    /// The fix is repository-specific file content — prose, configuration
    /// wired to this repository's toolchain. An agent authors it; a human
    /// reviews it.
    Agent,
    /// The fix is a repository or organisation setting behind the
    /// administration API. `administration: write` is indivisible, so this
    /// fix kind is human-only, behind the TUI.
    Operator,
}

impl FixKind {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            FixKind::Airlock => "airlock",
            FixKind::Agent => "agent",
            FixKind::Operator => "operator",
        }
    }

    /// Parse a fix kind from its machine-readable name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        FixKind::ALL
            .iter()
            .copied()
            .find(|fix_kind| fix_kind.code() == value)
    }

    /// Every fix kind.
    pub const ALL: &'static [FixKind] = &[FixKind::Airlock, FixKind::Agent, FixKind::Operator];
}

/// One rule's declared fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixDefinition {
    /// The per-rule consumer join key, unique across the rules.
    pub code: &'static str,
    /// The rule this fix closes.
    pub rule: &'static str,
    /// The fix kind the fix travels in.
    pub fix_kind: FixKind,
    /// What the fix would change.
    pub change: &'static str,
    /// Whether the change can be undone by a later change of mind.
    pub reversible: bool,
}

/// What airlock declares about closing one rule's gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixAvailability {
    /// Airlock declares a fix for the rule.
    Fix(FixDefinition),
    /// Airlock declares no fix for the rule, and says why.
    NotFixable {
        /// The rule the declaration is about.
        rule: &'static str,
        /// Why no fix is offered.
        reason: &'static str,
    },
}

impl FixAvailability {
    /// The rule this classification is about.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            FixAvailability::Fix(definition) => definition.rule,
            FixAvailability::NotFixable { rule, .. } => rule,
        }
    }

    /// The declared fix, when there is one.
    #[must_use]
    pub const fn fix(&self) -> Option<&FixDefinition> {
        match self {
            FixAvailability::Fix(definition) => Some(definition),
            FixAvailability::NotFixable { .. } => None,
        }
    }
}

pub(crate) const fn fix(
    code: &'static str,
    rule: &'static str,
    fix_kind: FixKind,
    change: &'static str,
    reversible: bool,
) -> FixAvailability {
    FixAvailability::Fix(FixDefinition {
        code,
        rule,
        fix_kind,
        change,
        reversible,
    })
}

pub(crate) const fn not_fixable(rule: &'static str, reason: &'static str) -> FixAvailability {
    FixAvailability::NotFixable { rule, reason }
}

/// Every rule's fix classification, in rules order.
///
/// A test asserts this table and [`crate::rules::RULES`] name exactly the
/// same rules in the same order: a rule cannot be registered without being
/// classified in its rule module.
pub const CLASSIFICATIONS: &[FixAvailability] = &classifications();

const fn classifications() -> [FixAvailability; crate::rules::RULES.len()] {
    let checks = crate::rules::RULES;
    let mut output = [checks[0].fix; crate::rules::RULES.len()];
    let mut index = 0;
    while index < checks.len() {
        output[index] = checks[index].fix;
        index += 1;
    }
    output
}

/// Look a rule's classification up by rule id.
#[must_use]
pub fn classify(rule: &str) -> Option<&'static FixAvailability> {
    CLASSIFICATIONS
        .iter()
        .find(|classification| classification.rule() == rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RULES;
    use std::collections::BTreeSet;

    #[test]
    fn fix_group_codes_are_unique_and_lower_snake() {
        let codes: Vec<&str> = FixGroup::ALL
            .iter()
            .map(|fix_group| fix_group.code())
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
    fn every_declared_fix_group_is_used_by_a_check() {
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

        for (constant, fix_group) in DECLARED_ACTION_GROUPS {
            assert!(
                check_sources.contains(&format!("FixGroup::{constant}")),
                "{constant} ({fix_group}) is declared but unused"
            );
        }
    }

    #[test]
    fn every_rule_is_classified_and_nothing_else_is() {
        let registered: Vec<&str> = RULES.iter().map(|check| check.id).collect();
        let classified: Vec<&str> = CLASSIFICATIONS.iter().map(FixAvailability::rule).collect();
        assert_eq!(
            classified, registered,
            "the classification table and the rules must name the same rules in the same order"
        );
    }

    #[test]
    fn fix_codes_are_unique() {
        let codes: Vec<&str> = CLASSIFICATIONS
            .iter()
            .filter_map(|classification| classification.fix())
            .map(|definition| definition.code)
            .collect();
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn fix_codes_are_lower_kebab() {
        for definition in CLASSIFICATIONS.iter().filter_map(FixAvailability::fix) {
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
                FixAvailability::Fix(definition) => {
                    assert!(!definition.change.trim().is_empty(), "{}", definition.rule);
                    assert!(!definition.code.trim().is_empty(), "{}", definition.rule);
                }
                FixAvailability::NotFixable { rule, reason } => {
                    assert!(!reason.trim().is_empty(), "{rule}");
                }
            }
        }
    }

    #[test]
    fn fix_kinds_round_trip_through_their_codes() {
        for fix_kind in FixKind::ALL {
            assert_eq!(FixKind::parse(fix_kind.code()), Some(*fix_kind));
        }
    }

    #[test]
    fn classify_finds_by_rule_id() {
        let classification = classify("REPO-LIC-01").expect("REPO-LIC-01 is registered");
        let definition = classification.fix().expect("has a fix");
        assert_eq!(definition.code, "add-license-file");
        assert_eq!(definition.fix_kind, FixKind::Airlock);
        assert!(classify("REPO-NOPE-99").is_none());
    }
}
