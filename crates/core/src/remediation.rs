//! The remediation model.
//!
//! Every registered rule declares, as data, what closing its gap takes: a
//! remediation with a stable code, the change it would make, whether that
//! change is reversible, and the lane it travels in — or an explicit
//! statement that airlock offers no remediation, with the reason. The lane is
//! declared here, once per rule, and read everywhere; no consumer infers it
//! from context.
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
    DISABLE_OR_WAIT => "disable_or_wait",
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

const fn remediation(
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

const fn not_remediable(rule: &'static str, reason: &'static str) -> Classification {
    Classification::NotRemediable { rule, reason }
}

/// Every rule's remediation classification, in registry order.
///
/// A test asserts this table and [`crate::registry::CHECKS`] name exactly the
/// same rules in the same order: a rule cannot be registered without being
/// classified here.
pub const CLASSIFICATIONS: &[Classification] = &[
    remediation(
        "transfer-repository",
        "REPO-ORG-01",
        Lane::OperatorSetting,
        "Transfer the repository to the org its audience implies.",
        true,
    ),
    not_remediable(
        "REPO-ORG-02",
        "Satisfied by a human's considered judgment; there is no artifact to change.",
    ),
    remediation(
        "rename-repository-kebab",
        "REPO-NAME-01",
        Lane::OperatorSetting,
        "Rename the repository to lower-kebab-case.",
        true,
    ),
    remediation(
        "rename-repository-undotted",
        "REPO-NAME-02",
        Lane::OperatorSetting,
        "Rename the repository so only a deployable site named for its hostname carries a dot.",
        true,
    ),
    remediation(
        "rename-repository-family-prefix",
        "REPO-NAME-03",
        Lane::OperatorSetting,
        "Rename the repository to carry its product family prefix.",
        true,
    ),
    remediation(
        "align-family-prefix-and-topic",
        "REPO-NAME-04",
        Lane::JudgmentFile,
        "Align the declared family topic with the name's family prefix.",
        true,
    ),
    remediation(
        "declare-description",
        "REPO-META-01",
        Lane::JudgmentFile,
        "Add a `description` to `.github/repo-settings.yml`.",
        true,
    ),
    remediation(
        "rewrite-description-length",
        "REPO-META-02",
        Lane::JudgmentFile,
        "Rewrite the declared description as one sentence within the length budget.",
        true,
    ),
    remediation(
        "expand-description-acronyms",
        "REPO-META-03",
        Lane::JudgmentFile,
        "Rewrite the declared description to expand each acronym on first use.",
        true,
    ),
    remediation(
        "remove-description-self-deprecation",
        "REPO-META-04",
        Lane::JudgmentFile,
        "Rewrite the declared description without self-deprecation.",
        true,
    ),
    remediation(
        "align-description-and-readme",
        "REPO-META-05",
        Lane::JudgmentFile,
        "Align the declared description with the README's opening line.",
        true,
    ),
    remediation(
        "adjust-topic-count",
        "REPO-META-06",
        Lane::JudgmentFile,
        "Add or remove declared topics to land within the required count.",
        true,
    ),
    remediation(
        "add-artifact-and-ecosystem-topics",
        "REPO-META-07",
        Lane::JudgmentFile,
        "Add an artifact-type and an ecosystem term to the declared topics.",
        true,
    ),
    remediation(
        "add-family-topic",
        "REPO-META-08",
        Lane::JudgmentFile,
        "Add the product family topic to the declared topics.",
        true,
    ),
    not_remediable(
        "REPO-META-09",
        "The fix is an edit to the organisation's topic registry, which lives outside the audited repository.",
    ),
    remediation(
        "remove-org-name-topics",
        "REPO-META-10",
        Lane::DeterministicFile,
        "Remove org-name topics from the declared topics.",
        true,
    ),
    remediation(
        "declare-merge-settings",
        "REPO-META-11",
        Lane::DeterministicFile,
        "Declare squash and rebase enabled, merge commits disabled, and head-branch auto-delete in `.github/repo-settings.yml`.",
        true,
    ),
    remediation(
        "remove-visibility-field",
        "REPO-META-12",
        Lane::DeterministicFile,
        "Remove the `visibility` field from `.github/repo-settings.yml`.",
        true,
    ),
    remediation(
        "align-live-settings",
        "REPO-META-13",
        Lane::OperatorSetting,
        "Align live GitHub metadata to the declared file.",
        true,
    ),
    remediation(
        "add-license-file",
        "REPO-LIC-01",
        Lane::DeterministicFile,
        "Add a `LICENSE` file carrying the default Apache-2.0 licence; a category-specific licence is REPO-LIC-02's judgment.",
        false,
    ),
    remediation(
        "replace-license",
        "REPO-LIC-02",
        Lane::JudgmentFile,
        "Replace the licence with the one the repository's category calls for.",
        false,
    ),
    remediation(
        "replace-dual-license",
        "REPO-LIC-03",
        Lane::JudgmentFile,
        "Replace the dual `MIT OR Apache-2.0` licence with the single licence the category calls for.",
        false,
    ),
    remediation(
        "declare-package-license",
        "REPO-LIC-04",
        Lane::DeterministicFile,
        "Declare the repository licence in the package metadata of each publishing release unit.",
        true,
    ),
    remediation(
        "state-packaging-license-scope",
        "REPO-LIC-05",
        Lane::JudgmentFile,
        "State in the README that the licence covers packaging, not payload.",
        true,
    ),
    remediation(
        "record-license-choice-reason",
        "REPO-LIC-06",
        Lane::JudgmentFile,
        "Record the reason for the non-default licence in the README or a decision record.",
        true,
    ),
    remediation(
        "add-readme",
        "REPO-FILE-01",
        Lane::JudgmentFile,
        "Write a `README.md` for this repository.",
        true,
    ),
    remediation(
        "add-contributing",
        "REPO-FILE-02",
        Lane::JudgmentFile,
        "Write a repository-level `CONTRIBUTING.md`.",
        true,
    ),
    remediation(
        "add-gitignore",
        "REPO-FILE-03",
        Lane::JudgmentFile,
        "Add an ecosystem-appropriate `.gitignore`.",
        true,
    ),
    remediation(
        "add-gitattributes",
        "REPO-FILE-04",
        Lane::DeterministicFile,
        "Add a `.gitattributes` that normalises line endings.",
        true,
    ),
    remediation(
        "add-editorconfig",
        "REPO-FILE-05",
        Lane::DeterministicFile,
        "Add the standard `.editorconfig`.",
        true,
    ),
    remediation(
        "add-taskfile",
        "REPO-FILE-06",
        Lane::JudgmentFile,
        "Add a lowercase `taskfile.yml` wired to this repository's toolchain.",
        true,
    ),
    remediation(
        "add-ci-workflow",
        "REPO-FILE-07",
        Lane::DeterministicFile,
        "Add the standard CI workflow: triggered on pull request, running `task check`.",
        true,
    ),
    remediation(
        "add-renovate-config",
        "REPO-FILE-08",
        Lane::DeterministicFile,
        "Add `.github/renovate.json` extending the org preset.",
        true,
    ),
    remediation(
        "add-repo-settings",
        "REPO-FILE-16",
        Lane::JudgmentFile,
        "Add `.github/repo-settings.yml` declaring this repository's metadata.",
        true,
    ),
    remediation(
        "add-audit-workflow",
        "REPO-FILE-17",
        Lane::DeterministicFile,
        "Add the standard scheduled, on-demand `.github/workflows/audit.yml`.",
        true,
    ),
    remediation(
        "add-lefthook-config",
        "REPO-FILE-09",
        Lane::DeterministicFile,
        "Add the standard `.config/lefthook.yml`.",
        true,
    ),
    remediation(
        "add-devcontainer",
        "REPO-FILE-10",
        Lane::JudgmentFile,
        "Add a `.devcontainer/` for this repository's toolchain.",
        true,
    ),
    remediation(
        "add-agents-file",
        "REPO-FILE-11",
        Lane::JudgmentFile,
        "Write an `AGENTS.md` for this repository.",
        true,
    ),
    remediation(
        "add-claude-symlink",
        "REPO-FILE-12",
        Lane::DeterministicFile,
        "Add `CLAUDE.md` as a symlink to `AGENTS.md`.",
        true,
    ),
    remediation(
        "remove-agent-harness-config",
        "REPO-FILE-13",
        Lane::DeterministicFile,
        "Remove committed agent harness configuration directories.",
        true,
    ),
    remediation(
        "remove-codeowners",
        "REPO-FILE-14",
        Lane::DeterministicFile,
        "Remove the `CODEOWNERS` file.",
        true,
    ),
    remediation(
        "remove-duplicated-health-files",
        "REPO-FILE-15",
        Lane::JudgmentFile,
        "Remove community health files the org already provides, unless the local copy is deliberate.",
        true,
    ),
    remediation(
        "write-readme-opening",
        "REPO-README-01",
        Lane::JudgmentFile,
        "Open the README with a title and a one-line statement of what it is.",
        true,
    ),
    remediation(
        "add-readme-badges",
        "REPO-README-02",
        Lane::JudgmentFile,
        "Add badges to the README.",
        true,
    ),
    remediation(
        "write-install-section",
        "REPO-README-03",
        Lane::JudgmentFile,
        "Write an installation section covering every supported channel.",
        true,
    ),
    remediation(
        "write-quickstart-section",
        "REPO-README-04",
        Lane::JudgmentFile,
        "Write a quickstart with at least one real, runnable example.",
        true,
    ),
    remediation(
        "add-animated-demo",
        "REPO-README-05",
        Lane::JudgmentFile,
        "Record and embed an animated demo.",
        true,
    ),
    remediation(
        "commit-tape-source",
        "REPO-README-06",
        Lane::JudgmentFile,
        "Commit the demo's `.tape` source.",
        true,
    ),
    remediation(
        "trim-prerequisites",
        "REPO-README-07",
        Lane::JudgmentFile,
        "Trim prerequisites to the non-obvious.",
        true,
    ),
    remediation(
        "remove-license-section",
        "REPO-README-08",
        Lane::JudgmentFile,
        "Remove the README's license section.",
        true,
    ),
    remediation(
        "remove-contributing-section",
        "REPO-README-09",
        Lane::JudgmentFile,
        "Remove the README's contributing section.",
        true,
    ),
    remediation(
        "set-default-branch-main",
        "REPO-GIT-01",
        Lane::OperatorSetting,
        "Rename the default branch to `main`.",
        true,
    ),
    remediation(
        "attach-org-rulesets",
        "REPO-GIT-02",
        Lane::OperatorSetting,
        "Attach organization-sourced rulesets to the default branch.",
        true,
    ),
    remediation(
        "tighten-org-rulesets",
        "REPO-GIT-03",
        Lane::OperatorSetting,
        "Configure the rulesets to require pull requests, allow only squash and rebase, and require linear history.",
        true,
    ),
    remediation(
        "rename-app-credentials",
        "REPO-GIT-13",
        Lane::OperatorSetting,
        "Rename the GitHub App identity to an `<APP>_APP_ID` variable and its private key to an `<APP>_APP_PRIVATE_KEY` secret.",
        true,
    ),
    remediation(
        "rename-task-named-credentials",
        "REPO-GIT-14",
        Lane::OperatorSetting,
        "Rename secrets and variables after what they are, not the task that introduced them.",
        true,
    ),
    remediation(
        "disable-merge-commits",
        "REPO-GIT-04",
        Lane::OperatorSetting,
        "Disable merge commits in the live repository settings.",
        true,
    ),
    remediation(
        "enable-squash-merge",
        "REPO-GIT-05",
        Lane::OperatorSetting,
        "Enable squash merge in the live repository settings.",
        true,
    ),
    remediation(
        "enable-head-branch-auto-delete",
        "REPO-GIT-06",
        Lane::OperatorSetting,
        "Enable auto-delete of head branches on merge.",
        true,
    ),
    remediation(
        "disable-unused-features",
        "REPO-GIT-07",
        Lane::OperatorSetting,
        "Turn off wikis, projects, and discussions that are not deliberately used.",
        true,
    ),
    not_remediable(
        "REPO-GIT-08",
        "Closing it means deleting and recreating published tags — history surgery airlock does not automate.",
    ),
    not_remediable(
        "REPO-GIT-09",
        "Closing it means re-tagging published releases — history surgery airlock does not automate.",
    ),
    not_remediable(
        "REPO-GIT-10",
        "Closing it means rewriting published history, which airlock does not automate.",
    ),
    remediation(
        "add-core-tasks",
        "REPO-TASK-01",
        Lane::JudgmentFile,
        "Add `test`, `lint`, `format`, and `check` tasks wired to this repository's toolchain.",
        true,
    ),
    remediation(
        "decide-build-and-dev-tasks",
        "REPO-TASK-02",
        Lane::JudgmentFile,
        "Decide whether `build` and `dev` apply, and add them where they do.",
        true,
    ),
    remediation(
        "align-check-with-ci",
        "REPO-TASK-03",
        Lane::JudgmentFile,
        "Make `task check` run everything CI runs.",
        true,
    ),
    remediation(
        "add-release-unit-taskfiles",
        "REPO-TASK-04",
        Lane::JudgmentFile,
        "Add a `taskfile.yml` at each release unit's path.",
        true,
    ),
    remediation(
        "set-include-dirs",
        "REPO-TASK-05",
        Lane::DeterministicFile,
        "Set `dir:` on every taskfile include.",
        true,
    ),
    remediation(
        "align-include-namespaces",
        "REPO-TASK-06",
        Lane::DeterministicFile,
        "Rename include namespaces to match release unit ids.",
        true,
    ),
    remediation(
        "add-pull-request-trigger",
        "REPO-CI-01",
        Lane::DeterministicFile,
        "Add a `pull_request` trigger to the CI workflow.",
        true,
    ),
    remediation(
        "empty-workflow-permissions",
        "REPO-CI-02",
        Lane::DeterministicFile,
        "Set workflow-level `permissions:` to `{}`.",
        true,
    ),
    remediation(
        "scope-job-permissions",
        "REPO-CI-03",
        Lane::JudgmentFile,
        "Declare on each job only the permissions it needs.",
        true,
    ),
    remediation(
        "pin-actions-to-shas",
        "REPO-CI-04",
        Lane::DeterministicFile,
        "Pin every action to a full commit SHA with a version comment.",
        true,
    ),
    remediation(
        "replace-pull-request-target",
        "REPO-CI-05",
        Lane::JudgmentFile,
        "Replace the `pull_request_target` trigger with a safe design.",
        true,
    ),
    remediation(
        "add-ci-concurrency-group",
        "REPO-CI-06",
        Lane::DeterministicFile,
        "Add a `concurrency` group with `cancel-in-progress` covering pull requests.",
        true,
    ),
    remediation(
        "move-commands-into-tasks",
        "REPO-CI-07",
        Lane::JudgmentFile,
        "Move raw workflow commands into tasks and invoke those.",
        true,
    ),
    remediation(
        "add-title-check",
        "REPO-CI-08",
        Lane::DeterministicFile,
        "Add the standard pull request title check workflow; marking it required is the rulesets' operator work.",
        true,
    ),
    remediation(
        "supply-airlock-token",
        "REPO-CI-09",
        Lane::DeterministicFile,
        "Supply `secrets.AIRLOCK_TOKEN` to the canonical Airlock audit action as `AIRLOCK_TOKEN`.",
        true,
    ),
    remediation(
        "remove-workflow-settings-writes",
        "REPO-CI-10",
        Lane::JudgmentFile,
        "Remove repository-settings mutations from every workflow.",
        true,
    ),
    remediation(
        "add-cd-workflow",
        "REPO-CD-01",
        Lane::JudgmentFile,
        "Add a `.github/workflows/cd.yml` delivering what this repository ships.",
        true,
    ),
    remediation(
        "add-tag-trigger",
        "REPO-CD-02",
        Lane::DeterministicFile,
        "Trigger CD on tags matching the release tag pattern.",
        true,
    ),
    remediation(
        "add-push-trigger",
        "REPO-CD-03",
        Lane::DeterministicFile,
        "Trigger CD on push to the default branch.",
        true,
    ),
    remediation(
        "set-cd-concurrency",
        "REPO-CD-04",
        Lane::DeterministicFile,
        "Set CD `concurrency` with `cancel-in-progress: false`.",
        true,
    ),
    remediation(
        "restrict-dispatch-to-redelivery",
        "REPO-CD-05",
        Lane::JudgmentFile,
        "Restrict the CD `workflow_dispatch` to re-delivering an existing tag.",
        true,
    ),
    remediation(
        "assert-credentials-up-front",
        "REPO-CD-06",
        Lane::JudgmentFile,
        "Assert every required publication credential before CD does any work.",
        true,
    ),
    remediation(
        "separate-release-and-delivery",
        "REPO-CD-07",
        Lane::JudgmentFile,
        "Split release creation and delivery into separate workflows.",
        true,
    ),
    remediation(
        "configure-pre-commit-hook",
        "REPO-HOOK-01",
        Lane::DeterministicFile,
        "Configure `pre-commit` to run `format` and `lint` on staged files only.",
        true,
    ),
    remediation(
        "configure-commit-msg-hook",
        "REPO-HOOK-02",
        Lane::DeterministicFile,
        "Configure `commit-msg` to validate conventional commit format.",
        true,
    ),
    remediation(
        "configure-pre-push-hook",
        "REPO-HOOK-03",
        Lane::DeterministicFile,
        "Configure `pre-push` to run nothing or lint only.",
        true,
    ),
    remediation(
        "invoke-tasks-from-hooks",
        "REPO-HOOK-04",
        Lane::JudgmentFile,
        "Point hooks at tasks instead of raw commands.",
        true,
    ),
    remediation(
        "write-agents-coverage",
        "REPO-AGENT-01",
        Lane::JudgmentFile,
        "Cover in `AGENTS.md` what the repository is, commands by reference, conventions, what not to touch, and where docs live.",
        true,
    ),
    remediation(
        "remove-discoverable-agents-content",
        "REPO-AGENT-02",
        Lane::JudgmentFile,
        "Remove from `AGENTS.md` anything discoverable by reading the repository.",
        true,
    ),
    remediation(
        "deduplicate-agents-content",
        "REPO-AGENT-03",
        Lane::JudgmentFile,
        "Remove `AGENTS.md` content that restates the README or `CONTRIBUTING.md`.",
        true,
    ),
    remediation(
        "trim-contributing-commands",
        "REPO-AGENT-04",
        Lane::JudgmentFile,
        "Trim `CONTRIBUTING.md` command sequences down to `task check`.",
        true,
    ),
    remediation(
        "mark-generated-directories",
        "REPO-AGENT-05",
        Lane::JudgmentFile,
        "Mark generated directories `linguist-generated=true` in `.gitattributes`.",
        true,
    ),
    remediation(
        "move-user-facing-docs",
        "REPO-DOCS-01",
        Lane::JudgmentFile,
        "Move user-facing pages to the top level of `docs/`.",
        true,
    ),
    remediation(
        "move-engineering-artifacts",
        "REPO-DOCS-02",
        Lane::JudgmentFile,
        "Move engineering artifacts into `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/`.",
        true,
    ),
    remediation(
        "rename-artifact-files",
        "REPO-DOCS-03",
        Lane::JudgmentFile,
        "Rename artifact files to lower-kebab slugs without type prefixes or `id:` fields.",
        true,
    ),
    remediation(
        "add-docs-manifest",
        "REPO-DOCS-04",
        Lane::JudgmentFile,
        "Add `docs/docs.yml` for publication to `wyrd.foo`.",
        true,
    ),
    remediation(
        "conform-yaml-to-schema",
        "REPO-DOCS-05",
        Lane::JudgmentFile,
        "Fix schema-bound YAML artifacts to follow their schema.",
        true,
    ),
    remediation(
        "declare-release-units",
        "REPO-REL-01",
        Lane::JudgmentFile,
        "Add `.intentional/config.yml` declaring this repository's release units.",
        true,
    ),
    remediation(
        "add-unit-changelogs",
        "REPO-REL-02",
        Lane::DeterministicFile,
        "Add a `CHANGELOG.md` skeleton at each release unit's declared path.",
        true,
    ),
    remediation(
        "remove-root-changelog",
        "REPO-REL-03",
        Lane::DeterministicFile,
        "Remove the root aggregate changelog.",
        true,
    ),
    remediation(
        "redesign-release-trigger",
        "REPO-REL-04",
        Lane::JudgmentFile,
        "Make release a `workflow_dispatch` on a pinned source SHA.",
        true,
    ),
    remediation(
        "assert-sha-is-main",
        "REPO-REL-05",
        Lane::JudgmentFile,
        "Assert in the release workflow that the pinned SHA equals current `main`.",
        true,
    ),
    remediation(
        "assert-ci-passed-for-sha",
        "REPO-REL-06",
        Lane::JudgmentFile,
        "Assert in the release workflow a successful push-event CI run for exactly that SHA.",
        true,
    ),
    remediation(
        "remove-merge-publish",
        "REPO-REL-07",
        Lane::JudgmentFile,
        "Remove any workflow that publishes automatically on merge.",
        true,
    ),
    remediation(
        "remove-custom-property-values",
        "REPO-PROP-03",
        Lane::DeterministicFile,
        "Remove custom property values from `.github/repo-settings.yml`.",
        true,
    ),
    remediation(
        "remove-property-writing-workflows",
        "REPO-PROP-04",
        Lane::JudgmentFile,
        "Remove workflow steps that write organization custom properties.",
        true,
    ),
];

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
    use crate::registry::{self, Evaluation, CHECKS};
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
    fn deterministic_remediations_close_mechanical_rules() {
        // The deterministic lane is closed headlessly from a failing finding,
        // which only a mechanical evaluation can produce.
        for definition in CLASSIFICATIONS
            .iter()
            .filter_map(Classification::remediation)
        {
            if definition.lane == Lane::DeterministicFile {
                let check = registry::find(definition.rule).expect(definition.rule);
                assert_eq!(
                    check.evaluation,
                    Evaluation::Mechanical,
                    "{} is deterministic but not mechanically evaluated",
                    definition.rule
                );
            }
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
