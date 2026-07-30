//! The finding detail: everything airlock knows about one rule.
//!
//! This is the screen that answers "why does this say what it says". The queue
//! above it has a line and a half per finding and shortens a statement to keep
//! a fact; here nothing is shortened and nothing is dropped. A fact the width
//! made the queue withhold is read here, whole, which is the only reason it is
//! safe for the queue to withhold one at all.
//!
//! Three kinds have to read correctly, and they are the three the specification
//! separates:
//!
//! * a **failure** is decided and gating — the audit is nonconformant and still
//!   complete, because the question was asked and answered;
//! * a **suppression** is a failure the policy authorized, not a failure that
//!   is absent, so the authorization is printed — a suppression that cannot be
//!   read is indistinguishable from a rule that was never run, and the
//!   remediation is retained because authorizing a failure does not delete the
//!   fix for it;
//! * an **error** is undecided, and what it reports is why airlock did not
//!   look. It is never rendered as a failure, at any severity, for any cause.
//!
//! Everything drawn here was made safe where the run became a read model, and
//! made safe without being shortened: a surface that promises to carry a fact
//! whole cannot also impose a length on it, and a bound would be silent about
//! having been reached, because an ellipsis looks like a value that ended.
//! Length is a layout concern, and this screen scrolls rather than eliding.
//! This module takes values and returns lines; it asks nothing else a question.

use ratatui::text::{Line, Span};

use airlock_core::findings::{EffectiveRule, Finding, Status, Undecided};
use airlock_core::registry;

use crate::admin::text::drawable;

use super::lane::{self, Lane};
use super::panel::{self, field_at, heading, Provenance, Scroll};
use super::theme::{Role, Styles};

/// The column every value on this screen starts in.
///
/// Wide, because the labels are the audit's own field names printed verbatim —
/// `accepted_permissions` alone is twenty columns — and every region shares the
/// column so the screen reads as one table rather than several.
pub const LABEL_WIDTH: usize = 22;

/// The indent under a heading that names the block its fields belong to.
const NESTED: &str = "  ";

/// The mark that stands where the run recorded no value.
///
/// The audit's own `null`, not a blank. A blank cell is a cell the interface
/// forgot to fill; `null` is what the run actually said.
const NULL: &str = "null";

/// One finding's evidence, as this screen draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The stable evidence code.
    pub code: String,
    /// The path the evidence is about, where it is about one.
    pub path: Option<String>,
    /// What was observed.
    pub detail: String,
}

/// The API failure that stopped a rule, as this screen draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Why the request failed, in the audit's own vocabulary.
    pub cause: String,
    /// The HTTP status, where there was a response.
    pub status: Option<u16>,
    /// The endpoint that was called.
    pub endpoint: String,
    /// GitHub's request id, where the response carried one.
    pub request_id: Option<String>,
    /// What the server said.
    pub message: Option<String>,
    /// The grants that would have sufficed, where a grant is the problem.
    pub accepted_permissions: Option<String>,
    /// Where the failure is documented.
    pub documentation_url: Option<String>,
}

impl Error {
    /// What this cause means, and what it does not.
    ///
    /// The two 403s are separated here and never conflated. `permission` says
    /// the grant was insufficient and `accepted_permissions` lists what would
    /// have sufficed; `plan_limitation` says no grant would help, and
    /// `accepted_permissions` is null because the grant was never the problem.
    /// Both are `error`, and neither is reported as a failure.
    #[must_use]
    pub fn reads_as(&self) -> String {
        let separation = match self.cause.as_str() {
            "permission" => {
                "the grant was insufficient. accepted_permissions lists what would have \
                 sufficed, so widening the grant and re-observing can answer this."
            }
            "plan_limitation" => {
                "no grant would help. accepted_permissions is null because the grant was \
                 never the problem; the account's plan is, and only changing it can \
                 answer this."
            }
            _ => {
                "the request did not complete, so airlock has no evidence about the \
                 repository either way."
            }
        };
        format!(
            "{separation} This is error and not fail: airlock did not observe the \
             condition to be unmet, it failed to look, and reporting that as a failure \
             would attribute a tooling limit to the repository."
        )
    }
}

/// The authorization standing behind a suppressed failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// Whether the policy suppressed it directly or allowed a request.
    pub source: &'static str,
    /// The reason the audited repository gave, when it asked.
    pub requested_reason: Option<String>,
    /// The reason the policy gave, when it suppressed directly.
    pub policy_reason: Option<String>,
    /// What authorized it.
    pub authorized_by: String,
}

/// What closing the gap would take.
///
/// Two vocabularies live here and are never merged: the contextual
/// `remediation` says what this failure needs, and the declared
/// `remediation_class` says what the rule's gap always takes and who can do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remediation {
    /// The contextual action group, where the run offered one.
    pub code: Option<String>,
    /// What the contextual remedy says to do.
    pub detail: Option<String>,
    /// The rule's declared join key.
    pub class_code: Option<String>,
    /// What the declared remediation would change.
    pub class_change: Option<String>,
    /// The lane the declared remediation travels in.
    pub class_lane: Option<String>,
    /// Whether the declared change can be undone.
    pub class_reversible: Option<bool>,
    /// Why no remediation is declared, when none is.
    pub class_none_reason: Option<String>,
}

impl Remediation {
    /// Whether anything at all is on offer for this rule.
    ///
    /// Either vocabulary will do: the region is drawn where there is something
    /// to say about closing the gap, whichever of the two said it.
    #[must_use]
    pub const fn offered(&self) -> bool {
        self.class_lane.is_some() || self.code.is_some()
    }

    /// Whether this run offered a contextual remedy for this failure.
    ///
    /// The narrower of the two questions, and the one the transcript turns on.
    /// A declared classification says what the rule's gap always takes; it does
    /// not say that this run produced something to carry out. Opening a
    /// transcript on a classification alone would offer to apply a change
    /// nothing described.
    #[must_use]
    pub const fn on_offer(&self) -> bool {
        self.code.is_some()
    }
}

/// Everything about one finding the queue's row does not already carry.
///
/// It rides on the row rather than being looked up again, so a row and its
/// detail are one value: they are built together at the boundary that
/// sanitizes, they sort together, and there is no second path by which a
/// server-supplied string could reach a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    /// How the rule is evaluated, which is a property of the rule and not of
    /// the run: a manual rule reports its judgment mode every time.
    pub evaluation: Option<&'static str>,
    /// Why a non-mechanical evaluation is the honest boundary, where the
    /// registry declares a reason.
    pub evaluation_reason: Option<&'static str>,
    /// The run's own record of where the rule came from, formatted
    /// `capability:{capability}/{section}`.
    pub policy_provenance: Option<String>,
    /// What was observed, where anything was.
    pub evidence: Option<Evidence>,
    /// The API failure that stopped the rule, where one did.
    pub error: Option<Error>,
    /// The authorization, where the failure was suppressed.
    pub suppression: Option<Suppression>,
    /// What closing the gap would take.
    pub remediation: Remediation,
}

impl Detail {
    /// Take everything off one finding, sanitizing as it goes.
    #[must_use]
    pub fn of(finding: &Finding, effective_policy: &[EffectiveRule]) -> Self {
        let definition = registry::find(&finding.rule);
        Self {
            evaluation: definition.map(|check| check.evaluation.code()),
            evaluation_reason: definition.and_then(registry::CheckDefinition::evaluation_reason),
            policy_provenance: effective_policy
                .iter()
                .find(|rule| rule.rule == finding.rule)
                .map(|rule| drawable(&rule.provenance)),
            evidence: finding.evidence.as_ref().map(|evidence| Evidence {
                code: drawable(&evidence.code),
                path: evidence.path.as_ref().map(|path| drawable(path)),
                detail: drawable(&evidence.detail),
            }),
            error: finding.error.as_ref().map(|error| Error {
                cause: drawable(&error.cause),
                status: error.status,
                endpoint: drawable(&error.endpoint),
                request_id: error.request_id.as_ref().map(|id| drawable(id)),
                message: error.message.as_ref().map(|message| drawable(message)),
                accepted_permissions: error
                    .accepted_permissions
                    .as_ref()
                    .map(|grants| drawable(grants)),
                documentation_url: error.documentation_url.as_ref().map(|url| drawable(url)),
            }),
            suppression: finding.suppression.as_ref().map(|suppression| Suppression {
                source: suppression.source.code(),
                requested_reason: suppression
                    .requested_reason
                    .as_ref()
                    .map(|reason| drawable(reason)),
                policy_reason: suppression
                    .policy_reason
                    .as_ref()
                    .map(|reason| drawable(reason)),
                authorized_by: drawable(&suppression.authorized_by),
            }),
            remediation: Remediation {
                code: finding
                    .remediation
                    .as_ref()
                    .map(|remediation| remediation.action_group.code().to_owned()),
                detail: finding
                    .remediation
                    .as_ref()
                    .map(|remediation| drawable(&remediation.detail)),
                class_code: finding
                    .remediation_class
                    .code
                    .as_ref()
                    .map(|code| drawable(code)),
                class_change: finding
                    .remediation_class
                    .change
                    .as_ref()
                    .map(|change| drawable(change)),
                class_lane: finding
                    .remediation_class
                    .lane
                    .as_ref()
                    .map(|lane| drawable(lane)),
                class_reversible: finding.remediation_class.reversible,
                class_none_reason: finding
                    .remediation_class
                    .none_reason
                    .as_ref()
                    .map(|reason| drawable(reason)),
            },
        }
    }
}

/// The whole screen, windowed to the rows it has.
///
/// The reading is composed in full and then windowed, never composed to fit:
/// what a shorter terminal changes is how much of the screen is in view, and
/// never what the screen says.
#[must_use]
pub fn body(
    styles: Styles,
    width: u16,
    height: u16,
    row: &super::findings::Row,
    provenance: &Provenance,
    state: &Scroll,
) -> Vec<Line<'static>> {
    let width = width as usize;
    state.window(
        regions(styles, width, row, provenance),
        height as usize,
        styles,
    )
}

/// Every region, in the order the specification lists them.
fn regions(
    styles: Styles,
    width: usize,
    row: &super::findings::Row,
    provenance: &Provenance,
) -> Vec<Line<'static>> {
    let detail = &row.detail;
    let mut lines = vec![identity(styles, row)];
    lines.extend(gate_note(styles, width, row));
    lines.push(Line::default());
    for part in super::chrome::wrap(&row.statement, width) {
        lines.push(Line::from(Span::styled(part, styles.of(Role::Text))));
    }
    lines.push(Line::default());
    lines.extend(evidence_region(styles, width, row));
    if detail.error.is_some() {
        lines.push(Line::default());
        lines.extend(error_region(styles, width, detail.error.as_ref()));
    }
    // Only when a suppression applies. A region drawn empty here would say a
    // failure was authorized by nothing, which is the one thing it must never
    // be possible to read.
    if let Some(suppression) = detail.suppression.as_ref() {
        lines.push(Line::default());
        lines.extend(suppression_region(styles, width, suppression));
    }
    lines.push(Line::default());
    lines.extend(remediation_region(styles, width, row));
    lines.push(Line::default());
    lines.extend(why_region(styles, width, row, provenance));
    lines.push(Line::default());
    lines.extend(effect_region(styles, width, row));
    lines
}

/// The rule, its status in its lane, and its severity.
fn identity(styles: Styles, row: &super::findings::Row) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            if row.gates() { lane::GATING_RAIL } else { " " },
            styles.of(Role::Status(row.status)),
        ),
        Span::raw(" "),
        Span::styled(row.rule.clone(), styles.bold(Role::Accent)),
        Span::raw("  "),
    ];
    spans.extend(lane::lanes_spans(Some(row.status), styles));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        row.status.code(),
        styles.bold(Role::Status(row.status)),
    ));
    spans.push(Span::raw("  "));
    spans.extend(lane::severity_spans(row.severity, styles));
    Line::from(spans)
}

/// Whether this finding gates the run, and why.
fn gate_note(styles: Styles, width: usize, row: &super::findings::Row) -> Vec<Line<'static>> {
    let text = if row.gates() && row.status.undecided().is_some() {
        format!(
            "gates the run: {} at {} severity, which the {} gate enforces, so complete \
             is false and no verdict can be certified",
            row.status.code(),
            row.severity.code(),
            row.gate.code()
        )
    } else if row.gates() {
        format!(
            "gates the run: {} at {} severity, which the {} gate enforces",
            row.status.code(),
            row.severity.code(),
            row.gate.code()
        )
    } else if row.status.undecided() == Some(Undecided::Structural) {
        format!(
            "does not gate: the fact requires admin access to verify, so a read-only \
             run reaching its expected access boundary is not a finding about the \
             repository \u{2014} at {} severity or any other",
            row.severity.code()
        )
    } else if lane::lane_of(row.status) == Lane::Inert {
        format!(
            "does not gate: {} never gates and never affects completeness",
            row.status.code()
        )
    } else if !row.gate.enforces(row.severity) {
        format!(
            "does not gate: the {} gate does not enforce {} severity",
            row.gate.code(),
            row.severity.code()
        )
    } else {
        format!(
            "does not gate: {} at {} severity is not a result the gate acts on",
            row.status.code(),
            row.severity.code()
        )
    };
    super::chrome::wrap(&text, width)
        .into_iter()
        .map(|part| Line::from(Span::styled(part, styles.of(Role::Dim))))
        .collect()
}

/// What was observed, or the statement that nothing was and why.
fn evidence_region(styles: Styles, width: usize, row: &super::findings::Row) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "EVIDENCE")];
    match row.detail.evidence.as_ref() {
        Some(evidence) => {
            lines.extend(value(styles, width, "evidence.code", &evidence.code));
            lines.extend(optional(styles, width, "evidence.path", &evidence.path));
            lines.extend(value(styles, width, "evidence.detail", &evidence.detail));
        }
        // Explicitly absent, with the reason, rather than blank: a rule that
        // could not be evaluated has no evidence, and that is a fact about the
        // run rather than an empty cell.
        None => {
            lines.extend(value(
                styles,
                width,
                "evidence",
                &format!("{NULL} \u{2014} {}", lane::gloss_of(row.status)),
            ));
        }
    }
    lines
}

/// The API failure, with the two 403s held apart.
fn error_region(styles: Styles, width: usize, error: Option<&Error>) -> Vec<Line<'static>> {
    let Some(error) = error else {
        return Vec::new();
    };
    let mut lines = vec![heading(styles, "ERROR")];
    lines.extend(value(styles, width, "error.cause", &error.cause));
    lines.extend(value(
        styles,
        width,
        "error.status",
        &error
            .status
            .map_or_else(|| NULL.to_owned(), |status| status.to_string()),
    ));
    lines.extend(value(styles, width, "error.endpoint", &error.endpoint));
    lines.extend(optional(
        styles,
        width,
        "error.request_id",
        &error.request_id,
    ));
    lines.extend(optional(styles, width, "error.message", &error.message));
    lines.extend(optional(
        styles,
        width,
        "accepted_permissions",
        &error.accepted_permissions,
    ));
    lines.extend(optional(
        styles,
        width,
        "documentation_url",
        &error.documentation_url,
    ));
    lines.extend(value(styles, width, "reads as", &error.reads_as()));
    lines
}

/// Who authorized the failure, and why.
fn suppression_region(
    styles: Styles,
    width: usize,
    suppression: &Suppression,
) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "SUPPRESSION")];
    lines.extend(value(
        styles,
        width,
        "suppression.source",
        suppression.source,
    ));
    // Which of the two reasons is absent follows from the source, so the
    // absence is stated in those terms rather than left as a bare null.
    lines.extend(value(
        styles,
        width,
        "requested_reason",
        &suppression.requested_reason.clone().unwrap_or_else(|| {
            if suppression.source == "policy" {
                format!("{NULL} \u{2014} the repository asked for nothing; the policy suppressed it directly")
            } else {
                format!("{NULL} \u{2014} the repository asked, and gave no reason")
            }
        }),
    ));
    lines.extend(value(
        styles,
        width,
        "policy_reason",
        &suppression
            .policy_reason
            .clone()
            .unwrap_or_else(|| format!("{NULL} \u{2014} the policy stated no reason of its own")),
    ));
    lines.extend(value(
        styles,
        width,
        "authorized_by",
        &suppression.authorized_by,
    ));
    lines
}

/// What closing the gap would take, under both of its two names.
fn remediation_region(
    styles: Styles,
    width: usize,
    row: &super::findings::Row,
) -> Vec<Line<'static>> {
    let remediation = &row.detail.remediation;
    let mut lines = vec![heading(styles, "REMEDIATION")];
    if row.status == Status::Suppressed && remediation.offered() {
        lines.extend(value(
            styles,
            width,
            "retained",
            "the failure is authorized and the fix for it is not deleted by that. \
             Applying it ends the suppression by closing the gap.",
        ));
    }
    if let Some(code) = remediation.code.as_ref() {
        lines.extend(value(styles, width, "remediation.code", code));
    }
    if let Some(detail) = remediation.detail.as_ref() {
        lines.extend(value(styles, width, "remediation.detail", detail));
    }
    match remediation.class_lane.as_ref() {
        Some(lane) => {
            lines.push(nested_heading(styles, "remediation_class"));
            lines.extend(nested(styles, width, "code", &remediation.class_code));
            lines.extend(nested(styles, width, "change", &remediation.class_change));
            lines.extend(nested(styles, width, "lane", &Some(lane.clone())));
            lines.extend(nested(
                styles,
                width,
                "reversible",
                &Some(match remediation.class_reversible {
                    Some(true) => "yes".to_owned(),
                    Some(false) => "no".to_owned(),
                    None => format!("{NULL} \u{2014} the classification does not say"),
                }),
            ));
        }
        // Exactly one of a lane and a declared reason is set. Where neither is,
        // the registry does not classify the rule at all, and saying so is a
        // different fact from a declared refusal to remediate.
        None => {
            lines.push(nested_heading(styles, "remediation_class"));
            lines.extend(nested(
                styles,
                width,
                "none_reason",
                &Some(remediation.class_none_reason.clone().unwrap_or_else(|| {
                    format!(
                        "{NULL} \u{2014} airlock declares no remediation classification \
                         for this rule at all, which is not the same as declaring that \
                         none is possible"
                    )
                })),
            ));
        }
    }
    lines
}

/// Why this rule applies, and what produced the reading.
fn why_region(
    styles: Styles,
    width: usize,
    row: &super::findings::Row,
    provenance: &Provenance,
) -> Vec<Line<'static>> {
    let detail = &row.detail;
    let mut lines = vec![heading(styles, "WHY THIS RULE APPLIES")];
    lines.extend(value(styles, width, "severity", row.severity.code()));
    lines.extend(value(
        styles,
        width,
        "evaluation",
        detail.evaluation.unwrap_or("not registered"),
    ));
    if let Some(reason) = detail.evaluation_reason {
        lines.extend(value(styles, width, "evaluation reason", reason));
    }
    lines.extend(value(styles, width, "section", &row.section));
    lines.extend(value(
        styles,
        width,
        "provenance",
        &detail.policy_provenance.clone().unwrap_or_else(|| {
            format!(
                "{NULL} \u{2014} the run recorded no effective-policy entry for this rule, \
                 so the capability that selected it is not established"
            )
        }),
    ));
    lines.push(Line::default());
    lines.extend(provenance.lines(styles, width, LABEL_WIDTH));
    lines
}

/// What this status at this severity does to the run, in plain terms.
fn effect_region(styles: Styles, width: usize, row: &super::findings::Row) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "EFFECT ON THE RUN")];
    for part in super::chrome::wrap(&effect(row), width) {
        lines.push(Line::from(Span::styled(part, styles.of(Role::Text))));
    }
    lines
}

/// The sentence itself.
///
/// Composed from status, severity, and the gate together, because neither
/// severity nor status alone is consequence: a fail at a severity the gate does
/// not enforce stops nothing, and an undecided result there leaves the run
/// complete.
#[must_use]
fn effect(row: &super::findings::Row) -> String {
    let severity = row.severity.code();
    let gate = row.gate.code();
    let enforced = row.gate.enforces(row.severity);
    match row.status {
        Status::Fail if enforced => format!(
            "A fail at {severity} severity makes the run nonconformant, because the {gate} \
             gate enforces it. The run is still complete: the question was asked and \
             answered. complete and conformant are separate facts, and this finding \
             changes only the second of them."
        ),
        Status::Fail => format!(
            "A fail at {severity} severity is real information that stops nothing: the \
             {gate} gate does not enforce {severity}. The run stays complete and this \
             finding leaves conformant untouched. It is still a gap, and it is not a pass."
        ),
        Status::Pass => format!(
            "A pass at {severity} severity is the condition observed to hold. It leaves \
             complete and conformant exactly as it found them."
        ),
        Status::Suppressed => format!(
            "The rule failed at {severity} severity and the policy authorized that failure \
             in advance. It is decided and inert: it does not gate, and it is not a pass. \
             It is standing debt, and the authorization is printed above because a \
             suppression that cannot be read is indistinguishable from a rule that was \
             never run."
        ),
        Status::Skipped => "condition_not_met: the capability condition did not apply, so the \
             rule's statement is not about this repository. It never gates and never affects \
             completeness."
            .to_owned(),
        Status::Manual => format!(
            "judgment_rule: airlock reports it for a human and reaches no verdict of its \
             own. It never gates at {severity} severity or any other, and it never affects \
             completeness. Evaluation is a property of the rule, so it does not become \
             mechanical on a later run."
        ),
        Status::AdminOnly => format!(
            "The fact requires admin access to verify, so the question is answered on the \
             verification surface the gate names rather than here. It leaves the run \
             complete at {severity} severity and at every other, because a read-only run \
             reaching its expected access boundary is not a finding about the repository. \
             The missing answer is still missing, and this is not a pass."
        ),
        Status::Unimplemented | Status::Inconclusive | Status::Error if enforced => format!(
            "This run fell short of deciding the rule, at a severity the {gate} gate \
             enforces. That makes the run incomplete: complete is false, and no verdict \
             can be certified while it is. Incompleteness outranks nonconformance, and an \
             unanswered question is not a clean repository."
        ),
        Status::Unimplemented | Status::Inconclusive | Status::Error => format!(
            "This run fell short of deciding the rule, at {severity} severity, which the \
             {gate} gate does not enforce. The run stays complete. The question is still \
             unanswered, and an unanswered question is not a pass."
        ),
    }
}

/// The status line: the lane, the gating effect, and what authorized a
/// suppression.
#[must_use]
pub fn status(row: &super::findings::Row) -> String {
    let lane = match lane::lane_of(row.status) {
        Lane::Gating => "decided \u{b7} gating",
        Lane::Inert => "decided \u{b7} inert",
        Lane::Undecided => "undecided",
    };
    // Undecided is asked first, because what an unanswered question does to a
    // run is decided before what a decided one does: it sets complete, and
    // incompleteness outranks nonconformance.
    let effect = match row.status.undecided() {
        Some(Undecided::Circumstantial) if row.gate.enforces(row.severity) => {
            "complete: false".to_owned()
        }
        Some(_) => "the run stays complete \u{b7} the question is still unanswered".to_owned(),
        None if row.gates() => "gates the run".to_owned(),
        None => "does not gate".to_owned(),
    };
    let mut text = format!("{lane} \u{b7} {effect}");
    if let Some(suppression) = row.detail.suppression.as_ref() {
        text.push_str(&format!(
            " \u{b7} authorized by {}",
            suppression.authorized_by
        ));
    }
    text
}

/// What the status line says after `o`.
///
/// The request is reported, never a result: what a re-observation concluded is
/// shown when the observation returns, and airlock does not claim an
/// observation it has not made.
#[must_use]
pub fn reobserving(rule: &str) -> String {
    format!(
        "re-observation of {rule} requested \u{b7} airlock reports what it then sees, \
         never that the request was accepted"
    )
}

/// What the status line says after `y`.
#[must_use]
pub fn copied(rule: &str) -> String {
    format!(
        "{rule} offered to the terminal's clipboard \u{b7} a terminal that does not take \
         it ignores it, and the rule id is above in full"
    )
}

/// What the status line says when a key that acts on a finding was pressed and
/// there is no finding under the focus.
///
/// Said rather than silently ignored: a key the footer lists and that does
/// nothing is a key the operator will press again.
#[must_use]
pub fn nothing_to_act_on() -> String {
    "no finding is open \u{b7} this screen is reached from a row in the queue, and \
     the focus is on a group heading or nothing has been observed yet"
        .to_owned()
}

fn value(styles: Styles, width: usize, label: &str, text: &str) -> Vec<Line<'static>> {
    field_at(styles, label, text, width, LABEL_WIDTH)
}

/// A field whose value the run may not have carried, printed as `null` when it
/// did not.
fn optional(
    styles: Styles,
    width: usize,
    label: &str,
    text: &Option<String>,
) -> Vec<Line<'static>> {
    value(styles, width, label, text.as_deref().unwrap_or(NULL))
}

/// The name of a block whose fields are printed under it.
fn nested_heading(styles: Styles, text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, styles.of(Role::Faint)))
}

/// One field of such a block, indented so its name is read as qualified by the
/// heading above it rather than standing on its own.
fn nested(styles: Styles, width: usize, label: &str, text: &Option<String>) -> Vec<Line<'static>> {
    field_at(
        styles,
        &format!("{NESTED}{label}"),
        text.as_deref().unwrap_or(NULL),
        width,
        LABEL_WIDTH,
    )
}

/// The screen when the queue's focus is not on a finding.
///
/// It states what would have populated the region, why it is empty, and what
/// to do next, because "nothing here" is never shown by itself.
#[must_use]
pub fn nothing_selected(styles: Styles, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "NO FINDING SELECTED")];
    for (label, text) in [
        (
            "would show",
            "one rule in full: its statement, its evidence, any error or \
             suppression, the remediation on offer, why the rule applies, and what \
             this status at this severity does to the run.",
        ),
        (
            "empty because",
            "this screen is opened from a finding, and the queue's focus is on a \
             group heading rather than on a row \u{2014} or no repository has been \
             observed in this session yet.",
        ),
        (
            "next",
            "press esc to return to the queue, move onto a row, and press \u{21b5}.",
        ),
    ] {
        lines.extend(panel::field(styles, label, text, width));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::chrome::{FLOOR_HEIGHT, FLOOR_WIDTH, REFERENCE_HEIGHT, REFERENCE_WIDTH};
    use crate::tui::findings::{fixture, Deliveries, Queue};
    use crate::tui::theme::{ColorMode, Theme};
    use airlock_core::findings::{Finding, Gate, Report};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn queue(report: &Report) -> Queue {
        Queue::of(report, &Deliveries::default())
    }

    fn row_for<'a>(queue: &'a Queue, rule: &str) -> &'a super::super::findings::Row {
        queue
            .rows
            .iter()
            .find(|row| row.rule == rule)
            .expect("the rule is in the run")
    }

    /// The reading as one string. Lines are joined with a space, because a
    /// sentence that wrapped is still the sentence.
    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A run of exactly one finding, so a rule id addresses one row.
    fn only(finding: Finding) -> Report {
        fixture::report(Gate::Required, vec![finding])
    }

    fn drawn(report: &Report, rule: &str, width: u16, height: u16) -> String {
        let queue = queue(report);
        let row = row_for(&queue, rule);
        text(&body(
            styles(),
            width,
            height,
            row,
            &queue.provenance,
            &Scroll::default(),
        ))
    }

    /// Everything the screen has to say, whatever the terminal is.
    fn whole(report: &Report, rule: &str, width: u16) -> String {
        let queue = queue(report);
        let row = row_for(&queue, rule);
        text(&regions(styles(), width as usize, row, &queue.provenance))
    }

    // -----------------------------------------------------------------
    // The three kinds
    // -----------------------------------------------------------------

    #[test]
    fn a_failure_reads_as_nonconformant_and_still_complete() {
        let rendered = whole(&fixture::mixed(), "REPO-GIT-01", REFERENCE_WIDTH);
        assert!(rendered.contains("nonconformant"), "{rendered}");
        assert!(rendered.contains("still complete"), "{rendered}");
        assert!(rendered.contains("gates the run"), "{rendered}");
        assert!(rendered.contains("branch_unprotected"), "{rendered}");
        assert!(rendered.contains("REMEDIATION"), "{rendered}");
    }

    #[test]
    fn a_suppression_always_says_who_authorized_it_and_why() {
        let rendered = whole(&only(fixture::suppressed()), "REPO-CI-02", REFERENCE_WIDTH);
        assert!(rendered.contains("SUPPRESSION"), "{rendered}");
        assert!(rendered.contains("suppression.source"), "{rendered}");
        assert!(rendered.contains("policy"), "{rendered}");
        assert!(rendered.contains("migration in flight"), "{rendered}");
        assert!(rendered.contains("authorized_by"), "{rendered}");
    }

    #[test]
    fn a_suppression_retains_its_remediation() {
        let report = only(fixture::suppressed());
        let queue = queue(&report);
        let row = row_for(&queue, "REPO-CI-02");
        assert_eq!(row.status, Status::Suppressed);
        let rendered = text(&remediation_region(styles(), 120, row));
        assert!(rendered.contains("REMEDIATION"), "{rendered}");
        assert!(
            rendered.contains("not deleted by that"),
            "authorizing a failure does not delete the fix for it: {rendered}"
        );
    }

    #[test]
    fn no_region_of_a_suppression_can_be_read_as_authorized_by_nothing() {
        // The region is drawn only where a suppression applies. A finding that
        // was never suppressed has no such region at all, so there is no empty
        // one to be misread.
        let rendered = whole(&fixture::mixed(), "REPO-GIT-01", REFERENCE_WIDTH);
        assert!(!rendered.contains("SUPPRESSION"), "{rendered}");
    }

    #[test]
    fn an_error_is_never_rendered_as_a_failure() {
        let rendered = whole(&fixture::incomplete(), "REPO-GIT-09", REFERENCE_WIDTH);
        assert!(rendered.contains("error"), "{rendered}");
        assert!(rendered.contains("error not fail") || rendered.contains("error and not fail"));
        assert!(rendered.contains("failed to look"), "{rendered}");
        assert!(rendered.contains("incomplete"), "{rendered}");
    }

    #[test]
    fn the_two_403s_are_separated_and_never_conflated() {
        let permission = Error {
            cause: "permission".to_owned(),
            status: Some(403),
            endpoint: "GET /repos/{owner}/{repo}/rulesets".to_owned(),
            request_id: None,
            message: None,
            accepted_permissions: Some("administration:read".to_owned()),
            documentation_url: None,
        };
        let plan = Error {
            cause: "plan_limitation".to_owned(),
            accepted_permissions: None,
            ..permission.clone()
        };
        assert!(permission.reads_as().contains("would have sufficed"));
        assert!(permission.reads_as().contains("widening the grant"));
        assert!(plan.reads_as().contains("no grant would help"));
        assert!(plan.reads_as().contains("plan"));
        assert_ne!(permission.reads_as(), plan.reads_as());
        // Neither is ever a failure, and both say so in the same words.
        for error in [&permission, &plan] {
            assert!(error.reads_as().contains("error and not fail"));
        }
    }

    #[test]
    fn an_error_region_prints_every_field_the_specification_names() {
        let rendered = text(&error_region(
            styles(),
            120,
            Some(&Error {
                cause: "permission".to_owned(),
                status: Some(403),
                endpoint: "GET /repos/{owner}/{repo}/rulesets".to_owned(),
                request_id: Some("FIXT:0001".to_owned()),
                message: Some("Resource not accessible by integration".to_owned()),
                accepted_permissions: Some("administration:read".to_owned()),
                documentation_url: Some("https://example.invalid/rulesets".to_owned()),
            }),
        ));
        for label in [
            "error.cause",
            "error.status",
            "error.endpoint",
            "error.request_id",
            "error.message",
            "accepted_permissions",
            "documentation_url",
        ] {
            assert!(rendered.contains(label), "{label} is missing: {rendered}");
        }
    }

    #[test]
    fn a_plan_limitation_prints_accepted_permissions_as_null_rather_than_omitting_it() {
        let rendered = text(&error_region(
            styles(),
            120,
            Some(&Error {
                cause: "plan_limitation".to_owned(),
                status: Some(403),
                endpoint: "GET /repos/{owner}/{repo}/rulesets".to_owned(),
                request_id: None,
                message: None,
                accepted_permissions: None,
                documentation_url: None,
            }),
        ));
        assert!(rendered.contains("accepted_permissions null"), "{rendered}");
    }

    // -----------------------------------------------------------------
    // Evidence, remediation, provenance
    // -----------------------------------------------------------------

    #[test]
    fn a_rule_that_could_not_be_evaluated_shows_evidence_as_explicitly_absent() {
        let queue = queue(&fixture::incomplete());
        let row = row_for(&queue, "REPO-GIT-09");
        let rendered = text(&evidence_region(styles(), 120, row));
        assert!(rendered.contains("evidence null"), "{rendered}");
        assert!(
            rendered.contains("no evidence exists"),
            "the reason is given: {rendered}"
        );
    }

    #[test]
    fn the_two_remediation_vocabularies_are_never_merged() {
        let mut finding = fixture::settings_failure();
        finding.remediation = Some(airlock_core::findings::Remediation::new(
            airlock_core::remediation::ActionGroup::TIGHTEN_RULESET,
            "Protect the default branch.",
        ));
        let report = fixture::report(Gate::Required, vec![finding]);
        let rendered = whole(&report, "REPO-GIT-01", REFERENCE_WIDTH);
        assert!(rendered.contains("remediation.code"), "{rendered}");
        assert!(rendered.contains("remediation_class"), "{rendered}");
    }

    #[test]
    fn a_rule_with_no_declared_remediation_prints_the_declared_reason() {
        let rendered = whole(&fixture::long_fact(), "REPO-DOCS-05", REFERENCE_WIDTH);
        assert!(rendered.contains("none_reason"), "{rendered}");
        assert!(rendered.contains("the maintainer's"), "{rendered}");
    }

    #[test]
    fn evaluation_is_a_property_of_the_rule_and_is_reported_every_time() {
        let queue = queue(&fixture::mixed());
        for row in &queue.rows {
            let rendered = text(&why_region(styles(), 120, row, &queue.provenance));
            assert!(rendered.contains("evaluation"), "{}: {rendered}", row.rule);
        }
    }

    #[test]
    fn the_provenance_block_is_on_every_finding() {
        let queue = queue(&fixture::mixed());
        for row in &queue.rows {
            let rendered = text(&regions(styles(), 120, row, &queue.provenance));
            assert!(
                rendered.contains("RUN PROVENANCE"),
                "{}: {rendered}",
                row.rule
            );
            assert!(
                rendered.contains(&queue.provenance.audited_commit),
                "{}: {rendered}",
                row.rule
            );
        }
    }

    // -----------------------------------------------------------------
    // The effect sentence
    // -----------------------------------------------------------------

    #[test]
    fn every_status_has_an_effect_sentence_naming_what_it_does_to_the_run() {
        let queue = queue(&fixture::mixed());
        let mut seen = Vec::new();
        for row in &queue.rows {
            let sentence = effect(row);
            assert!(!sentence.is_empty(), "{}", row.rule);
            seen.push(row.status);
        }
        assert!(seen.contains(&Status::Suppressed));
        assert!(seen.contains(&Status::AdminOnly));
    }

    #[test]
    fn an_admin_only_finding_leaves_the_run_complete_and_is_never_a_pass() {
        let queue = queue(&fixture::mixed());
        let row = row_for(&queue, "REPO-GIT-04");
        let sentence = effect(row);
        assert!(sentence.contains("complete"), "{sentence}");
        assert!(sentence.contains("not a pass"), "{sentence}");
        assert!(!row.gates(), "an admin-only finding never gates");
    }

    // -----------------------------------------------------------------
    // The frame
    // -----------------------------------------------------------------

    #[test]
    fn no_line_overflows_at_either_size() {
        let report = fixture::mixed();
        let queue = queue(&report);
        for row in &queue.rows {
            for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
                for line in regions(styles(), width as usize, row, &queue.provenance) {
                    let rendered: String = line
                        .spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect();
                    assert!(
                        rendered.chars().count() <= width as usize,
                        "{} at {width}: {rendered:?}",
                        row.rule
                    );
                }
            }
        }
    }

    #[test]
    fn a_reading_longer_than_the_terminal_scrolls_and_says_where_the_window_is() {
        let report = fixture::mixed();
        let rendered = drawn(&report, "REPO-GIT-01", FLOOR_WIDTH, FLOOR_HEIGHT - 3);
        assert!(rendered.contains("lines above"), "{rendered}");
        assert!(rendered.contains("below"), "{rendered}");
    }

    #[test]
    fn the_window_never_leaves_the_reading() {
        let report = fixture::mixed();
        let queue = queue(&report);
        let row = row_for(&queue, "REPO-GIT-01");
        let mut state = Scroll::default();
        let height = FLOOR_HEIGHT - 3;
        for _ in 0..200 {
            let lines = body(
                styles(),
                FLOOR_WIDTH,
                height,
                row,
                &queue.provenance,
                &state,
            );
            assert_eq!(lines.len(), height as usize);
            state.by(1);
        }
        // At the bottom, the last line of the reading is in view.
        let lines = body(
            styles(),
            FLOOR_WIDTH,
            height,
            row,
            &queue.provenance,
            &state,
        );
        let rendered = text(&lines);
        assert!(rendered.contains("0 below"), "{rendered}");
        for _ in 0..200 {
            state.by(-1);
        }
        assert_eq!(state.offset(), 0);
    }

    #[test]
    fn a_reading_that_fits_is_never_windowed() {
        let report = fixture::mixed();
        let queue = queue(&report);
        let row = row_for(&queue, "REPO-META-01");
        let lines = body(
            styles(),
            REFERENCE_WIDTH,
            REFERENCE_HEIGHT * 4,
            row,
            &queue.provenance,
            &Scroll::default(),
        );
        let rendered = text(&lines);
        assert!(!rendered.contains("lines above"), "{rendered}");
    }

    /// Every string the run supplied for a rule, as the run wrote it.
    ///
    /// Read off the finding rather than off the read model, so the test
    /// compares what was drawn against the source and not against another copy
    /// of the drawing.
    fn supplied(finding: &Finding) -> Vec<String> {
        let mut values = vec![finding.statement.clone()];
        if let Some(evidence) = finding.evidence.as_ref() {
            values.push(evidence.code.clone());
            values.extend(evidence.path.clone());
            values.push(evidence.detail.clone());
        }
        if let Some(error) = finding.error.as_ref() {
            values.push(error.cause.clone());
            values.push(error.endpoint.clone());
            values.extend(error.message.clone());
            values.extend(error.documentation_url.clone());
            values.extend(error.accepted_permissions.clone());
            values.extend(error.request_id.clone());
        }
        if let Some(suppression) = finding.suppression.as_ref() {
            values.extend(suppression.requested_reason.clone());
            values.extend(suppression.policy_reason.clone());
            values.push(suppression.authorized_by.clone());
        }
        if let Some(remediation) = finding.remediation.as_ref() {
            values.push(remediation.detail.clone());
        }
        values.extend(finding.remediation_class.code.clone());
        values.extend(finding.remediation_class.change.clone());
        values.extend(finding.remediation_class.none_reason.clone());
        values
    }

    /// What a value looks like once the unexaminable characters are refused.
    fn expected(value: &str) -> String {
        crate::admin::text::drawable(value).replace(' ', "")
    }

    #[test]
    fn a_value_longer_than_any_layout_bound_is_still_carried_whole() {
        // The surface of last resort, tested on values it could have shortened.
        // Every one of these is far past the bound the queue imposes for its
        // own layout, which is exactly the case the guarantee is for and
        // exactly the case a fixture of convenient lengths cannot reach.
        let report = fixture::hostile();
        let queue = queue(&report);
        for finding in &report.findings {
            let row = row_for(&queue, &finding.rule);
            for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
                let rendered = text(&regions(styles(), width as usize, row, &queue.provenance))
                    .replace(' ', "");
                for value in supplied(finding) {
                    assert!(
                        value.chars().count() > 400,
                        "the fixture must exceed any layout bound: {}",
                        value.chars().count()
                    );
                    assert!(
                        rendered.contains(&expected(&value)),
                        "{} at {width} lost a value it promised to carry whole",
                        finding.rule
                    );
                }
                assert!(
                    !rendered.contains('\u{2026}'),
                    "{} at {width} elided something",
                    finding.rule
                );
            }
        }
    }

    #[test]
    fn a_hostile_value_is_carried_whole_and_still_cannot_instruct_the_terminal() {
        // Completeness and safety on the same value: the guarantee is that
        // nothing is shortened, never that nothing is examined.
        let report = fixture::hostile();
        let queue = queue(&report);
        for row in &queue.rows {
            for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
                let rendered = text(&regions(styles(), width as usize, row, &queue.provenance));
                for refused in ['\u{1b}', '\u{202e}', '\u{200b}'] {
                    assert!(
                        !rendered.contains(refused),
                        "{} at {width}: {refused:?} reached a cell",
                        row.rule
                    );
                }
                // Refused rather than dropped, so the operator has a sign that
                // something was removed.
                assert!(rendered.contains('\u{fffd}'), "{} at {width}", row.rule);
            }
        }
    }

    #[test]
    fn nothing_on_this_screen_is_ever_elided() {
        // The queue elides a statement to keep a fact. Here there is nothing to
        // keep room for: the reading is whole at every width, and a mark that
        // said something was dropped would be the one thing this screen is for
        // failing to do.
        for report in [
            fixture::mixed(),
            fixture::incomplete(),
            fixture::long_fact(),
            fixture::hostile(),
            only(fixture::suppressed()),
        ] {
            let queue = queue(&report);
            for row in &queue.rows {
                for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
                    let rendered = text(&regions(styles(), width as usize, row, &queue.provenance));
                    assert!(
                        !rendered.contains('\u{2026}'),
                        "{} at {width}: {rendered}",
                        row.rule
                    );
                }
            }
        }
    }

    #[test]
    fn nothing_is_shortened_to_fit_the_floor() {
        // The whole reading is the same text at both widths. What a narrower
        // terminal changes is how much of it is in view, never what it says.
        let report = fixture::long_fact();
        let strip = |text: String| text.replace(' ', "");
        let wide = strip(whole(&report, "REPO-DOCS-05", REFERENCE_WIDTH));
        let narrow = strip(whole(&report, "REPO-DOCS-05", FLOOR_WIDTH));
        // Compared without the spaces the wrapping put in: what a width
        // changes is where a line ends, never which characters are on screen.
        assert_eq!(wide, narrow);
        assert!(
            !wide.contains('\u{2026}'),
            "nothing on this screen is elided: {wide}"
        );
    }

    // -----------------------------------------------------------------
    // The status line and the two keys that report rather than claim
    // -----------------------------------------------------------------

    #[test]
    fn the_status_line_states_the_lane_and_the_gating_effect() {
        let mixed = queue(&fixture::mixed());
        assert!(status(row_for(&mixed, "REPO-GIT-01")).starts_with("decided \u{b7} gating"));
        assert!(status(row_for(&mixed, "REPO-GIT-04")).starts_with("undecided"));
        let report = only(fixture::suppressed());
        let inert = queue(&report);
        assert!(status(row_for(&inert, "REPO-CI-02")).starts_with("decided \u{b7} inert"));
    }

    #[test]
    fn a_suppressed_findings_status_line_names_what_authorized_it() {
        let report = only(fixture::suppressed());
        let queue = queue(&report);
        assert!(
            status(row_for(&queue, "REPO-CI-02")).contains("authorized by policy"),
            "{}",
            status(row_for(&queue, "REPO-CI-02"))
        );
    }

    #[test]
    fn re_observation_reports_the_request_and_never_a_result() {
        let note = reobserving("REPO-GIT-01");
        assert!(note.contains("requested"), "{note}");
        assert!(note.contains("what it then sees"), "{note}");
    }

    #[test]
    fn a_copy_reports_the_asking_and_says_the_value_is_on_screen_anyway() {
        let note = copied("REPO-GIT-01");
        assert!(note.contains("clipboard"), "{note}");
        assert!(note.contains("ignores it"), "{note}");
        assert!(note.contains("in full"), "{note}");
    }

    #[test]
    fn an_unselected_screen_states_what_would_have_filled_it() {
        let rendered = text(&nothing_selected(styles(), 120));
        assert!(rendered.contains("would show"), "{rendered}");
        assert!(rendered.contains("empty because"), "{rendered}");
        assert!(rendered.contains("next"), "{rendered}");
    }
}
