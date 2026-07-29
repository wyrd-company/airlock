---
relationships:
  specifies: airlock-cli
  references:
    - airlock-core
    - README.md
---

# Terminal interface

Airlock's terminal interface is a release-readiness console. It observes a
repository against the effective policy, presents the resulting findings as a
work queue, and carries out the closing moves only a person may make:
repository and organisation settings, capability decisions, judgment
attestations, and the publishing bootstrap.

It requires an interactive terminal. Under a pipe, a scheduler, or any
non-tty, it exits without rendering; `airlock audit` is the complete
unattended findings surface, and `airlock agent-work` is its lane-scoped
definition-of-done projection for an executing agent.

The interface never writes files. File-level gaps are closed by an agent
working headlessly and arrive as pull requests for review. Nothing on any
screen offers to edit a tracked file.

The headless projection uses the same grouping boundary as the findings queue:
failed `deterministic-file` and `judgment-file` remediations are agent work;
failed `operator-setting` remediations and failures with no declared
remediation are reported separately and never gate the agent lane. Capability
decisions, other undecided findings, manual judgments, and suppressed debt
remain separately counted and identified. Every undecided finding says whether
the effective gate enforces it; enforced unanswered questions make the
projection `could_not_settle`. Its clear outcome means only “the agent lane is
clear,” never “the repository is aligned,” and its output retains the audit's
per-finding and run-level observation sources.

## Authorization and the credential

Authorization is requested on every launch through the GitHub App device flow
and is discarded on exit. No credential is written to disk, and none is read
from the environment, the `gh` credential store, or a git credential helper.
The credential's value is never displayed; the interface displays only its
source and its grant.

The grant is write-capable, because applying a repository or organisation
setting requires `administration: write`, which GitHub does not subdivide.
This grant belongs to the interactive session alone. It is not the credential
`airlock audit` accepts: that command verifies its token to be read-only
before first use and refuses any token carrying write access.

## Reference layout and the accessibility floor

The reference layout is 120 columns by 40 rows. Every screen also renders
within a floor of 80 columns by 24 rows, and no screen requires more than the
floor to be usable.

The interface renders in a dark palette and a light palette. Both carry the
same information; neither is a degraded form of the other. Under `NO_COLOR`
the interface renders without any colour, and every distinction the design
carries survives — status is read from glyph and lane position, severity from
a three-cell bar, gating from a solid left rail, and group membership from
headings.

Where a rendering cannot fit, it is withheld rather than clipped. The scan
code on the sign-in screen is the case that matters: it occupies 33 columns,
so at the floor it is not drawn beside the device code. The screen says so,
offers to draw it below the code instead, and states the width at which it
would sit alongside. A partially drawn scan code is never rendered, because a
code that cannot be scanned is worse than an address the operator types.

Type is monospaced throughout, and the device code is rendered in a face that
distinguishes `0` from `O` and `1` from `l` and `I`.

## Status vocabulary

A finding carries exactly one of eight statuses. Each status sits in one of
three lanes, and the lane is a physical column position on every row that
shows a status. Position carries the meaning; hue confirms it and never
carries it alone.

| Status | Glyph | Lane | Effect on the run |
| --- | --- | --- | --- |
| `pass` | `✓` | gating | Counts toward the verdict |
| `fail` | `✗` | gating | Counts toward the verdict |
| `manual` | `◆` | inert | Never gates, never affects completeness |
| `suppressed` | `⊘` | inert | Never gates, never affects completeness |
| `skipped` | `○` | inert | Never gates, never affects completeness |
| `unimplemented` | `▢` | undecided | Makes the run incomplete at a gating severity |
| `inconclusive` | `◑` | undecided | Makes the run incomplete at a gating severity |
| `error` | `!` | undecided | Makes the run incomplete at a gating severity |

The three lanes read as three shape families: the gating lane uses stroke
marks, the inert lane uses closed outlines, and the undecided lane uses
enclosed forms. The undecided lane is ruled off on both sides on every row
that shows it, so nothing standing in it can be mistaken for a pass in any
theme or with colour removed.

The glosses the interface prints for each status are:

- `pass` — the condition was observed to hold
- `fail` — the condition was observed not to hold
- `manual` — `judgment_rule`, reported for a human
- `suppressed` — a failure the policy authorized
- `skipped` — `condition_not_met`, the capability condition did not apply
- `unimplemented` — registered and enabled, not yet evaluated
- `inconclusive` — the question could not be established
- `error` — the call did not complete, so no evidence exists

## Severity and the gate

A rule carries one of three severities: `blocking`, `required`, or
`observation`. Severity is rendered as a three-cell bar plus its name, so it
reads at a glance and survives monochrome: `███ blocking`, `██░ required`,
`█░░ observation`.

The gate is severity times status. Severity alone is not consequence, and
status alone is not consequence. A `fail` at `observation` severity is real
information that stops nothing; an `inconclusive` at `observation` severity
leaves the run complete. Rows that actually gate the run carry a solid left
rail; nothing else does.

The gate is a property of the effective policy, not of the session. The
interface displays which gate is in force and never offers to change it.

`complete` and `conformant` are separate facts and are always printed
separately. A run is incomplete when a rule at a gating severity ended in the
undecided lane. A run is nonconformant when a rule at a gating severity ended
in `fail`. Incompleteness outranks nonconformance in the verdict, which is one
of `conformant`, `nonconformant`, or `incomplete`. An unanswered question is
not a clean repository.

## Emptiness

"Nothing here" is never shown by itself. Every empty region states what would
have populated it, why it is empty, and what the operator can do next. Where
an emptiness has more than one possible cause, all of the causes are listed,
because an empty result cannot distinguish between them.

## Screens

Two keys are live on every screen in every state: `t` switches theme and
`ctrl-c` exits. Each screen's keymap below lists the keys it adds, and names
any state in which one of those keys is not live and why.

### Sign-in

**Purpose.** Obtain an authorization for this session through the device flow.

**Content.** The program identity and version; a standing statement that no
credential of any kind is stored and that an interactive terminal is required;
the device code; the address to enter it at; and the scan code when width
allows. The device code is eight characters, case-insensitive, drawn from an
alphabet that excludes `0`, `O`, `1`, and `I`. The scan code encodes the
address only — GitHub's device flow offers no address that carries the code,
so the code is always typed by hand and is always present as legible text.
The scan code paints its own white field and a four-module quiet zone rather
than inheriting the terminal background, so it scans identically on both
themes.

The screen has five states:

- **Requesting.** The code frame is drawn empty rather than absent, so nothing
  shifts position when the code arrives. `r` and `q` are not live in this
  state, because there is not yet a code to reissue or to encode.
- **Awaiting approval.** The code, the address, the polling interval, the
  attempt number, and the code's remaining validity are shown.
- **Expired.** The code lapsed without approval. A new code is issued in
  place; the session is not restarted and nothing else is lost.
- **Denied.** GitHub reported `access_denied` for the code. The screen states
  that the request was rejected in the browser or the account is not permitted
  to authorize the app, and that if this was not the operator, no action is
  required, because nothing was granted and no credential exists to revoke.
- **Polling interrupted.** The transport failed. The cause is named, the
  still-valid code stays on screen with its remaining validity, and the
  backoff and attempt number are shown rather than hidden. Approval already
  given is picked up when polling resumes.

**Keymap.** `r` issue a new code · `q` show or hide the scan code. Both are
live only once a device code exists.

**Status line.** `no credential on disk · tty required`.

### Organizations

**Purpose.** Choose which installation to work in.

**Content.** The reachable installations, each with its name, its kind
(organization or user account), and its repository count. Where an
installation is scoped to a subset of repositories, the row says so. The list
is the intersection of where the app is installed and what the account can
reach, and the screen states that an absent organization is not evidence of
absence.

Whether or not the list is empty, the screen carries the three causes of an
absent organization, because they have three different remedies and cannot be
distinguished from here — each one also hides the evidence of itself:

1. The app is not installed on that organization. Install airlock on it; an
   owner or an admin can do this.
2. It is installed, but the account is not a member, or its role does not
   reach it. Ask an owner to add the account, or to grant the role.
3. Both are fine, but the installation was scoped to repositories the account
   cannot see. Widen the installation's repository selection.

The credential in force is shown alongside: its source (GitHub App, device
flow), the permissions in its grant, and the statement that its value is never
displayed and never written to disk.

**Keymap.** `↑↓` select · `↵` open.

**Status line.** The installation count and the note that the list is the
intersection of install and access.

### Repositories

**Purpose.** Choose a repository to observe.

**Content.** An incremental filter over the repository name, and a table of
name, visibility, date of last audit, the verdict that audit reached, and
default branch. A repository never audited shows so explicitly rather than
showing a blank verdict.

A prior verdict is displayed for orientation only. Nothing is acted upon from
memory: opening a repository re-observes it in full.

**Keymap.** `↑↓` select · `/` filter · `↵` observe · `esc` back.

**Status line.** The count shown against the count available in the
installation, and the note that prior verdicts are shown for orientation only.

### Findings

**Purpose.** Present the whole standard as a work queue, ordered by what
closing each gap takes and who can close it.

Every rule the policy enables produces exactly one finding, and every finding
is either aligned or it is not. Nothing is triaged away as unimportant, because
an unimportant rule would not be in the policy. What differs between findings
is how much reading each one needs before it can be closed, and who can close
it.

**Content.** Above the queue, unchanged by anything below it:

- The verdict, its glyph, and the reason for it, stating `complete` and
  `conformant` as separate facts.
- The status summary — every one of the eight statuses with its glyph, its
  count, and its lane, under the three lane headings `DECIDED · GATING`
  (counts toward the verdict), `DECIDED · INERT` (never gates), and
  `UNDECIDED` (makes the run incomplete at a gating severity). The undecided
  heading carries the qualifier, because an undecided result at a severity the
  effective gate does not enforce leaves the run complete.
- When a rule at a gating severity could not be evaluated, a blocker banner
  naming each such rule, its status, and why it could not be evaluated. The
  banner states that `complete` is false and that no verdict below it can be
  certified.

The queue itself is seven groups, in this order. Each group heading carries
its count and a one-line gloss of the work:

1. **Airlock closes this.** Settings-level changes applied directly from the
   interface. The operator is confirming, not studying, so these are
   bulk-confirmable.
2. **Closes by pull request — agent work.** File-level gaps. Display only. Each
   row shows the delivery state of its remediation so the operator can tell
   agent work in flight from agent work not yet picked up. No action is offered
   on these rows.
3. **Needs a decision.** The repository has not declared what it is, so airlock
   cannot know what to apply.
4. **Needs a judgment.** Rules a person must attest to.
5. **Airlock could not answer.** The undecided lane. Blocks certification where
   the effective gate enforces the rule's severity, and the remedy often sits
   outside the repository — a plan change, a grant change, a rule not yet
   built. A row in this group that does not block says so on the row: it is
   still an unanswered question, and it is not a pass.
6. **Authorized but not aligned.** Suppressed failures. The policy permitted
   the failure; it did not close the gap, and the remediation is still on
   offer. This is standing debt and is never folded in with passing rules.
7. **Aligned.** Passing rules, and rules skipped because a capability condition
   genuinely does not apply.

A finding takes the first group it matches, tested in this order:

1. `suppressed` → group 6.
2. `inconclusive` with `evidence.code` of `condition_undecided` → group 3.
3. `unimplemented`, `inconclusive`, or `error` → group 5.
4. `manual` → group 4.
5. `pass` or `skipped` → group 7.
6. `fail` whose `remediation_class.lane` is `operator-setting` → group 1.
7. `fail` whose `remediation_class.lane` is `deterministic-file` or
   `judgment-file` → group 2.
8. `fail` for which `remediation_class` declares no remediation → group 4. The
   declared reason is shown on the row, because the only remaining move is a
   person's.

Only group 7 is done. Groups 3, 4, and 5 are where the operator's attention
goes.

Each row carries its rule id, its severity bar, its three status lanes with
the glyph in the lane its status belongs to, its status name, its statement,
and the section the registry gives its rule. The three-lane model is unchanged
by grouping: grouping layers
on top of it, and every row still shows its status glyph in its lane. Nothing
in the undecided lane reads as a pass, and no group heading implies that
everything under it gates, or that nothing does.

Rows in group 2 additionally carry the delivery state of their remediation,
which is one of `open` (a pull request is open against this gap), `none` (no
pull request is open), or `unknown` (the observation did not establish it).
`unknown` never renders as `none`.

Per-group counts and the overall aligned count are visible whatever is
expanded or collapsed, so the whole standard is always in view. The aligned
count is the score and reads as one: a fully aligned repository looks
finished, not like an empty list.

Collapsing is screen space, never a judgment. Group 7 starts collapsed because
it needs no action. No other group starts collapsed.

A filter narrows the working set across all groups: the whole working set,
gating failures, undecided, all failures, or inert. The filter changes what is
shown; it never changes a count in a group heading.

A secondary view lists every finding flat, ordered by rule id. Its purpose is
lookup — a predictable address for every rule, for answering what airlock says
about a given rule id. It is reached by keystroke and is labelled as a lookup
view.

**Keymap.** `↑↓`/`j`/`k` move · `space` collapse or expand the focused group ·
`↵` finding detail · `f` filter · `a` apply, on group 1 rows only · `l` flat
list by rule id · `p` policy inspector · `b` publishing bootstrap · `esc` back.

`a` is inert on every row outside group 1, and the status line says why rather
than the key silently doing nothing.

**Status line.** The verdict, `complete` as a separate boolean, the rule count,
the registry version, and the gate in force.

### Finding detail

**Purpose.** Show everything airlock knows about one finding, and what closing
it would take.

**Content.** The rule id, its status glyph and name, its severity bar and name,
and a gate note stating whether this finding gates the run and why. Then the
rule's statement, followed by:

- **Evidence.** `evidence.code`, `evidence.path`, and `evidence.detail`. A rule
  that could not be evaluated shows evidence as explicitly absent, with the
  reason, rather than as blank.
- **Error**, when the status is `error`. `error.cause`, `error.status`,
  `error.endpoint`, `error.request_id`, `error.message`,
  `accepted_permissions`, and `documentation_url`. The two 403s are separated
  here and never conflated: `permission` means the grant was insufficient and
  `accepted_permissions` lists what would have sufficed; `plan_limitation`
  means no grant would help and `accepted_permissions` is null. Both are
  `error`, and neither is reported as a failure.
- **Suppression**, when the status is `suppressed`. The source, the reason the
  repository requested if it requested one, the reason the policy gave, and
  what authorized it. The authorization is printed because a suppression that
  cannot be read is indistinguishable from a rule that was never run.
- **Remediation.** The remediation code and what it would change, the declared
  lane, and whether the change is reversible. A suppressed finding retains its
  remediation and shows it: authorizing a failure does not delete the fix for
  it. A finding for which airlock declares no remediation shows the declared
  reason.
- **Why this rule applies.** Severity, evaluation, the rule's section and the
  capability that selected it — both read from
  `effective_policy[].provenance` — and the run provenance: airlock version,
  registry version, registry digest, schema version, audited commit, and the
  time the settings were observed.
- **Effect on the run.** A sentence stating in plain terms what this status at
  this severity does to `complete` and to `conformant`.

**Keymap.** `esc` back · `a` open the remediation transcript, where a
remediation is on offer and its lane is `operator-setting` · `o` re-observe
this rule · `y` copy the rule id.

**Status line.** The finding's lane and gating effect, and for a suppressed
finding, what authorized it.

### Remediation

**Purpose.** Carry out a settings-level remediation and show what was actually
observed afterwards.

**Content.** The proposed change, stated before anything happens: the rule, the
remediation code and its sentence, what it would change, and whether it is
reversible.

Then a transcript, one line per step, each with a status glyph and an elapsed
time. The transcript ends with a re-observation of the rule and reports what
airlock then sees. Status follows observation, never the request's success: a
change that was accepted and did not close the gap is reported as still
failing, and says why.

The screen states the boundary plainly: file-level gaps leave as a pull
request. They are proposed for review and are never written to the default
branch, and this interface does not author them. Settings-level fixes are
applied directly, because they are not files. There is no exception: the
interface writes no file, in any flow, at any point.

Creating a repository is settings-level and is applied directly. Its first
commit is not, and the interface does not make it. An empty repository has no
branch to open a pull request against, so until a first commit exists the
agentic path has nothing to deliver against. The screen names that step,
states that it is performed outside this interface — by a person, or by the
agentic path committing directly to the new repository — and re-observes until
a default branch exists. The pull-request path resumes at that point.

A queue shows the remaining remediations with their rule ids and, for each,
its remediation code, whether it is a file change or a setting, and how it
would be delivered.

**Keymap.** `esc` back · `↵` next in queue · `u` undo, where the change is
reversible · `o` re-observe.

**Status line.** The number remaining in the queue and the statement that
airlock re-observes after every change.

### Policy inspector

**Purpose.** Show the effective policy — every rule the run asked about, and
where each one came from.

**Content.** The rule count and section count, then a table of rule id,
severity bar and name, evaluation, and provenance. Evaluation is a property of
the rule, not of the run: a manual rule reports `judgment_rule` every time and
never becomes mechanical.

The registry digest is shown in full, with a statement of what it is computed
over and what it means — two runs quoting the same digest asked the same
questions. Remediation classification is not part of the digest: two binaries
that agree on the digest agree on what every rule means, and may still differ
on how they would close a gap.

A sources block lists where the rules came from — each policy source with its
reference and its blob identity, and policy-sourced material such as
suppressions marked as policy-sourced rather than registry-sourced.

A run provenance block repeats airlock's version, the registry version, the
schema version, the audited commit, and the time the settings were observed.

**Keymap.** `esc` back · `↑↓` move · `y` copy digest.

**Status line.** The registry version, the abbreviated digest, the rule count,
and the section count.

### Publishing bootstrap

**Purpose.** Walk the five steps that take a package from never-published to
publishing without a stored credential.

**Content.** A statement of why the sequence exists: most registries will not
accept a trusted publisher for a package that has never been published, so a
token exists only to produce that first release, and that token is the thing
the policy is trying to eliminate.

The five steps, each with a glyph, a state, and a note:

1. **Mint a registry token.** Scoped to publishing this package. Airlock never
   displays the value.
2. **Set it as a repository secret.** Observed present; the value is not
   readable back, by GitHub or by airlock.
3. **Wait for a release to run and publish.** The external step.
4. **Configure the trusted publisher.** Binds the repository and workflow to
   the package so publishing needs no token at all. Blocked by step 3.
5. **Revoke the token and delete the secret.** Blocked by step 4. The bootstrap
   is not conformant until the credential it created no longer exists.

Position in the sequence is never remembered. On entry the interface
re-observes the repository secret, the registry credential, and the package's
publish history, and places the operator at the step those observations imply.
The screen says so: closing the terminal does not lose progress, because
nothing here is a saved wizard position.

While step 3 is live, the screen names what it is waiting for, shows how long
ago it last re-observed, and states that the step is an external event that may
take hours and that leaving is expected.

An outstanding credential block is shown for as long as one exists: the secret
name, its scope, when it was created, and the statement that its value is never
displayed. It states that the credential exists solely to complete this
bootstrap and that the flow is not conformant until it is gone.

**Keymap.** `esc` back · `o` re-observe now.

**Status line.** The current step of five, what it is waiting on, and that the
position was re-observed on entry.

## Mid-session expiry

The grant lapses on GitHub's schedule, which can fall mid-session. When it
does, the interface re-authorizes in place: the device flow is presented over
the current screen rather than returning the operator to a launch state.

Interface position is held across the boundary — the selected row, the active
filters, the expanded and collapsed groups, and whether a detail pane was
open — and the screen says what it is holding.

No observation is reused across the boundary. Every visible row is re-observed
once authorization returns, because an observation made under a grant that has
since lapsed is not evidence of the present state.

`esc` abandons the re-authorization and exits.

## Vocabulary

The interface uses the audit's vocabulary verbatim. Rule ids, statuses,
severities, evaluations, sections, evidence codes, error causes, and
remediation codes are printed exactly as the audit emits them, never
paraphrased into interface prose.

Two vocabularies are adjacent and are not interchangeable:

- A **section** is the rule's own grouping. It is not a field on a finding.
  The interface resolves a rule's section from the compiled registry, which is
  the same registry the run attests to with its digest, and the run's own
  record of it is `effective_policy[].provenance`, formatted
  `capability:{capability}/{section}`. A **capability** is a policy-side named
  bundle of sections. The two are not interchangeable, and the interface
  labels a rule's grouping `section`.
- A finding's contextual `remediation.code` is snake_case and describes what
  this failure needs. A rule's declared `remediation_class.code` is
  lower-kebab and describes what the rule's gap always takes. The interface
  shows both under their own names and never merges them.

No token, secret, or key material appears on any screen, including the
credential airlock itself holds. Only its grant and its source are shown.

Illustrative values — rule counts, digests, repository names, device codes,
timestamps — are shapes, not fixtures. Any value the interface renders comes
from the run.

## Provenance

The visual design this specification describes is preserved as an export at
`airlock-tui-design`, alongside the brief that shaped the findings screen into
a work queue. That export is a reference copy. This specification is the
authority for terminal interface behaviour; where the two differ, this
document governs.
