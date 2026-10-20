# airlock

[![CI](https://github.com/wyrd-company/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/wyrd-company/airlock/actions/workflows/ci.yml)

Audits a GitHub repository against a declared release-readiness policy and
reports what would block a release.

A policy names the checks that apply and how severely each one counts. Airlock
resolves that policy, runs the checks against the repository through the GitHub
API, and prints a findings document. Its GitHub client never writes: every
credential is verified read-only before first use. The local `align-files`
command may author deterministic files in an explicit working tree, but never
stages, commits, pushes, or opens a pull request.

## Install

Not yet published to any registry. Build from source:

```sh
cargo install --git https://github.com/wyrd-company/airlock airlock-cli
```

## Install the `repository-standards` skill

Airlock carries the complete `repository-standards` agent skill, including its
platform references, topics vocabulary, and templates. Emit it directly into
your agent skill directory:

```bash
airlock skill ~/.agents/skills/repository-standards
```

The target must not exist. Use `--force` only to replace a tree previously
emitted by Airlock; the command verifies its `.airlock-skill` provenance marker
and refuses any other file or directory. Airlock never merges an emitted tree
with local changes. To adopt an older standalone copy that has no marker, move
it aside and emit a fresh tree. With no target, the command writes
`repository-standards` in the current directory.

The generated `references/conformance.md` quotes the compiled rules version
and digest. Its rule statements, severities, sections, and evaluation modes
come from those rules; the remaining guidance and reference material is
hand-written in Airlock. This includes the rule-by-rule inspection guidance in
`references/check-guidance.md`, which is joined into the generated checklist
without owning its evaluation modes. Command output also reminds operators to
cite a rule id and its statement together, never the id alone.

The minimum supported Rust version is 1.88.

## Quickstart

Acquire a read-only credential, then audit a repository:

```sh
airlock auth login
airlock audit wyrd-company/airlock
```

## The console

Bare `airlock`, with no arguments, opens the interactive release-readiness
console:

```sh
airlock
```

The console is the only surface that carries out the closing moves a person
must make, and it has no subcommand and no flag. An agent holding this binary
therefore has nothing to invoke: the guarantee is that the code path does not
exist, not that a check declines to take it.

Creating a repository is align against the maximally unaligned case. The
operator chooses the owner, names the repository, and chooses its visibility
and declared capabilities in the console. Because an empty repository has no
branch against which Airlock can open a pull request, the console writes the
first commit directly: a single branch-creating commit carrying the
deterministic files the owner's policy requires. That commit is the sole direct
file-write exception; after it, Airlock audits the repository normally and
every later file change follows the ordinary pull-request path. Airlock ships
no policy and no built-in scaffold.

It requires an interactive terminal on both stdin and stdout. Under a pipe, a
redirect, or a scheduler it exits non-zero without rendering anything, and names
what to run instead. `airlock audit` is the complete unattended findings
surface, and `airlock agent-work` is its work-list projection for an executing
agent.

Two keys are live everywhere: `t` switches between the dark and light palettes,
and `ctrl-c` exits. `NO_COLOR` is honoured, and every distinction the interface
draws survives it. The terminal is restored on every exit path, including a
panic and a signal.

See [terminal interface design](docs/technical-designs/terminal-interface.yml) for what each
screen shows and why.

## GitHub Action

The Action audits through the GitHub REST API, so the repository being audited
does not need to be checked out. Give the step an `AIRLOCK_TOKEN` secret and,
if the owner does not publish the default policy, name a policy explicitly:

```yaml
permissions:
  contents: read

steps:
  - id: audit
    uses: wyrd-company/airlock@0123456789abcdef0123456789abcdef01234567 # 0.0.1
    env:
      AIRLOCK_TOKEN: ${{ secrets.AIRLOCK_TOKEN }}
    with:
      policy: example/.github:airlock/policy.yml
      ref: ${{ github.sha }}
      format: json
  - if: always() && env.AIRLOCK_FINDINGS != ''
    uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
    with:
      name: airlock-findings
      path: ${{ env.AIRLOCK_FINDINGS }}
```

Replace the example revision with the full commit SHA for the Action release
your repository has reviewed, retaining the release version comment.
`repository` defaults to the repository running the workflow. `policy`, `ref`,
and `format` (`json` or `text`) are optional. The step exposes `outcome`,
`complete`, and `findings-location`; the last is an absolute runner path that
can be uploaded as an artifact even when the audit fails.
The Action also exports `AIRLOCK_FINDINGS`, `AIRLOCK_OUTCOME`, and
`AIRLOCK_COMPLETE` to later steps because GitHub may not propagate composite
outputs after a failing inner step.

The Action preserves Airlock's exit codes: conformant exits `0`,
nonconformant exits `1`, and incomplete exits `2`. An incomplete audit fails
the step by default. Set `fail-on-incomplete: "false"` only when the workflow
must continue despite an unanswered audit; the outputs still say
`outcome: incomplete` and `complete: false`. Nonconformance always fails.

`AIRLOCK_TOKEN` must be minted by the Airlock Safe GitHub App as described in
[Provisioning CI](#provisioning-ci). The Action does not use the workflow's
automatic GitHub token. Before making any audit request, the same verifier as
the command-line interface enumerates the credential's authority and refuses
it if any permission is writable or cannot be proved read-only. Airlock has no
mutating GitHub client methods, and the Action only builds and runs Airlock, so
it can report changes but can never apply them.

`AIRLOCK_TOKEN` is present in the environment of every composite step,
including the toolchain setup and cached source build. The positive read-only
verification is therefore the security boundary; the Action does not claim
credential isolation from the build it performs.

With no `--policy`, airlock reads `{owner}/.github:airlock/policy.yml` for the
audited repository's owner. Airlock ships no built-in policy, so a repository
whose owner has none cannot be audited — that is an error, not an empty run.

Output is text on a terminal and JSON otherwise, so piping needs no extra flag:

```sh
airlock audit wyrd-company/airlock --policy ./policy.yml | jq '.summary'
```

At the end of an agent's work, `agent-work` re-runs the same audit and projects
its findings into the agent's file work:

```sh
airlock agent-work wyrd-company/airlock --working-tree .
```

Its `agent_work` contains Gaps classified as `airlock` or `agent`.
`operator_deferred` lists operator work. `needs_decision` and
`run_errors` name missing inputs and failed observations. `waived`, `routed`,
`unbuilt`, and `out_of_scope` list rules not evaluated here. These lists
carry counts, identities, reasons, and settling surfaces. The `observation`
block records whether files came from the API tree or the local working tree.

This check establishes whether the agent work list is clear. A clear list can
coexist with operator work,
unbuilt checks, waivers, routed or out-of-scope rules, and other repository
gaps; run `airlock audit` for the complete findings authority.

`airlock audit --list-rules` prints the complete rules: every rule id,
its statement, its severity, its compiled check and declared gates, and what
closing its gap would take.
That last part is the fix catalogue — read it to know what airlock
would do to a repository before pointing it at one.

To see what it would change about a particular repository rather than in
general:

```sh
airlock plan wyrd-company/airlock
```

To author only the Airlock fix kind in a checkout:

```sh
airlock align-files wyrd-company/airlock --working-tree .
```

## What the exit code means

| Code | Result | Meaning |
| ---- | ------ | ------- |
| `0` | `conformant` | No blocking Gaps and no run errors |
| `1` | `nonconformant` | At least one blocking Gap, with no run errors |
| `2` | `incomplete` | Airlock could not complete its job |

An evaluated rule has exactly one outcome: `met` or `gap`. Severity is
`none`, `advisory`, or `blocking`. A blocking Gap sets exit `1`; an advisory
Gap leaves the exit code unchanged. An agent assessment is advisory evidence;
only the compiled check decides Met or Gap.

The JSON document uses schema version `2`. Its `findings` list contains the
Met and Gap results. Separate lists identify work without an outcome:

- `waived`: effective severity `none`; the check does not run. Each entry names
  the rule and its authorization reason.
- `routed`: a compiled gate sends the rule to another run or surface.
  `needs-github-api` routes the whole rule to a credentialed API-tree audit
  or Action. A disclosure gate names the interactive session. An unobserved
  repository owner routes the Renovate preset comparison after file presence,
  valid JSON, typed `extends`, and a nonempty preset list have been checked. The
  built-binary regression `renovate_without_owner_preserves_json_and_extends_diagnostics`
  covers these independent diagnostics.
- `unbuilt`: this evaluation reaches a declared part of the check that Airlock
  has not built. It names the reason and needs a release with that check built.
  Other branches of the same check still decide Met or Gap.
- `out_of_scope`: a compiled check reached its declared release-unit boundary.
  Reason `out-of-scope` means no release units are declared. It has no Met or
  Gap outcome and leaves the exit code unchanged. Malformed declarations are
  run errors.
- `run_errors`: a failed read, exhausted budget, truncated input, or missing
  input with no declared gate. Every run error sets exit `2`, at any severity.
  A credentialed endpoint failure is a run error, never routing.
  Absent required topic reference data defaults to severity `none`, with waiver
  reason `no reference data configured` when the topic map is absent. A partial
  map names its missing required topic categories in alphabetical order.
  Configured malformed data remains a run error. The regressions
  `absent_topic_configuration_waives_checks_before_reading_repository_inputs` and
  `partial_topic_configuration_names_missing_categories_before_reading_repository_inputs`
  exercise both waiver reasons.

Waived, routed, unbuilt, and out-of-scope entries have no Met or Gap outcome and
do not change the exit code. A rule is evaluated whole or routed whole when
it requires an API-only fact. Other rules continue to run. A clean report
with waivers, routed, unbuilt, or out-of-scope work is distinguishable from one
where every rule was evaluated.

The tests `decided_outcomes_match_the_integration_base`,
`a_waived_rule_does_not_run_its_check`,
`the_api_gate_routes_a_whole_file_tree_rule`,
`disclosure_routing_and_a_missing_input_without_a_gate_are_distinct`, and
`unbuilt_branches_preserve_decided_outcomes` verify these contracts.

The binary's exit contract is unconditional. The composite Action retains
`fail-on-incomplete: "false"` as an adapter override: it maps binary exit `2`
to Action success while reporting `outcome: incomplete` and `complete: false`.
The override also covers setup errors such as a missing `AIRLOCK_TOKEN`.
`scripts/test-action.sh` verifies this mapping. Blocking Gaps still fail the
Action.

On Unix, a closed output pipe terminates silently on signal 13 (`SIGPIPE`),
commonly reported by shells as status 141.

`airlock agent-work` asks whether agent file work remains. Its codes are `0`
for `agent_work_clear`, `1` for `agent_work_remains`, and `2` for
`could_not_settle`. It retains waived, routed, unbuilt, out-of-scope, and
run-error lists.
Operator work does not turn a clear agent work list into a claim that the repository
meets every rule.

## Fix kinds

Every registered rule declares, as compiled-in data, what closing its gap
takes. Each finding carries that declaration in `fix_class`: a stable
code, what the change would be, whether it is reversible, and the fix kind it
travels in — or `none_reason` when airlock offers no fix. The
classification tells the consumer who can act and through which surface.

| Fix kind                 | What it means                                                                                              | Who does the work                                 |
| -------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `airlock` | The same gap resolves to the same file content in every repository                                         | Airlock authors locally; the caller delivers a PR |
| `agent`      | The fix is repository-specific file content — prose, or configuration wired to this repository's toolchain | An agent authors it; a human reviews              |
| `operator`   | The fix sits behind the administration API, and `administration: write` is indivisible                     | A human, behind the TUI                           |
| _(none)_             | A human attestation, a fix outside the repository, or history surgery airlock will not automate            | Nobody — the reason says why                      |

Fix kind is the only authorship gate. Mechanical evaluation is not enough:
README presence, task wiring, job permissions, and other mechanically observed
facts can still need repository judgment and therefore remain
`agent`.

The classification is not part of the rules digest. The digest attests what
every rule means and how it is evaluated — the contract a policy binds to with
`requires-rules`. Fix is airlock's answer to a gap, and a better
answer must not invalidate policy compatibility.

## Planning what would change

`airlock plan` observes a repository and prints the change each open gap calls
for, grouped by fix kind: what an operator can apply directly, what airlock can
author, and what needs an author's judgment. Each entry names the rule, its
fix code, what the change would be, and whether it can be undone.

```sh
airlock plan wyrd-company/airlock
```

It reads the repository through the same verified read-only path the audit
uses. There is no write anywhere behind it, and no flag that adds one.

A plan is a display, and the output says so. Nothing consumes it: it has no
JSON form, it is never stored, and it is never handed to anything that applies
changes. Aligning re-observes each rule immediately before acting on it and
decides from what it then sees — a plan printed a minute ago describes a
repository that may since have changed, and acting on it would be acting on a
remembered observation. Machine consumers read the audit's findings document,
which carries the same `fix_class` this is derived from.

An authorized failure keeps its fix on offer and is marked as standing
debt: a suppression permitted the failure, it did not close the gap. A rule
airlock could not decide proposes nothing and is named separately, because
there is no observed gap to propose a change for.

`airlock plan` exits 0 whenever it could observe and render at all. It is not a
second gate; `airlock audit` is the surface whose exit code carries the
verdict.

## Closing settings gaps

The interactive terminal session is the only surface that holds the
write-capable Airlock Admin credential. Opening a repository performs a fresh
full observation. Applying a settings fix then observes that rule
again immediately before the request and once more afterwards. The transcript
reports the request as one step, but derives pass or fail only from the final
observation. An accepted request that leaves the setting unchanged remains a
failure in the queue.

The confirmation names the rule, fix code, exact change, and
reversibility before any request is sent. Input-free settings of the same kind
can share one confirmation, but each retains its own pre-observation, request,
post-observation, and transcript. Transfers, repository names, and ruleset
choices are confirmed singly from values the session has freshly observed or
the operator has explicitly entered. Airlock never guesses a target.

GitHub does not reveal secret values. A credential rename that creates a new
secret therefore opens the shared value- and length-hidden entry surface; the
operator supplies the value immediately before confirming the named write.
The value never enters the queue, confirmation, transcript, or any rendered
frame, and airlock never claims it verified the value works. No settings flow
writes a repository file.

## Closing file gaps

`airlock align-files` is non-interactive and single-repository. It observes the
working tree, authors only failing `airlock` findings, and then
re-observes the affected rules through the working-tree source. It consumes the
same `worktree::read_facts` boundary as the audit; a path that boundary refuses
is refused here too.

Dirty trees are normal in agent loops. The command reports dirtiness before
and after, but does not reject it. A target path already modified relative to
HEAD is skipped with a reason, including a path made dirty only by checkout
line-ending normalization. Each successful path is written through a temporary
file and same-directory rename. A failure exits nonzero and includes every path
already written and the path not written.

When several findings claim the same file, one fix owns that path for
the run. The report tells the caller to commit that write and run the command
again; the next observation, not a remembered finding, decides what remains.

The JSON and text reports include path operations, rule ids, fix
codes, skipped reasons, post-write findings and their sources, agent-work
delegations, and read-only pull-request context. The well-known delivery branch
is `airlock/align`. `open`, `none`, and `unknown` are distinct; unknown never
means none. A second run re-observes the checkout and writes nothing when the
repository is unchanged.

Airlock stops before every git operation. The caller chooses commit
granularity, stages and commits the reported paths, pushes `airlock/align`, and
opens a draft pull request. Where `CODEOWNERS` exists, the caller derives and
requests the applicable reviewers from that file; where it does not, the
pull-request description says plainly that no CODEOWNERS reviewers were
available. The command's read-only observation reports an existing pull
request so the caller can suppress duplicates. Live caller-side duplicate
suppression remains an integration responsibility.

Agent fixes are not filled with boilerplate. The report hands their
rule, fix, evidence, and source to an agent. Emit task 82's embedded
guidance with:

```sh
airlock skill repository-standards
```

The agent authors the repository-specific content and sends it through the
same draft-pull-request review. Operator-setting findings never enter either
file path: they require a person in the terminal interface because GitHub's
`administration: write` permission is too broad to grant an agent.

The CLI release used here should be pinned with the same released-version
discipline documented under [GitHub Action](#github-action); the packaged
audit Action does not invoke `align-files`. A fleet workflow installs the CLI,
checks out one repository per matrix job, and invokes this single-repository
command. Airlock does not add a second multi-repository runner or aggregate
fleet results.

The post-write working-tree result says what is true locally. The default
branch remains unaligned until the pull request merges, so an API observation
of the default branch stays open in the meantime.

## Two observation sources

File-level rules can be observed two ways; platform rules only one.

- **API tree** (the default): every git-backed fact is read from GitHub at a
  single resolved commit. This is the source for scheduled audits, the
  Action, and any run without a checkout. Airlock never requires a clone.
- **Local working tree** (`--working-tree <path>`): file-level rules are read
  from a checkout on disk, **as it stands** — including uncommitted and
  untracked content, because that is what an agent that just wrote changes is
  asking about. Gitignored files are excluded: a rule satisfied only by an
  ignored file is not satisfied. Tracked files are still read even when an
  ignore rule matches them.

Platform rules — settings, rulesets, tags, history, secrets — have no local
equivalent and are never inferred from a working tree. With a repository and
a credential (`airlock audit owner/repo --working-tree .`) they still come
from the API and the run mixes sources; without a credential
(`airlock audit --working-tree . --policy ./policy.yml`) each rule with a
declared API gate is listed as `routed`, with reason `needs-github-api` and the
credentialed API-tree audit or Action as its settling surface. Routing leaves
the exit code unchanged.

Every finding carries a `source` field naming what decided it (`api` or
`working-tree`; null when nothing observed it), and the report carries an
`observation` block stating the run's terms: which source served each half,
the working tree's HEAD commit, and whether the tree was dirty. "Clear
against an unpushed working tree" and "clear against the default branch" are
different facts; the output never lets one wear the other's words. A local
result with `dirty: true` describes something not yet committed, and a
working-tree run that had to assume the default branch says so with
`default_branch_observed: false`.

## Policy

The policy is YAML. It selects sections of the rules through
capabilities, refines individual rules, and decides who may suppress what.
It expresses no logic of its own: the checks are the only place logic lives.

```yaml
version: 1
name: wyrd-company
requires-rules: ">=0.2" # the binary's rules must satisfy this

capabilities:
  base: [identity, licensing, files, git, automation]
  rules: [release]

checks:
  REPO-META-06:
    params: { min-topics: 3, max-topics: 8 }
  REPO-FILE-10:
    severity: advisory
  REPO-DOCS-04:
    enabled: false

suppressions:
  allow-repo-requests: [REPO-DOCS-01, REPO-DOCS-02]

reference-data:
  topics: wyrd-company/.github:airlock/topics.yml
```

Template identity uses an organization exception. Select `release` in the
`rules` capability and list each required parent template:

```yaml
exceptions:
  REPO-TPL-01:
    reason: Governed repositories use this release process.
    record-path: .toha.json
    templates:
      - source: gh:example-org/catalog#bundle
        ref: main
        minimum: release@2.0.0
        parts: [alpha, beta]
```

Each parent is required at its `target` (default `.`) inside the configured
record. The recorded Git commit must be reachable from `ref` and equal to or
descend from `minimum` when specified. Selected parts must be listed; listed
parts need not be selected. An empty template list is visibly not configured.
Organization policy can lower the compiled blocking severity. Repository
refinements and suppression requests cannot override this rule.

The check validates the record as JSON against the embedded Toha applied-record
schema. JSON evidence includes each expected parent, found identity, resolved
refs, comparison statuses and Gap reasons. Apply, update or baseline with Toha,
select accepted parts, and commit the result to close a Gap. Missing credentials
route the whole rule; unreadable API inputs and exhausted budgets are run errors.
`template_audit_reads_configured_record_at_captured_commit_and_compares_both_directions`
and `template_audit_without_credential_routes_whole_rule_without_template_api_calls`
exercise these contracts through the REST transport and report.

Capabilities select sections until the two-file configuration replaces this
policy format. `apply` selectors and the separate `gate` threshold are rejected.
Severity alone determines whether an evaluated Gap fails the audit.

Anything airlock does not recognise — an unknown key, section, rule id,
parameter, or severity — is an error, never a silently narrower
audit. `--policy owner/repo:path[@ref]` names a policy explicitly, and
`--policy ./path` reads a local one for development.

Before any check runs, the policy and every transitive reference are resolved
to immutable identities — a commit and blob sha for remote sources, a content
hash for local ones — and hashed into a **policy bundle digest** that travels
in every result alongside the rules version and digest. Two runs that agree
on those three values ran the same rules against the same policy.

Each source is also reported individually under `policy.sources`, with what it
pinned to, so a reader who sees the bundle digest move can tell which reference
moved it:

```json
"sources": [
  {
    "name": "topics",
    "source": "wyrd-company/.github:airlock/topics.yml",
    "commit": "def456…",
    "blob_sha": "abc789…",
    "content_digest": "sha256:…"
  }
]
```

Suppression authority lives in the policy. An audited repository's
`.github/airlock.yml` holds _requests_:

```yaml
version: 1
suppress:
  - rule: REPO-DOCS-01
    reason: "docs are design notes until the first release"
```

A request is honoured only where the policy's `allow-repo-requests` names that
rule, and the honoured finding records both the request's reason and the
policy's authorisation. Anything else leaves the finding exactly as it was and
records the attempt in `policy_observations`. The repository being judged never
controls the exceptions to the judge.

Worked examples are in [`docs/examples/`](docs/examples/).

## Credentials

Airlock has two credential paths. They share no code, no storage, and no
identity, and neither can reach the other's.

### The read path

Every subcommand runs on it. Airlock reads a token from `--token`,
`--token-file`, or `--token-stdin` first, then `AIRLOCK_TOKEN`, then the profile
written by `airlock auth login`.

It deliberately ignores `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential store,
and git credential helpers. A tool that refuses write access should not quietly
pick up the write-capable credential already sitting in your environment.

`--token` puts a credential in your shell history and in process listings.
Prefer `--token-file` or `--token-stdin`.

Every token is verified before its first use, and the rule is positive
enumeration: airlock accepts a token only when it can list the token's whole
grant and every entry in that list is a read.

- **`ghu_`**, issued by the Airlock Safe app: every installation the token can
  reach is listed, across every page, and each must be attested to that app by
  **both** its numeric app id and its slug — an id survives a rename, a slug
  does not — and must carry only `read` permissions.
- **`ghp_` / `gho_`**: the exact scopes from `X-OAuth-Scopes` must all appear on
  a closed, reviewed list of scopes whose full authority is read-only. An
  unknown scope is refused rather than assumed safe, a missing header is an
  unread grant rather than an empty one, and a response carrying the header
  twice has no single answer and is refused too.
- **`github_pat_`**, **`ghs_`**, and unknown prefixes are refused as
  unverifiable. GitHub offers no way to enumerate a fine-grained token's
  permissions, and probing for write access would break the read-only contract
  airlock exists to keep.

`airlock auth status` says which source would be used and what it grants.
`airlock auth login` runs the device flow and stores the result at
`$XDG_CONFIG_HOME/airlock/config.toml`, created `0600` before anything is
written to it, replaced atomically, and refused on later runs if it has become
a symlink or readable by anyone but you.
`airlock auth token --profile <name>` verifies a stored profile and writes only
its token to standard output; see [Provisioning CI](#provisioning-ci).

### Provisioning CI

The repository's dogfood job accepts only an `AIRLOCK_TOKEN` minted by the
Airlock Safe GitHub App. The supported CI credential is a non-expiring `ghu_`
user access token:

1. An operator disables **Expire user authorization tokens** in the Airlock
   Safe app's optional features.
2. The operator runs `airlock auth login --profile ci` and approves the device
   flow in the browser. With expiry disabled, the profile stores the access
   token without an expiry or refresh token.
3. The operator runs `airlock auth token --profile ci`. Airlock verifies the
   stored token is Airlock-Safe-issued and wholly read-only before writing only
   the token to standard output.
4. The operator pipes that value into the `AIRLOCK_TOKEN` Actions repository
   secret for `wyrd-company/airlock`:

   ```bash
   airlock auth token --profile ci |
     gh secret set AIRLOCK_TOKEN --repo wyrd-company/airlock
   ```

   If the receiving command exits before reading the token, Airlock follows
   normal Unix pipe semantics: it exits silently on `SIGPIPE` (signal 13,
   commonly reported by shells as status 141) rather than printing a panic.

Treat the output of `airlock auth token` as a secret: keep it out of shell
history, logs, and shared terminals. The dogfood job runs the real audit
whenever the repository secret is present and reports a graceful skip when it
is absent.

This chooses a long-lived credential to avoid giving CI any write authority.
GitHub rotates refresh tokens on every exchange, so refreshing in a job would
either require forbidden `secrets: write` access to persist the successor or
leave later and concurrent jobs with a stale token. The accepted trade-off is
a long-lived token whose permissions are read-only by app registration and are
verified again by Airlock before every audit. To rotate it, repeat the device
flow and replace the repository secret.

### The write path

The interactive console runs on it, and reads with it too, so a session never
acquires a second token.

It has exactly one source: the GitHub App device flow, approved by you in a
browser. There is no config file entry, no environment variable, and no
command-line flag, because the type that holds the credential can be built from
nothing else. Everything below is a property of the code rather than a policy
it follows:

- **It is never stored.** Not in a file, not in the environment, not in a child
  process, and not after the session ends. Its bytes are overwritten when it
  goes — wherever it is dropped, including on the way out of a session that has
  already closed. A session leaves its home directory and its working directory
  exactly as it found them; the suite runs one and watches both.
- **No refresh token is kept.** GitHub sends one alongside the access token; it
  is overwritten on arrival and never reaches the session.
- **No child process is started**, so there is nothing to export it to. The
  console does not open your browser for you, for exactly that reason.
- **Its value is never displayed.** The sign-in screen shows the credential's
  source and its grant, and nothing else. The interface is not given the
  credential at all: it is told that one exists, and the type that draws names
  nothing that could carry it.
- **Nothing a server says is executed by your terminal.** Codes, addresses, and
  error text are sanitized where they leave the network worker: control
  characters, escape sequences, and bidirectional overrides are replaced, and
  lengths are bounded.
- **A scan code never points anywhere the response chose.** A scan code is
  followed without being read, so one is drawn only for an address at the origin
  airlock sent its own request to. Any other address is printed as the text it
  is, and the screen says why it was not encoded.
- **There is no subcommand and no flag** that acquires it, and none that
  mutates. `--yes` exists on nothing.

The grant is write-capable because applying a repository or organisation
setting requires `administration: write`, which GitHub does not subdivide. That
grant belongs to the interactive session alone. `airlock audit` refuses any
token carrying write access, and does so before its first request.

The accepted app is bound at compile time, by both its numeric id and its slug —
an id survives a rename and a slug does not, so neither alone is sufficient. A
runtime override would be a way to point airlock at an app of someone's
choosing, which is the whole thing the binding prevents.

| App           |    App id | Slug            | Client id              | Build                      |
| ------------- | --------: | --------------- | ---------------------- | -------------------------- |
| Airlock Admin | `4409767` | `airlock-admin` | `Iv23li6LeVszqbchI9Ah` | shipped                    |
| Airlock Test  | `4419504` | `airlock-test`  | `Iv23liTl9KRNwxjFhrfA` | `--features test-identity` |

**Airlock Test is a development affordance**, not a supported configuration. It
is installed on `mmenm` only, and that bound is the point of it: while the
aligning code is least trustworthy, a wrong repository selection cannot reach a
production account, because the console's organization list is the set of
reachable installations and no production account is on it. A shipped binary is
built without the feature and contains no code, and no string, that could accept
it; the test suite asserts that against the built artifact rather than against a
setting.

Airlock Admin's registered grant is:

| Permission                       | Level |
| -------------------------------- | ----- |
| `metadata`                       | read  |
| `actions`                        | read  |
| `administration`                 | write |
| `contents`                       | write |
| `environments`                   | write |
| `secrets`                        | write |
| `variables`                      | write |
| `organization_administration`    | write |
| `organization_secrets`           | write |
| `organization_custom_properties` | admin |
