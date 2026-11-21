# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

### Breaking

- The Airlock action is a JavaScript action on `node24` that runs the engine as WebAssembly from the committed `dist/`; no step installs Rust, and no Rust binary is published. It runs repository mode only, on the run's own `GITHUB_TOKEN`, which the engine admits only inside Actions, for the run's repository, when every permission the job declares is `read`. `mode: central` is refused with a message that names the Airlock Worker's scheduled central audit, and the central inputs (`app-id`, `key-name`, `installation-repositories`, `vault-url`, `azure-tenant-id`, `azure-client-id`) and the `airlock-central-report` artifact are removed. A local policy path is refused. The action uploads its report as the `airlock-findings` artifact. Tokens in GitHub's stateless `ghs_<app id>_<JWT>` format are accepted.

### Features

- Observe repository maturity from Intentional baseline and release tag records. Apply each rule from its declared rung, report later rules as out-of-scope, and show prospective assessments for higher rungs.
- Show each observed gap's declared fix, fix kind, reversibility and contextual
  instruction in the audit's human output. The JSON agent work list carries file
  work, operator deferrals, evidence, gate reasons, waivers and run errors.
  The interactive views share one read model. Fixes are derived from fresh audit
  results without credentials; Airlock re-observes before acting. There is no
  separate plan command or JSON plan to apply.
  
  `airlock audit --list-rules` carries each rule's declared fix in the text and
  JSON listings so the fix catalogue can be read before an audit.
- Evaluate capability declarations from organization custom properties and let the interactive session close undeclared decisions through observed property writes.
- Embed the repository-standards skill for offline directory emission, generating its conformance reference from the compiled rules so released audit behavior and agent guidance cannot drift.
- Bare `airlock` opens the interactive release-readiness console: chrome, navigation, both palettes, the status-lane primitive, and a terminal restored on every exit path. Off a terminal it refuses before rendering anything.
- Choose an organization and then a repository in the console: the reachable installations with their kind, repository count, and scope, the three causes of an absent organization, and a filtered repository table whose prior verdicts are orientation only.
- Ship the Airlock GitHub Action with policy, ref, format, outcome, completeness, and findings-location contracts; add a scheduled read-only self-audit; retire the repository settings-write workflow; and encode that replacement posture in rules 0.4. The candidate organisation policy accepts rules 0.4 only, so later semantic versions require deliberate policy review.
- Add the terminal interface's finding detail and policy inspector. The detail reads one rule whole — its evidence, its error with the two 403s held apart at error.cause, the authorization behind a suppression, the fix it retains under one, why the rule applies, and what its status at its severity does to complete and conformant. The inspector shows the effective policy: every rule with its severity, evaluation mode, and provenance, the rules digest in full with what it proves and what it excludes, where the rules came from including policy-sourced suppressions and conditionally enabled rules, and the run's provenance. Readings longer than the terminal scroll rather than being shortened, and both screens can offer their identifying value to the terminal's clipboard.
- Add `airlock auth token`, which verifies the stored profile through the read-path verifier and emits only the verified token, enabling CI to hold a Safe-minted non-expiring `AIRLOCK_TOKEN`. The dogfood CI job now runs the real audit whenever the secret is provisioned.
- The engine builds as a WebAssembly module, `airlock-wasm`, for the Airlock Worker and the JavaScript action. Every request, wait and clock reading goes through one transport interface, which the host supplies in the module. Central sign-in runs in the module too: the host signs in to Entra ID with its own client secret or client assertion, then Key Vault signs Airlock Safe's JSON Web Token and the App, installation and token checks hold as before. CI builds the module on every pull request, holds it to the size budget `docs/wasm.md` states, and compares its findings with the native build's on recorded responses.
- Close the remaining unimplemented repository conformance rules. `REPO-DOCS-05`
  becomes non-gating manual judgment, so a policy that grades it blocking can
  change from incomplete with exit 2 to conformant with exit 0 on rules 0.3.0.
- Re-authorize in place when the grant lapses mid-session: interface position is held across the boundary, every observation made under the lapsed grant is discarded and observed again, and what is left of the grant is on screen before it lapses.
- Add the console's sign-in screen and the write credential behind it.
  
  Bare `airlock` now runs the GitHub App device flow. The screen draws all five
  states the terminal interface specification names — requesting a code, awaiting
  approval with a live poll count and remaining validity, expired, denied, and
  polling interrupted — and each one names its remedy. Expiry and denial issue a
  replacement code in place: the session is not restarted and nothing else is
  lost. An interruption keeps the still-valid code on screen with its backoff, so
  approval already given is not wasted, and a denial states plainly that nothing
  was granted and there is nothing to revoke.
  
  The scan code encodes the address only, because the device flow offers no
  address that carries the code, so the code is always typed and is always
  legible text, spaced character by character over an alphabet that excludes 0,
  O, 1, and I. It paints its own light field and four-module quiet zone rather
  than inheriting the terminal background. It is withheld rather than clipped
  whenever it cannot be drawn whole — at the floor, without the rows for it, and
  under `NO_COLOR` — and says which of those it is, with a key to draw it below
  the code instead.
  
  The write credential has one source, and it is structural rather than
  conventional: the type that holds it can be built from nothing but a device
  grant. It is never written anywhere, never placed in a child process
  environment, never displayed, and its bytes are overwritten when it goes. No
  refresh token is kept. The credential lives in the run loop rather than in the
  drawing state, so what renders the screen cannot reach it.
  
  The accepted app is a compile-time constant, checked by both numeric id and
  slug. A test build accepts Airlock Test, which is installed on one account
  only; the shipped binary accepts Airlock Admin and contains no string that
  could accept anything else, which is asserted against the built artifact.
- The three release-unit conformance rules (REPO-GIT-09, REPO-TASK-04, REPO-LIC-04) now skip with the condition named on repositories that declare no release units, instead of reporting inconclusive forever. Rules 0.2.0.
- Add value- and length-hidden secret entry to the interactive session, with a
  zeroizing buffer and GitHub's repository public-key flow, so credential-secret
  renames can be confirmed and re-observed without exposing their values.
- File-level rules can now be observed from a local working tree (`--working-tree`), as it stands, including uncommitted and untracked content, with gitignored files deliberately excluded. Platform rules stay with the API or are reported as not observed — never passing. Every finding names the source that decided it, and the report carries an observation block stating the run's terms, including dirtiness. A parity test holds the two sources to agreement on every file-level rule for a clean checkout.
- Present the findings screen as a work queue: eight groups ordered by what closing
  each gap takes and who can close it, with the verdict, the standing counts, and
  the aligned score always in view, and a flat rule-id list for lookup.
- Add the publishing bootstrap to the interactive session: the sequence that
  takes a package from never-published to publishing without a stored credential.
  
  The flow persists nothing. On entry, and again on `o`, airlock re-observes the
  repository's bootstrap secret, the package on its registry, and any public
  credential-free publisher signal, and the steps' states are read off those
  observations. Closing the terminal loses no progress because there is no
  progress stored to lose.
  
  Step 2 takes the token's value through the shared secret-entry surface and
  consumes it only after the operator confirms the named write. Completion is the
  re-observed presence of the secret name: GitHub does not read a secret's value
  back, so nothing claims the value works. The outstanding credential is shown by
  name, scope, and creation time for as long as it exists, and the bootstrap is
  not conformant until it is gone. The token's expiry is stated as unobservable
  rather than guessed, and a token that died before the first publish is replaced
  by setting the same name again.
  
  Registries answer differently and the screen says so: PyPI's pending publisher
  skips the ceremony entirely, GHCR's publish-link-publicise path is drawn as its
  own three steps, and a registry that could not be reached leaves the
  publication not established rather than reading as an absent package.
- Add deterministic working-tree alignment. Airlock authors only findings with the `airlock` fix kind, reports every path operation and dirty-tree skip, re-observes the local result, and exposes read-only pull-request context while leaving staging, commits, pushes, and draft pull requests to the caller. Findings with the `agent` fix kind are handed to an agent with the embedded repository-standards skill, and operator settings remain human-only.
- Every registered rule now declares its fix as data: a stable code, what the change would be, whether it is reversible, and its fix kind (`airlock`, `agent`, or `operator`) — or an explicit no-fix reason. Findings carry the classification in a new `fix_class` field. The classification is deliberately outside the rules digest.
- Distinguish contextual fix groups from per-rule fix codes and declare the fix-group vocabulary in the core model.
- Add confirmed interactive application of repository settings with fresh re-observation, guided inputs, transcripts, and undo.
- Add a headless agent work list and definition-of-done check.
- Create repositories from the interactive align session, declaring policy
  capabilities through organization custom properties and creating the initial
  branch with one policy-derived Git Data API commit before running the ordinary
  audit.
- Audit without a stored Airlock credential. The Action's repository mode accepts the run's own `GITHUB_TOKEN` through its `token` input, only inside Actions, for the run's repository, when every permission the job declares is `read`. Its central mode signs in as Airlock Safe through Azure Key Vault with the job's OpenID Connect token, checks the App and its installation, mints a read-only installation token, audits every repository the installation reaches into one report uploaded as an artifact, and accepts no other credential. `REPO-CI-09` now requires one of the two modes and no `AIRLOCK_TOKEN` secret; its fix `supply-airlock-token` becomes `supply-run-token`.
- Distinguish structural from circumstantial inconclusives: a gap the mandated credential can never observe is named, never gated, and never a pass.

### Fixes

- Refuse incomplete ruleset, branch-rule, and tag observations instead of reporting definitive audit verdicts.
- Correct installation repository discovery to use GitHub's documented endpoint.
- The terminal interface has a specification in `docs/terminal-interface.md`: the eight statuses and their three lanes, severity and the gate, the accessibility floor, and each of the eight screens with its purpose, content, keymap, and status line. The findings screen is specified as a work queue grouped by what closing each gap takes, keyed on the declared fix lane.
- Internal hygiene: module splits for the automation and policy domains, structured error payloads, deduplicated check helpers, consolidated test fixtures, and repository lint gates (actionlint, shellcheck, ryl, rumdl) in `task check` and CI. Audit output is unchanged.
- A closed stdout pipe (for example airlock auth token piped to a command that exits early) now terminates silently via SIGPIPE, shell status 141, instead of panicking.

## [Unreleased]
