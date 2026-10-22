---
relationships:
  references: ../hosted/src/shared/report.ts
  implemented-by: ../hosted/src/service/worker.ts
---

# Hosted browser

Airlock's hosted browser presents organization and repository conformance. The
Cloudflare Worker serves a browser read model through an adapter. The Rust audit,
agent work list, Action, and terminal console operate independently.

## Local development

This increment uses synthetic reports. It connects to no GitHub or identity
service. From `hosted/`:

```sh
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://localhost:5178`. The development server supplies the fixture API.
For the local Worker and static assets, run `pnpm build`, then `pnpm preview`,
and open `http://localhost:8788`. Run `pnpm check` for type checks, focused tests,
and browser assets. Run `pnpm format:check` for formatting.

The Worker requires explicit local fixture configuration and a loopback URL.
External hosts receive an unavailable response. These checks separate a local
preview from an unimplemented hosted runtime; they are not authentication or a
safe deployment configuration. This increment has no deployment script,
credentials, live reads, settings writes, or schedule cadence.

## Browser contract

The cross-organization view contains summary cards only. Selecting an
organization opens its repositories, sorted by blocking results, advisory
results, incomplete results, then repository name. Work queue buttons filter
that list by fixer. Blocking and advisory counts have visible text labels in
both repository list rows and detail headings. Unassigned repositories appear
separately and are not gaps.

Organization sections are Repos, Rules, Assignments, and Pull requests. Results
are grouped as You, Airlock PR, Agent, Not fixable, and Couldn't evaluate.
Passing, waived, and not-applicable results are collapsed below failures.
Repository result filters select all results, failures, passes, incomplete
results, or failures by severity. Sorting preserves fixer groups and the
collapsed passing section: report order, severity, or rule id applies within
each section. Changing a result filter clears fix selection. The shown/total
count makes filtered results explicit.

One engine result appears as one row. When an engine result has more than one
fixer, it appears in the first applicable group in the listed order and names
all fixers; work queue filters match every fixer. Its detail preserves all
organization and repository instances, their independent conditions and config
commits, and relaxation warnings. The browser does not recompute AND results,
severity, fix derivation, or rule predicates.

The Rules section is a per-id index with expandable observations. Each
observation names its repository, maturity rung, statement and effective
severity; the index does not choose one repository's values as global values.
Repository result details hold instance-specific requirements. The fixture API
has only organization summary, selected organization, and unavailable session
reads. Mutation requests return an unavailable response even with a token.

Reviewing settings fixes shows selected requirements. It does not claim that
requirements are an executable, reviewed change batch. Real exact before/after
changes must come from a server-side planner that re-observes GitHub state.
Config proposal drafts remain in their dialog. No proposal is submitted or
merged.

## Adapter boundaries

`shared/report.ts` defines a synthetic hosted input/view shape. It does not
match core output. `projection.ts` projects that synthetic shape only;
`fixtures.ts` supplies local sample data. No real core report is accepted here.
A boundary adapter and validation against serialized engine output are required
before connection. Invalid or unobserved input must remain incomplete, never
become a passing observation.

The core report fixture has these differences that the integration adapter must
handle explicitly:

- Core has no report `observed_at`. Hosted observation time requires an explicit
  source; it cannot be invented from a config commit or display placeholder.
- Core repository entries include `audited_commit`, which the hosted synthetic
  shape does not carry.
- Core assignments are objects with `id`, `matched` (`true`, `false`, or `null`)
  and `diagnostic`; hosted assignments are string ids.
- Core statement, severity and diagnostic are per instance. Statement can be
  null. Both shapes retain aggregate effective severity; core also retains each
  instance's severity. Core reason and relaxation reason are separate nullable
  fields. The synthetic hosted shape places statement on the aggregate rule,
  requires an instance reason, and uses a rule-level `detail_code`. Invalid
  rules have instance `diagnostic.code = invalid-rule` and remain not evaluated.
- Core fixes are tagged `action` (with `fixer: person|airlock`, `action`, `input`),
  `agent` (with `guidance`), or `not-fixable` (with `reason`). The synthetic hosted
  shape uses a UI fixer, an origin and a description. Mapping cannot assume an
  executable change or reconstruct declaration origin from an absent field.
- Core condition evidence includes index, result, flavor, diagnostic, expected
  JSON, probe, pointer, evaluation, `observed_digest`, reason and fix. It does not
  disclose raw observed contents. The synthetic conditions use display strings
  `label`, `expected` and `observed`. A digest is not raw observed evidence.
- Core warnings use `rule`, `code`, `reason`; synthetic warnings use `rule_id`,
  `code`, `message`.
- Core lists an unassigned repository both in `repositories` (with zero rules
  and nonmatching assignment observations) and `unassigned_repositories`. The
  hosted synthetic list contains assigned repositories only. The adapter must
  separate these entries; an unassigned repository is not a passing assigned
  repository and must not inflate assigned counts.

`ReportStore` is an asynchronous read port. Its local implementation copies
fixtures to prevent a caller from changing stored reports. A live store needs
verified organization visibility and persistence. No live adapter is provided.

`integrations.ts` expresses unavailable Truename step-up, Admin authorization,
and config proposal ports. Those methods fail closed. The interface is not a
claim about Truename's protocol. A real step-up must cover one immutable digest
of exact listed changes, the browser person and session, fresh user verification,
and atomic single-use consumption. No API token or CLI may produce it.

The Admin session begins on the first batch review, with inline GitHub
authorization. It ends on sign-out, tab close, or GitHub's eight-hour token
expiry. It uses no refresh token and no Airlock idle timer. The live token
custody, reliable tab-close termination, same-person identity binding, and
single-use distributed confirmation storage require an explicit integration
contract. This increment stores no credential or session.

`WebhookVerifier` must validate the signature, installation and organization
scope before producing a target. `receiveWebhook` enqueues that verified target.
`sweep` enumerates installed organizations through a port and queues an org audit.
No default verifier, durable queue, storage, GitHub Safe credential, cron trigger,
retry policy, or HTTP webhook admission is connected. The Worker's scheduled
handler reports unavailable. Tests use explicit local doubles.

## Security decisions required before connection

Truename's step-up protocol, identity binding and browser-session custody must
be verified. Config PR credential custody and enforceable cannot-merge behavior
remain unresolved. A contents-write credential alone does not establish a
cannot-merge boundary. These ports remain unavailable until their contracts are
approved and implemented. Airlock Safe must be proven read-only; Admin access
belongs only to the browser person's session.

Cloudflare integration uses its documented
[static asset binding](https://developers.cloudflare.com/workers/static-assets/binding/)
and reserves its
[scheduled handler](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
for an authorized future sweep configuration.
