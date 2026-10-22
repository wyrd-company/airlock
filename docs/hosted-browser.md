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

The local preview reads an unedited serialized Rust engine fixture through a
typed adapter. It connects to no GitHub or identity service. From `hosted/`:

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
observation names its repository, maturity rung, instance statements and effective
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

`shared/engine-report.ts` describes the Rust Serde input contract.
`report-adapter.ts` validates unknown JSON and converts it to `shared/report.ts`.
Invalid required fields, enums and fix tags return `invalid-engine-report` with
a field path. Both report endpoints return HTTP 503, including bodyless HEAD;
invalid input cannot become a healthy empty report. The Worker and Vite API use
`engineReportStore`, not the synthetic fixtures reserved for unit boundary cases.

Aggregate result, flavor and severity come from the engine. A row is identified
by rule id; statement, severity, reason, relaxation reason and diagnostic stay
with their own source instances. Config repository/path/commit and repository
`audited_commit` remain distinct. Conditions retain index, expected JSON, probe,
pointer, evaluation, result, flavor, diagnostic, reason and tagged fix plan.
`observed_digest` is labeled as digest evidence, never raw observed content.

Assignments retain id, `matched: true|false|null`, and diagnostic. True means
assigned, false means not matched, and null means unknown. Explicit unassigned
repositories appear once in a separate list with their metadata; they do not
inflate assigned counts or healthy cards. An unknown assignment remains visible
and increases the incomplete count, including when the repository has zero
rules. The Assignments section shows all three states and diagnostics.

Warnings retain their rule id, code and reason, and appear only on that rule.
The containing organization/repository config sources remain available for
inspection. Tagged fixes retain the entire plan: action with person/airlock,
action and JSON input; agent guidance; or not-fixable reason. Person maps to You
and airlock to Airlock PR. Multi-fixer display order is retained; passing
instances contribute no actionable fixes. Not-evaluated takes group precedence.
A displayed plan is not an authorized or executed change. Declaration origin is
absent from the engine output and is not inferred.

The separate observation supplement permits unavailable time, explicit audit
time, or capture time. Unavailable time displays as unavailable. Capture time is
labeled capture time. Config commits cannot supply audit time. No archive,
language, default-branch, visibility, raw observation or declaration-origin
metadata is fabricated or fetched. Unsupported fields remain absent in the API
and browser readers.

### Fixture refresh

`hosted/fixtures/configurable-report.json` is an unedited engine export.
`provenance.json` records its producer source head, source/lock/output hashes,
toolchain and capture time. `observation.json` explicitly supplies unavailable
audit time. From the repository root, export to a temporary file:

```sh
AIRLOCK_CONFIGURABLE_FIXTURE_OUTPUT=/tmp/engine-report.json CARGO_BUILD_JOBS=2 \
  cargo test --offline --locked -p airlock-core --test configurable_rules \
  report_contract_fixture_is_serialized_by_the_real_engine -- --exact
cmp /tmp/engine-report.json hosted/fixtures/configurable-report.json
```

When engine changes require a refresh, copy the generated bytes intact and
update provenance and consumer assertions together. Prettier excludes this JSON
file to preserve producer bytes. Run affected hosted type/format/tests and
browser verification. No running engine, subprocess bridge, deployment,
persistence or report-versioning mechanism is selected here.

The real fixture proves its emitted AND, warning, invalid-rule, assignment and
unassigned cases. Tests label separate representable boundary cases for pass,
waiver, not-applicable, action fixes, unavailable evidence and unknown
assignments. The current engine does not emit not-applicable; its boundary test
is not evidence of applicability execution. Local fixture validation is not a
live or production audit.

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
