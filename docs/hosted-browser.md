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
that list by fixer. Unassigned repositories appear separately and are not gaps.

Organization sections are Repos, Rules, Assignments, and Pull requests. Results
are grouped as You, Airlock PR, Agent, Not fixable, and Couldn't evaluate.
Passing, waived, and not-applicable results are collapsed below failures.

One engine result appears as one row. When an engine result has more than one
fixer, it appears in the first applicable group in the listed order and names
all fixers; work queue filters match every fixer. Its detail preserves all
organization and repository instances, their independent conditions and config
commits, and relaxation warnings. The browser does not recompute AND results,
severity, fix derivation, or rule predicates.

The Rules section is a per-id index of observed rules and repository coverage;
repository result details hold instance-specific requirements. The fixture API
has only organization summary, selected organization, and unavailable session
reads. Mutation requests return an unavailable response even with a token.

Reviewing settings fixes shows selected requirements. It does not claim that
requirements are an executable, reviewed change batch. Real exact before/after
changes must come from a server-side planner that re-observes GitHub state.
Config proposal drafts remain in their dialog. No proposal is submitted or
merged.

## Adapter boundaries

`shared/report.ts` is a provisional hosted input and view contract. It follows
the core workstream's draft result shape without importing its unfinished
modules or claiming wire compatibility. `projection.ts` maps supplied results;
`fixtures.ts` is visibly synthetic. A serialized core fixture and a boundary
validation adapter are required before accepting real core output. Invalid or
unobserved input must remain incomplete, never become a passing observation.

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
