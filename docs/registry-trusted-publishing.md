# What Airlock can observe and configure per registry

Airlock reports registry posture and runs the first-publication ceremony that
moves a package onto OIDC trusted publishing. Both depend on what each registry
actually exposes. This document records what it exposes, with the evidence, so
the bootstrap flow can be specified against fact rather than assumption.

## How to read the evidence

Every answer carries a grade:

- **verified-by-doc** — official registry documentation or a published API
  specification states it. Cited inline.
- **verified-by-probe** — an API response proves it. Every probe is recorded in
  the [probe log](#probe-log) with its method, endpoint, status, and response
  excerpt.
- **needs-live-confirmation** — the documentation does not settle it and no
  credential was available to test it. Treated as unknown, not as true.

Probing was read-only: unauthenticated registry reads and GitHub reads under an
app installation token. Nothing was published, minted, or configured. No
credential exists in this environment for npmjs, crates.io, PyPI, or pub.dev,
so every owner-authenticated read is graded from documentation or a published
specification rather than from a live response.

## The two questions that are not the same question

"Is trusted publishing configured?" and "was this version published through
trusted publishing?" have different answers on every registry, and conflating
them is the trap.

Configuration is private state. Provenance is published alongside the artifact
and is world-readable. Where configuration cannot be read, provenance is
sometimes still a sound substitute — and sometimes only looks like one.

A second distinction matters just as much, and the ceremony's shape depends on
it: a **bootstrap credential** is one obtainable *before* a trusted publisher
exists, while a **publish-time token** is minted by OIDC exchange *after* one
exists. They have opposite answers on two registries.

## Per registry

### npm

**Observability — no, for anyone but a maintainer.**
`GET https://registry.npmjs.org/-/package/{package}/trust` returns the trusted
publisher configurations, but requires write permission on the package plus an
`npm-otp` header. Probed unauthenticated: `401`, `{"message":"Bearer token
authorization is required"}`. The public packument exposes no trusted-publisher
field — probed, and no key anywhere in the document matches `trust` or
`publish`. *verified-by-doc, verified-by-probe.* Whether a granular token with
`bypass_2fa` can satisfy the OTP requirement unattended is
*needs-live-confirmation*: the documentation says the header is always required
and no account was available to test the exception.
Sources: <https://api-docs.npmjs.com/> (Trust), and
<https://docs.npmjs.com/trusted-publishers>.

**Pre-publication configuration — no.** The API documentation states "Package
MUST exist" for both the read and the write, and `POST .../trust` answers
`404 Package not found` otherwise. The `createPackage` value in the config's
permissions names an allowed action, not a pending publisher.
*verified-by-doc.* Source: <https://api-docs.npmjs.com/> (Trust).

**Bootstrap credential — an API exists but is not automatable.**
`POST https://registry.npmjs.org/-/npm/v1/tokens` creates a granular token, but
requires a session token, the account password in the request body, and an OTP
header. Probed unauthenticated: `401`. Classic tokens were withdrawn in
November 2025, so granular is the only kind and read-write tokens cap at 90
days. *verified-by-doc, verified-by-probe.* Sources:
<https://api-docs.npmjs.com/> (Tokens),
<https://docs.npmjs.com/about-access-tokens/>, and the withdrawal announcement
at <https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes>.

**Publish-time token — not applicable.** npm's trusted publishing authenticates
the workflow directly; there is no documented exchange endpoint that returns a
short-lived token to the caller. *verified-by-doc*, in the weak sense of a
documented absence.

**First publication — a human publishes once.** The package must exist before a
trusted publisher can be attached, and neither the token endpoint nor the trust
endpoint can be driven headlessly. *verified-by-doc.*

**Provenance — public, but weaker than it looks.**
`GET https://registry.npmjs.org/-/npm/v1/attestations/{pkg}@{version}` is
unauthenticated. Probed on `sigstore@5.0.0`: `200`, returning bundles for two
predicate types, `https://slsa.dev/provenance/v1` and npm's own publish
attestation. But npm provenance can be produced by `npm publish --provenance`
from CI holding an ordinary granular token, so its presence proves CI origin,
not trusted publishing. *verified-by-probe* for the endpoint;
*verified-by-doc* for what it does and does not imply, per
<https://docs.npmjs.com/generating-provenance-statements>.

### PyPI

**Observability — no.** The project JSON API exposes an `ownership` block but no
trusted-publisher field; probed on `requests`, the top-level keys are `info`,
`last_serial`, `ownership`, `releases`, `urls`, `vulnerabilities`, and no key
under `info` matches `trust` or `publish`. The only configuration surface,
`https://pypi.org/manage/project/{project}/settings/publishing/`, probed to a
`303` redirect to the login page. *verified-by-probe.*

**Pre-publication configuration — yes, and it is a first-class feature.**
Pending publishers are configured against an account rather than a project,
name the intended project, and create the project on first use. A pending
publisher does not reserve the name; another registration invalidates it.
*verified-by-doc.* Source:
<https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/>.

**Bootstrap credential — not required.** Because a pending publisher creates the
project on first upload, there is no bootstrap token to mint, paste, or revoke.
Long-lived tokens are web-UI only, but PyPI never needs one for this flow.
*verified-by-doc.* Source: <https://docs.pypi.org/trusted-publishers/>.

**Publish-time token — yes, headless.**
`POST https://pypi.org/_/oidc/mint-token` exchanges an OIDC identity token for a
fifteen-minute project-scoped API token, with no human in the loop. PyPI tokens
are macaroons, so a holder can additionally attenuate one offline into a
narrower token — derivation rather than minting. *verified-by-doc.* Source:
<https://docs.pypi.org/trusted-publishers/using-a-publisher/>.

**First publication — one human action, then fully automated.** A person
configures the pending publisher; CI creates the project on first upload. No
bootstrap token and no manual publish. *verified-by-doc.*

**Provenance — public, and it means what it says.** PEP 740 attestations are
served unauthenticated from
`GET https://pypi.org/integrity/{project}/{version}/{filename}/provenance`.
Probed on `sigstore` 4.5.0: `200`, and the response carries a `publisher` object
naming `kind: GitHub`, the repository, and the workflow file. A file without
attestations answers `404` with an explicit "No provenance available" message,
probed on `requests` 2.32.3, so presence and absence are equally legible. PyPI
rejects non-trusted-publisher attestations at upload, so a valid attestation
*is* evidence that trusted publishing was used. *verified-by-probe* for the
endpoint and shape; *verified-by-doc* for the upload-time rejection, per
<https://docs.pypi.org/attestations/producing-attestations/>.

### crates.io

crates.io publishes a machine-readable API specification at
<https://crates.io/api/openapi.json>, which is the authority for the endpoint
and authentication claims below. It was fetched during this spike (`200`, ~73
KiB) and each `security` block quoted here was read from it directly.

**Observability — partial, and better than expected.** Two distinct facts:

- **The configuration itself is owner-gated.**
  `GET /api/v1/trusted_publishing/github_configs?crate={name}` exists and
  declares `security: [{cookie}, {api_token}]`, so an API token suffices — but
  the handler additionally requires the caller be a crate owner. Probed
  unauthenticated: `403`, `{"errors":[{"detail":"this action requires
  authentication"}]}`. A GitLab equivalent exists at `.../gitlab_configs`.
  *verified-by-doc, verified-by-probe.*
- **But one bit is public.** `GET /api/v1/crates/{name}` returns a
  `trustpub_only` boolean, specified as "Whether this crate can only be
  published via Trusted Publishing." Probed unauthenticated on four crates
  (`serde`, `ripgrep`, `tagver`, `cargo-dist`): `200`, `trustpub_only: false` on
  all four. *verified-by-doc, verified-by-probe.*

`trustpub_only` does not say a publisher is configured, so it cannot stand in
for the configuration read. What it does say, when true, is stronger in a
different direction: that the crate refuses any publish that did not come
through trusted publishing. That is a credential-free, unauthenticated signal
worth checking, and it is the only one of its kind found on any registry.

**Pre-publication configuration — no.** The documentation states the crate must
already be published and the caller must be an owner, and the create handler
loads the crate before anything else. There is no pending-publisher concept.
*verified-by-doc.* Source: <https://crates.io/docs/trusted-publishing>.

**Bootstrap credential — no.** Token creation is not in the published API
surface at all: the specification exposes `/api/v1/me/tokens/{id}` for deletion
and `/api/v1/tokens/current`, but no collection endpoint for creating one. The
implementation refuses it explicitly — "cannot use an API token to create a new
API token" — leaving the browser session as the only route.
*verified-by-doc, verified-by-probe.*

**Publish-time token — yes, headless.**
`POST /api/v1/trusted_publishing/tokens` is specified as "Exchange an OIDC token
for a temporary access token" with `security: null`, meaning the OIDC assertion
in the body is the credential. It returns a thirty-minute token and is what
`rust-lang/crates-io-auth-action` wraps. A matching `DELETE` revokes it early.
*verified-by-doc.*

**Configuration write — scriptable by an owner.**
`POST /api/v1/trusted_publishing/github_configs` declares the same
`security: [{cookie}, {api_token}]` as the read, so an owner holding a suitably
scoped API token can create the configuration without a browser. The token to do
it with must still come from the web UI. *verified-by-doc.*

**First publication — two human steps.** Mint a token in the web UI, publish to
create the crate, then register the trusted publisher — by UI or by
owner-authenticated API call — and revoke the token. *verified-by-doc.*

**Provenance — not investigated.** See [Left unanswered](#left-unanswered).

### pub.dev

**Observability — no, for anyone, by any means.** The route table defines only
`PUT /api/packages/{package}/automated-publishing` and its `/publishing` alias;
there is no `GET`. Probed: `GET` on that path returns the site's HTML `404`
page rather than an API error, consistent with no such route. The public package
API exposes nothing about automated publishing — only the unrelated verified
publisher badge. *verified-by-probe*, from the route definitions in
<https://github.com/dart-lang/pub-dev/blob/master/app/lib/frontend/handlers/pubapi.dart>
and the `GET` probe.

**Pre-publication configuration — no.** The handler requires package admin
rights, which requires the package to exist. *verified-by-doc.* Source:
<https://dart.dev/tools/pub/automated-publishing>.

**Bootstrap credential — no, and the configuration is not scriptable either.**
`dart pub token add` stores a credential rather than issuing one; the
interactive path is a browser OAuth flow writing `pub-credentials.json`. The
write path requires an authenticated *web session* rather than a pub token, so
even the owner cannot script the configuration. *verified-by-doc.* Sources:
<https://dart.dev/tools/pub/cmd/pub-token> and the handler's
`requireAuthenticatedWebUser` check in
<https://github.com/dart-lang/pub-dev/blob/master/app/lib/package/backend.dart>.

**Publish-time token — externally sourced.** Publishing uses a GitHub Actions
OIDC token directly, or a GCP service account identity token, as the bearer.
pub.dev issues nothing itself. *verified-by-doc.*

**First publication — a browser login, a manual publish, and a UI form.**
*verified-by-doc.*

**Provenance — not investigated.** See [Left unanswered](#left-unanswered).

### GHCR

GHCR has no credential problem and a differently-shaped first-time step.

**Defaults.** A newly published package is **private**, and it is linked to a
repository only if the image carried `org.opencontainers.image.source` at push
time. Permission inheritance follows the same rule: a package inherits the
linked repository's access only if it was linked *before* publication.
Connecting afterwards does not grant it retroactively. An org owner can disable
inheritance for all new packages, which breaks the happy path.
*verified-by-doc.* Source:
<https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility>.

**Making it public is UI-only and irreversible.** The REST packages API offers
list, get, delete, and restore, with no visibility mutation, and GraphQL was
withdrawn for the re-platformed registries in 2022. A public package cannot be
made private again. *verified-by-doc.* Sources:
<https://docs.github.com/en/rest/packages/packages> and
<https://github.blog/changelog/2022-08-17-deprecation-notice-graphql-for-packages/>.

**Connecting a repository afterwards is also UI-only.** *verified-by-doc*, with
the stronger claim that no undocumented endpoint exists graded
*needs-live-confirmation*. Source:
<https://docs.github.com/en/packages/learn-github-packages/connecting-a-repository-to-a-package>.

**Reading the state is fully supported, by name.**
`GET /orgs/{org}/packages/container/{name}` returns `visibility` and
`repository`. Probed live under an app installation token: `200`, and
`wyrd-company/lore` reports `visibility: public` and `repository:
wyrd-company/lore`. Nested names URL-encode the slash as `%2F`.
*verified-by-probe.*

**Enumeration fails under the token Airlock would use.**
`GET /orgs/{org}/packages?package_type=container` returned
`400 Invalid argument` under the same installation token that succeeds by name,
while `package_type=npm` returned `200` with twelve packages and
`package_type=docker` returned `200` with none. Both the succeeding and the
failing request carried
`X-Accepted-Github-Permissions: allows_permissionless_access=true`, so this is
request validation rather than a permission failure. *verified-by-probe*, for
exactly that: one organisation, one installation token, on the date in the probe
log.

What this does **not** establish is that the endpoint fails under anything but a
classic personal access token, or that a PAT is the only workaround; that
generalisation comes from third-party reports
(<https://github.com/cli/cli/issues/9606>) and is graded
*needs-live-confirmation*. The design conclusion does not depend on the
generalisation: looking packages up by name is independently the better choice,
because Airlock derives package names from the repository's declared release
units and therefore never needs to enumerate.

### Homebrew

The exclusion is correct and the reason is structural. A tap is a git
repository, publishing is `git add`, `git commit`, `git push`, and consumption
is `git clone` plus `git pull`. There is no registry service in the loop, so
there is nothing that could implement trusted publishing. *verified-by-doc.*
Sources: <https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap> and
<https://docs.brew.sh/Taps>.

That no publisher-side OIDC mechanism exists for third-party taps is a
documented absence rather than a documented denial, so it is graded
*needs-live-confirmation* in the strict sense — no `brew` command, documentation
page, or changelog describes one, and Homebrew appears in the OpenSSF survey
only as a contrast case
(<https://repos.openssf.org/trusted-publishers-for-all-package-repositories.html>).

Two nuances keep the claim from being overstated:

- Homebrew's own `homebrew-core` bottles do carry Sigstore build provenance from
  Homebrew's CI, verified by `brew install` when `HOMEBREW_VERIFY_ATTESTATIONS`
  is set. That attests to Homebrew's build identity and does not extend to
  third-party taps. *verified-by-doc*, per
  <https://blog.sigstore.dev/homebrew-build-provenance>.
- Homebrew 6.0.0 added Tap Trust, which requires a user to `brew trust` a
  non-official tap. That is consumer-side trust with no cryptographic link to a
  publishing identity. *verified-by-doc*, per <https://docs.brew.sh/Tap-Trust>.

So the exclusion should be phrased as "no *publisher-side* OIDC trust exists",
so a reader who has met `brew trust` does not think the claim is stale.

The available improvement is unchanged: replace the long-lived token with a
GitHub App installation token scoped to the tap repository.
`POST /app/installations/{id}/access_tokens` accepts `repositories` and
`permissions` to narrow the grant, and the resulting token expires in an hour.
*verified-by-doc*, per
<https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app>.

**Direct push is preferred, on a graded caveat.** An app installation token is
clean for pushing directly to a tap the owner controls. It is *reported* to fail
for `brew bump-formula-pr`, which forks and opens a cross-repository pull
request, with `Resource not accessible by integration`
(<https://github.com/orgs/Homebrew/discussions/5129>). The mechanism is
plausible — an installation token reaches only the repositories the installation
names, and a fork lives outside them — but this is a single community report,
not documentation, and it was not reproduced here. Graded
*needs-live-confirmation*. It is a reason to prefer the direct-push shape, which
the tap update already uses, rather than a settled prohibition on the
fork-and-PR shape.

## Summary

| Registry | Read config | Pre-publication config | Bootstrap credential | Headless publish-time token | Public provenance |
| --- | --- | --- | --- | --- | --- |
| npm | Owner only, needs OTP | No | Human-gated | Not applicable | Yes, but weak |
| PyPI | No | **Yes** | **Not needed** | **Yes** | Yes, conclusive |
| crates.io | Owner only, plus a public `trustpub_only` bit | No | Human-gated | **Yes** | Not investigated |
| pub.dev | No, no endpoint | No | Human-gated | Externally sourced | Not investigated |
| GHCR | **Yes, by name** | Not applicable | Not applicable | Not applicable | Not applicable |

## Consequences for Airlock

**Every trusted-publishing configuration check is attested, not verified.**
Airlock holds one credential, a read-only GitHub App token, and no registry
credential at all. Even where a configuration endpoint exists, it is gated on
package ownership on that registry. So the check "this package has trusted
publishing configured" cannot be verified for npm, PyPI, crates.io, or pub.dev
without giving Airlock a registry credential per ecosystem, which contradicts
its credential model. The check degrades to attested on all four, and the
degradation is a property of Airlock's design rather than a registry gap that
might close.

The one exception is partial and belongs to crates.io: `trustpub_only` is public
and, when true, proves the crate refuses non-trusted-publishing uploads. That is
a verified check Airlock can run today with no credential, and it is worth
having even though it answers a narrower question than the configuration read
would.

**Provenance is the check that can actually be verified, and conclusively only
on PyPI.** Because PyPI rejects non-trusted-publisher attestations at upload, a
public unauthenticated read of the provenance endpoint proves the published
artifact came through trusted publishing — and names the repository and workflow
while doing it. This needs no credential and is stronger than reading
configuration would have been. npm's equivalent proves CI origin only, so it can
support a weaker finding — "published from CI with provenance" — but must not be
worded as trusted publishing. This reframes the rule: ask what the last release
*did*, not what the settings *say*.

**Only PyPI skips the ceremony.** The pending-publisher belief was correct for
PyPI and correct in the negative for the other three. npm, crates.io, and
pub.dev all require the package to exist and the caller to be an owner, so all
three need the full mint-publish-configure-revoke dance.

**Bootstrap credentials are human-gated everywhere they are needed — and PyPI
does not need one.** This is the answer that most changes the flow's shape, and
it has to be stated in two parts, because the registries answer differently
depending on which credential is meant.

- *Before* a trusted publisher exists, no registry will mint one headlessly. npm
  requires a session token, a password, and an OTP. crates.io does not expose
  token creation in its API at all and refuses a token creating a token. pub.dev
  issues credentials only through a browser OAuth flow. So on those three, the
  ceremony's first step is a human instruction plus somewhere to paste the
  result.
- *After* one exists, PyPI and crates.io both mint short-lived scoped tokens
  headlessly by OIDC exchange, which is exactly the steady state the ceremony is
  trying to reach.
- PyPI has no bootstrap step at all, because a pending publisher creates the
  project on first upload.

So the flow branches: three registries get a guided human step, and PyPI gets a
single "configure the pending publisher" instruction and nothing else. A design
that assumed one uniform paste-a-token step would be wrong for a quarter of the
matrix, and wrong in the direction of adding work that PyPI does not require.

**The configuration step is an instruction on two of the three.** crates.io
accepts an owner-authenticated API token for the configuration write, so it can
be scripted once a token exists. pub.dev requires a web session and npm requires
an OTP, so both stay guided human steps.

**GHCR gets detection but not remediation.** Airlock can assert the real state —
`visibility` and `repository` — under the credential it already holds, then stop
at the one irreversible flip and hand the operator the settings URL. Getting
`org.opencontainers.image.source` onto the image before the first push collapses
the ceremony from three manual steps to one, and is itself a checkable
repository fact.

**Look GHCR packages up by name.** Airlock derives package names from the
declared release units, so it never needs to enumerate — which is fortunate,
since the container list endpoint rejects the installation token Airlock holds.

**Homebrew stays out of the bootstrap model,** because there is no first
publication event to bootstrap. It belongs where the design already puts it: the
cross-repository write capability, judged on credential shape and scope.

## Left unanswered

- Whether npm's OTP requirement on the trust endpoints can be satisfied by a
  granular token with `bypass_2fa`. Documented as always required; no account
  available to test the exception.
- Whether crates.io or pub.dev publish machine-readable provenance comparable to
  PyPI's attestations. Not investigated, and it matters more than it seemed at
  the outset, because provenance is the only credential-free verified path
  Airlock has.
- Whether an undocumented GitHub endpoint can change package visibility or
  connect a repository. Assumed not; a documented absence only.
- Whether the GHCR container list endpoint fails for every non-PAT credential,
  or only for the installation-token shape probed here.
- Whether `brew bump-formula-pr` genuinely fails under a scoped app installation
  token. One community report, not reproduced.

## Probe log

Every probe below was read-only and was run on 2026-07-29. Unauthenticated
requests carried the user agent
`airlock-spike/1.0 (read-only research probe; kanban task 71)` where the
registry requires one. GitHub requests used a GitHub App installation token for
the `wyrd-company` account; no registry credential was used or available.

| Method and endpoint | Status | Response excerpt |
| --- | --- | --- |
| `GET registry.npmjs.org/-/package/express/trust` | 401 | `Bearer token authorization is required` |
| `GET registry.npmjs.org/-/npm/v1/tokens` | 401 | empty body |
| `GET registry.npmjs.org/express` | 200 | no key matches `trust` or `publish` |
| `GET registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.0` | 200 | predicates `slsa.dev/provenance/v1`, npm publish v0.1 |
| `GET pypi.org/pypi/requests/json` | 200 | keys `info`, `last_serial`, `ownership`, `releases`, `urls`, `vulnerabilities` |
| `GET pypi.org/manage/project/requests/settings/publishing/` | 303 | redirect to `/account/login/?next=…` |
| `GET pypi.org/integrity/sigstore/4.5.0/…whl/provenance` | 200 | one bundle; `publisher: {kind: GitHub, repository: sigstore/sigstore-python, workflow: release.yml}` |
| `GET pypi.org/integrity/requests/2.32.3/…whl/provenance` | 404 | `No provenance available for …` |
| `GET crates.io/api/v1/trusted_publishing/github_configs?crate=serde` | 403 | `this action requires authentication` |
| `GET crates.io/api/v1/crates/{serde,ripgrep,tagver,cargo-dist}` | 200 | `trustpub_only: false` on all four |
| `GET crates.io/api/openapi.json` | 200 | ~73 KiB; `security` blocks quoted above |
| `GET pub.dev/api/packages/http/automated-publishing` | 404 | site HTML 404, not an API error |
| `GET /orgs/wyrd-company/packages/container/lore` | 200 | `visibility: public`, `repository: wyrd-company/lore` |
| `GET /orgs/wyrd-company/packages?package_type=container` | 400 | `Invalid argument.` |
| `GET /orgs/wyrd-company/packages?package_type=npm` | 200 | 12 packages |
| `GET /orgs/wyrd-company/packages?package_type=docker` | 200 | 0 packages |

Both GitHub package requests, the succeeding one and the failing one, returned
`X-Accepted-Github-Permissions: allows_permissionless_access=true`.
