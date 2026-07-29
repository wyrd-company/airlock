# What Airlock can observe and configure per registry

Airlock reports registry posture and runs the first-publication ceremony that
moves a package onto OIDC trusted publishing. Both depend on what each registry
actually exposes. This document records what it exposes, with the evidence, so
the bootstrap flow can be specified against fact rather than assumption.

## How to read the evidence

Every answer carries a grade:

- **verified-by-doc** — official registry documentation states it.
- **verified-by-probe** — an API response or the registry's own source code
  proves it.
- **needs-live-confirmation** — the documentation does not settle it and no
  credential was available to test it. Treated as unknown, not as true.

Probing was read-only throughout: unauthenticated registry reads, GitHub reads
under an app installation token, and route definitions read from registry
source. Nothing was published, minted, or configured.

No credential exists in this environment for npmjs, crates.io, PyPI, or pub.dev,
so every owner-authenticated read is graded from documentation and source rather
than from a live response.

## The two questions that are not the same question

"Is trusted publishing configured?" and "was this version published through
trusted publishing?" have different answers on every registry, and conflating
them is the trap.

Configuration is private state. Provenance is published alongside the artifact
and is world-readable. Where configuration cannot be read, provenance is
sometimes still a sound substitute — and sometimes only looks like one.

## Per registry

### npm

**Observability — no, for anyone but a maintainer.**
`GET https://registry.npmjs.org/-/package/{package}/trust` returns the trusted
publisher configurations, but requires write permission on the package plus an
`npm-otp` header. An unauthenticated probe returns
`401 Bearer token authorization is required`. The public packument exposes no
trusted-publisher field at all. *verified-by-doc, verified-by-probe.* Whether a
granular token with `bypass_2fa` can satisfy the OTP requirement unattended is
*needs-live-confirmation*.

**Pre-publication configuration — no.** The API documentation states "Package
MUST exist" for both the read and the write; `POST .../trust` returns
`404 Package not found` otherwise. The `createPackage` permission in the config
body names an allowed action, not a pending publisher. *verified-by-doc.*

**Programmatic token minting — an API exists but is not automatable.**
`POST https://registry.npmjs.org/-/npm/v1/tokens` creates a granular token, but
requires a session token, the account password in the body, and an OTP header.
Classic tokens were withdrawn in November 2025, so granular is the only kind.
*verified-by-doc, verified-by-probe.*

**First publication — a human publishes once.** The package must exist before a
trusted publisher can be attached, and neither the token endpoint nor the trust
endpoint can be driven headlessly. *verified-by-doc.*

**Provenance — public, but weaker than it looks.**
`GET https://registry.npmjs.org/-/npm/v1/attestations/{pkg}@{version}` is
unauthenticated and returns Sigstore bundles. npm provenance can be produced by
`npm publish --provenance` from CI holding an ordinary granular token, so its
presence proves CI origin, not trusted publishing. *verified-by-probe.*

### PyPI

**Observability — no.** The project JSON API exposes an `ownership` block but no
trusted-publisher field, and the only configuration surface,
`https://pypi.org/manage/project/{project}/settings/publishing/`, redirects to
login. *verified-by-probe.*

**Pre-publication configuration — yes, and it is a first-class feature.**
Pending publishers are configured against an account rather than a project, name
the intended project, and create the project on first use. A pending publisher
does not reserve the name; another registration invalidates it.
*verified-by-doc.*

**Programmatic token minting — not needed.** `POST https://pypi.org/_/oidc/mint-token`
exchanges an OIDC token for a fifteen-minute project-scoped token, which is the
trusted-publishing exchange itself. Long-lived tokens are web-UI only. PyPI
tokens are macaroons, so a holder can attenuate one offline, but that is
derivation rather than minting. *verified-by-doc.*

**First publication — one human action, then fully automated.** A person
configures the pending publisher; CI creates the project on first upload. No
bootstrap token and no manual publish. *verified-by-doc.*

**Provenance — public, and it means what it says.** PEP 740 attestations are
served from `GET https://pypi.org/integrity/{project}/{version}/{filename}/provenance`
and carry the repository, workflow, ref, and commit. PyPI rejects
non-trusted-publisher attestations at upload, so a valid attestation *is*
evidence that trusted publishing was used. *verified-by-doc, verified-by-probe.*

### crates.io

**Observability — no, unless Airlock is a crate owner.**
`GET /api/v1/trusted_publishing/github_configs?crate={name}` exists and is
documented, but the handler applies an endpoint scope and then an explicit
`crate_owners` lookup that answers "You are not an owner of this crate". An
unauthenticated probe returns `403`. The public crate endpoint surfaces no
indicator. *verified-by-probe*, from both the response and the route source.

**Pre-publication configuration — no.** The documentation states the crate must
already be published and the caller must be an owner; the handler loads the
crate before anything else. There is no pending-publisher concept.
*verified-by-doc, verified-by-probe.*

**Programmatic token minting — no.** `PUT /api/v1/me/tokens` is cookie-session
only and explicitly refuses token auth: "cannot use an API token to create a new
API token". `POST /api/v1/trusted_publishing/tokens` does exchange an OIDC token
for a thirty-minute publish token, but only once a configuration exists.
*verified-by-probe.* Whether the configuration *write* accepts a scoped token
rather than a cookie is *needs-live-confirmation*.

**First publication — two human steps.** Mint a token in the web UI, publish to
create the crate, then register the trusted publisher and revoke the token.
*verified-by-doc.*

### pub.dev

**Observability — no, for anyone, by any means.** The route table defines only
`PUT /api/packages/{package}/automated-publishing`; there is no `GET`. A probe
confirms it: `GET` returns the site's HTML 404 while `PUT` returns
`400 Malformed JSON payload`, so the route exists and is method-specific. The
public package API exposes nothing about automated publishing.
*verified-by-probe.*

**Pre-publication configuration — no.** The handler requires package admin
rights, which requires the package to exist. *verified-by-doc,
verified-by-probe.*

**Programmatic token minting — no.** `dart pub token add` stores a credential
rather than issuing one; the interactive path is a browser OAuth flow. The write
path requires an authenticated *web session*, not a pub token, so even the owner
cannot script the configuration. *verified-by-doc.*

**First publication — a browser login, a manual publish, and a UI form.**
*verified-by-doc.*

### GHCR

GHCR has no credential problem and a differently-shaped first-time step.

**Defaults.** A newly published package is **private**, and it is linked to a
repository only if the image carried
`org.opencontainers.image.source` at push time. Permission inheritance follows
the same rule: a package inherits the linked repository's access only if it was
linked *before* publication. Connecting afterwards does not grant it
retroactively. *verified-by-doc.*

**Making it public is UI-only and irreversible.** The REST packages API offers
list, get, delete, and restore — no visibility mutation — and GraphQL was
withdrawn for the re-platformed registries in 2022. A public package cannot be
made private again. *verified-by-doc.*

**Connecting a repository afterwards is also UI-only.** *verified-by-doc*, with
the stronger claim that no undocumented endpoint exists graded
*needs-live-confirmation*.

**Reading the state is fully supported, by name.**
`GET /orgs/{org}/packages/container/{name}` returns `visibility` and
`repository`, and works under an app installation token. Confirmed live against
two organisations. *verified-by-probe.*

**But enumeration is not.** `GET /orgs/{org}/packages?package_type=container`
returns `400 Invalid argument` under an installation token, while `npm` and
`docker` package types return 200 on the same token. This is a long-standing
defect for which the only reported workaround is a classic personal access
token. *verified-by-probe.*

### Homebrew

The exclusion is correct and the reason is structural. A tap is a git
repository, publishing is `git add`, `git commit`, `git push`, and consumption
is `git clone` plus `git pull`. There is no registry service in the loop, so
there is nothing that could implement trusted publishing. *verified-by-doc.*

Two nuances keep the claim from being overstated:

- Homebrew's own `homebrew-core` bottles do carry Sigstore build provenance from
  Homebrew's CI. That attests to Homebrew's build identity and does not extend
  to third-party taps.
- Homebrew 6.0.0 added Tap Trust, which requires a user to `brew trust` a
  non-official tap. That is consumer-side trust with no cryptographic link to a
  publishing identity. The exclusion should therefore be phrased as "no
  publisher-side OIDC trust exists", so a reader who has met `brew trust` does
  not think the claim is stale.

The available improvement is unchanged: replace the long-lived token with a
GitHub App installation token scoped to the tap repository.
`POST /app/installations/{id}/access_tokens` accepts `repositories` and
`permissions`, and the resulting token expires in an hour. *verified-by-doc.*
This is clean for a direct push to a tap Airlock's owner controls; it is
reported to fail for `brew bump-formula-pr`, which forks and opens a
cross-repository pull request. Prefer the direct-push shape.

## Summary

| Registry | Read config | Pending publisher | Headless token mint | Public provenance |
| --- | --- | --- | --- | --- |
| npm | Owner only, needs OTP | No | No | Yes, but weak |
| PyPI | No | **Yes** | Not needed | Yes, conclusive |
| crates.io | Owner only | No | No | Not investigated |
| pub.dev | No, no endpoint | No | No | Not investigated |
| GHCR | **Yes, by name** | Not applicable | Not applicable | Not applicable |

## Consequences for Airlock

**Every trusted-publishing configuration check is attested, not verified.**
Airlock holds one credential, a read-only GitHub App token, and no registry
credential at all. Even where a configuration endpoint exists, it is gated on
package ownership on that registry. So the check "this package has trusted
publishing configured" cannot be verified for npm, PyPI, crates.io, or pub.dev
without giving Airlock a registry credential per ecosystem — which contradicts
its credential model. The check degrades to attested on all four, and the
degradation is a property of Airlock's design rather than a registry gap that
might close.

**Provenance is the check that can actually be verified, and only on PyPI.**
Because PyPI rejects non-trusted-publisher attestations at upload, a public,
unauthenticated read of the provenance endpoint proves the published artifact
came through trusted publishing. This is a stronger and cheaper check than
reading configuration would have been, and it needs no credential. npm's
equivalent proves CI origin only, so it can support a weaker finding —
"published from CI with provenance" — but must not be worded as trusted
publishing. This reframes the rule: ask what the last release *did*, not what
the settings *say*.

**Only PyPI skips the ceremony.** The pending-publisher belief was correct for
PyPI and correct in the negative for the other three. npm, crates.io, and
pub.dev all require the package to exist and the caller to be an owner, so all
three need the full mint-publish-configure-revoke dance.

**Step one of the ceremony is an instruction on every registry, never an
action.** This is the answer that most changes the flow's shape. npm has a token
API but requires a session token, a password, and an OTP. crates.io explicitly
forbids a token creating a token. pub.dev issues credentials only through a
browser OAuth flow. PyPI's long-lived tokens are web-UI only, though PyPI never
needs one. There is no registry on which Airlock can mint a scoped publishing
token headlessly, so the bootstrap flow's first step is a human instruction plus
a place to paste the result — uniformly, with no per-registry branch.

**The configuration step is also an instruction almost everywhere.** crates.io
may accept an owner-authenticated scoped token for the write, which is worth
confirming, but pub.dev requires a web session and npm requires an OTP. Plan for
guided human steps and treat any scriptable write as an optimisation.

**GHCR gets detection but not remediation.** Airlock can assert the real state —
`visibility` and `repository` — under the credential it already holds, then stop
at the one irreversible flip and hand the operator the settings URL. Getting
`org.opencontainers.image.source` onto the image before the first push collapses
the ceremony from three manual steps to one, and is itself a checkable
repository fact.

**Never enumerate GHCR packages.** The container list endpoint fails under
anything but a classic personal access token. Airlock must look packages up by
name, derived from the repository's declared release units, or it will acquire a
credential requirement it cannot justify.

**Homebrew stays out of the bootstrap model,** because there is no first
publication event to bootstrap. It belongs where the design already puts it: the
cross-repository write capability, judged on credential shape and scope.

## Left unanswered

- Whether a crates.io token carrying the trusted-publishing endpoint scope can
  perform the configuration *write*, or whether that too needs a browser
  session. Source suggests it accepts a token; untested.
- Whether npm's OTP requirement on the trust endpoints can be satisfied by a
  granular token with `bypass_2fa`. Documented as always required.
- Whether crates.io or pub.dev publish any machine-readable provenance
  comparable to PyPI's attestations. Not investigated, and it matters, because
  provenance is the only verified path Airlock has.
- Whether an undocumented GitHub endpoint can change package visibility or
  connect a repository. Assumed not; a documented absence only.
