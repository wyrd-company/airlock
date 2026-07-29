# Security Policy

## Reporting a vulnerability

**Report privately through GitHub.** Open the repository's **Security** tab and
choose **Report a vulnerability**. That opens a private advisory visible only to
the maintainers.

Do not open a public issue for a security problem, and do not include exploit
details in a pull request.

Private reporting is preferred over email: there is no address to go stale, the
report is attached to the repository it concerns, and the advisory becomes the
place a fix and a CVE are coordinated.

## What to include

- What the vulnerability allows an attacker to do
- The affected version, or the commit you tested
- Steps to reproduce, or a proof of concept
- Anything you know about who is exposed

A report that reproduces is worth far more than one that speculates. If you are
unsure whether something is a vulnerability, report it anyway.

## What to expect

- **Acknowledgement** that the report was received and read
- **An assessment** of whether it is a vulnerability and how severe
- **A fix or a decision**, with the reasoning if the answer is that it will not
  be fixed
- **Credit** in the advisory, unless you ask otherwise

These projects are maintained by a very small team. Response is best-effort, not
contractual.

## Supported versions

Unless a repository says otherwise, only the latest released version is
supported. Fixes land there; there is no backporting to earlier lines.

Repositories below `1.0.0` carry no support commitment at all. Pin a version and
read the changelog before upgrading.

## Scope

In scope: the code in these repositories and the artifacts published from them.

Out of scope: third-party dependencies — report those upstream, though telling
us is welcome so the dependency can be updated — and vulnerabilities requiring
an already-compromised machine or account.
