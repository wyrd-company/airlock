---
airlock: minor
---

Add the publishing bootstrap to the interactive session: the sequence that
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
