---
airlock: minor
---

Add `airlock auth token`, which verifies the stored profile through the standard read-path verifier and emits only the verified token, enabling CI to hold a Safe-minted non-expiring `AIRLOCK_TOKEN`. The dogfood CI job now runs the real audit whenever the secret is provisioned.
