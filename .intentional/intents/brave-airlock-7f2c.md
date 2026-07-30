---
airlock: minor
---

Add `airlock plan`, the headless face of the remediation model. It observes a
repository through the same verified read-only path the audit uses and prints
the change each open gap calls for, grouped by lane, naming each rule's
remediation code, what it would change, and whether it is reversible. The
output is a display: it has no JSON form and nothing consumes it, because
aligning re-observes every rule before acting rather than applying a plan
computed earlier.

`airlock audit --list-checks` now also carries each rule's declared
remediation, in both the text and JSON listings, so the remediation catalogue
is readable before airlock is pointed at a repository and cannot drift from
what a run reports.
