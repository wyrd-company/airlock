---
airlock: minor
---

Add deterministic working-tree alignment. Airlock authors only findings with the `airlock` fix kind, reports every path operation and dirty-tree skip, re-observes the local result, and exposes read-only pull-request context while leaving staging, commits, pushes, and draft pull requests to the caller. Findings with the `agent` fix kind are handed to an agent with the embedded repository-standards skill, and operator settings remain human-only.
