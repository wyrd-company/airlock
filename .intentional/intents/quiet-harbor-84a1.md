---
airlock: minor
---

Every registered rule now declares its fix as data: a stable code, what the change would be, whether it is reversible, and its fix kind (`airlock`, `agent`, or `operator`) — or an explicit no-fix reason. Findings carry the classification in a new `fix_class` field. The classification is deliberately outside the rules digest.
