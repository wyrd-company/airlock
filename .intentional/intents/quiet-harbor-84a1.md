---
airlock: minor
---

Every registered rule now declares its fix as data: a stable code, what the change would be, whether it is reversible, and its lane (deterministic file change, judgment file change, or operator-only setting) — or an explicit no-fix reason. Findings carry the classification in a new `fix_class` field. The classification is deliberately outside the registry digest.
