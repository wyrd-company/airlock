---
airlock: minor
---

Every registered rule now declares its remediation as data: a stable code, what the change would be, whether it is reversible, and its lane (deterministic file change, judgment file change, or operator-only setting) — or an explicit no-remediation reason. Findings carry the classification in a new `remediation_class` field. The classification is deliberately outside the registry digest.
