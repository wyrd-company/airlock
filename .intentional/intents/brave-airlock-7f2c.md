---
airlock: minor
---

Show each observed gap's declared fix, fix kind, reversibility and contextual
instruction in the audit's human output. The JSON agent work list carries file
work, operator deferrals, evidence, gate reasons, waivers and run errors.
The interactive views share one read model. Fixes are derived from fresh audit
results without credentials; Airlock re-observes before acting. There is no
separate plan command or JSON plan to apply.

`airlock audit --list-rules` carries each rule's declared fix in the text and
JSON listings so the fix catalogue can be read before an audit.
