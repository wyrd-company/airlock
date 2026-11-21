---
relationships:
  references: maturity
---

# Observed maturity

Airlock observes maturity from Git tag records and ancestry.
A working-tree edit, an untracked file, the clock and the Airlock binary version
do not change it. Local and API audits use the same observer.

A repository is Seeded until its first Intentional baseline tag. A baseline
establishes Building at any version. Committed Change Intents are not required.
A non-baseline release tag after the baseline establishes Released, or Stable
at a version at or above 1.0.0. A 1.0.0 prerelease remains Released.
Repositories with no non-baseline release-unit tag records stay on the Seeded
and Building rungs.

Airlock reads Intentional's tag-record protocol. An ordinary SemVer tag does
not establish a baseline or release. Tags outside the audited ancestry do not
change the observed rung. Incomplete Git evidence leaves maturity unobserved.
A check that requires the rung reports a run error; independent checks still
evaluate.

Each compiled rule declares its earliest rung in the generated
[conformance reference](conformance.md). A rule below its earliest rung is
out-of-scope, without a Met or Gap outcome. Classification, accepted generation
and exceptions remain separate inputs. Blocking severity has the same meaning
at every visibility and rung.

The report lists prospective assessments at each higher rung: how many rules
it adds, how many already pass, and each assessment. These assessments use the
same captured inputs and retain each rule's accepted-generation `new` marker.
They do not change the current audit's exit code.
The seeded diagnostic explains how to establish a baseline with
`intentional tag --baseline`.
