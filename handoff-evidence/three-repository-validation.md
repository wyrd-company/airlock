# Task 65 Real-Repository Validation

The before run used registry `0.1.0` at base commit `5706ff7`. The after run
used registry `0.2.0` with digest
`sha256:4a978f4ee0adfc35f87976ecdb2ce3abb985beffd11d757025ea1e898b4a5c01`.
Both runs used the devcontainer's verified Airlock Safe profile credential and
the live `wyrd-company/.github:airlock/policy.yml`.

| Repository | Rule | Before | After |
| --- | --- | --- | --- |
| `wyrd-company/airlock` | `REPO-GIT-09` | pass (`single_release_unit`) | pass (`single_release_unit`) |
| `wyrd-company/airlock` | `REPO-TASK-04` | pass (`single_release_unit`) | pass (`single_release_unit`) |
| `wyrd-company/airlock` | `REPO-LIC-04` | pass (`license_declared_in_metadata`) | pass (`license_declared_in_metadata`) |
| `wyrd-company/intentional` | `REPO-GIT-09` | pass (`single_release_unit`) | pass (`single_release_unit`) |
| `wyrd-company/intentional` | `REPO-TASK-04` | pass (`single_release_unit`) | pass (`single_release_unit`) |
| `wyrd-company/intentional` | `REPO-LIC-04` | pass (`license_declared_in_metadata`) | pass (`license_declared_in_metadata`) |
| `wyrd-company/tagver` | `REPO-GIT-09` | inconclusive (`no_release_units_declared`) | skipped (`condition_not_met`: `release-units-declared`) |
| `wyrd-company/tagver` | `REPO-TASK-04` | inconclusive (`no_release_units_declared`) | skipped (`condition_not_met`: `release-units-declared`) |
| `wyrd-company/tagver` | `REPO-LIC-04` | fail (`license_missing_from_metadata`) | skipped (`condition_not_met`: `release-units-declared`) |

The whole-audit exit codes were unchanged: `airlock` exited 0; `intentional`
and `tagver` exited 1 because of findings outside these three rules. Publishing
repositories therefore retained their evaluation results, while the
non-publishing repository conclusively skipped all three conditioned rules.
