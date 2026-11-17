---
airlock: minor
---

Audit without a stored Airlock credential. The Action's repository mode accepts the run's own `GITHUB_TOKEN` through its `token` input, only inside Actions, for the run's repository, when every permission the job declares is `read`. Its central mode signs in as Airlock Safe through Azure Key Vault with the job's OpenID Connect token, checks the App and its installation, mints a read-only installation token, audits every repository the installation reaches into one report uploaded as an artifact, and accepts no other credential. `REPO-CI-09` now requires one of the two modes and no `AIRLOCK_TOKEN` secret; its fix `supply-airlock-token` becomes `supply-run-token`.
