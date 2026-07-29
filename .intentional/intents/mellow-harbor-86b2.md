---
airlock: minor
---

File-level rules can now be observed from a local working tree (`--working-tree`), as it stands, including uncommitted and untracked content, with gitignored files deliberately excluded. Platform rules stay with the API or are reported as not observed — never passing. Every finding names the source that decided it, and the report carries an observation block stating the run's terms, including dirtiness. A parity test holds the two sources to agreement on every file-level rule for a clean checkout.
