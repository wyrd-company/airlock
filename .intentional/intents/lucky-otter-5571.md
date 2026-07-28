---
airlock: patch
---

A closed stdout pipe (for example airlock auth token piped to a command that exits early) now terminates silently via SIGPIPE, shell status 141, instead of panicking.
