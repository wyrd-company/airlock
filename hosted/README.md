---
relationships:
  references: ../docs/hosted-browser.md
---

# Airlock hosted browser

Run `pnpm install --frozen-lockfile`, then `pnpm dev`. Open
<http://localhost:5178> for the local sample-data preview.

`pnpm check` runs type checks, focused tests and the browser build.
`pnpm build && pnpm preview` serves the same browser through a local Cloudflare
Worker at <http://localhost:8788>.

Read [the hosted browser contract](../docs/hosted-browser.md) for boundaries and
unconnected integrations. This package has no public deployment script.
