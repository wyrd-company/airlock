---
airlock: minor
---

Add the console's sign-in screen and the write credential behind it.

Bare `airlock` now runs the GitHub App device flow. The screen draws all five
states the terminal interface specification names — requesting a code, awaiting
approval with a live poll count and remaining validity, expired, denied, and
polling interrupted — and each one names its remedy. Expiry and denial issue a
replacement code in place: the session is not restarted and nothing else is
lost. An interruption keeps the still-valid code on screen with its backoff, so
approval already given is not wasted, and a denial states plainly that nothing
was granted and there is nothing to revoke.

The scan code encodes the address only, because the device flow offers no
address that carries the code, so the code is always typed and is always
legible text, spaced character by character over an alphabet that excludes 0,
O, 1, and I. It paints its own light field and four-module quiet zone rather
than inheriting the terminal background. It is withheld rather than clipped
whenever it cannot be drawn whole — at the floor, without the rows for it, and
under `NO_COLOR` — and says which of those it is, with a key to draw it below
the code instead.

The write credential has one source, and it is structural rather than
conventional: the type that holds it can be built from nothing but a device
grant. It is never written anywhere, never placed in a child process
environment, never displayed, and its bytes are overwritten when it goes. No
refresh token is kept. The credential lives in the run loop rather than in the
drawing state, so what renders the screen cannot reach it.

The accepted app is a compile-time constant, checked by both numeric id and
slug. A test build accepts Airlock Test, which is installed on one account
only; the shipped binary accepts Airlock Admin and contains no string that
could accept anything else, which is asserted against the built artifact.
