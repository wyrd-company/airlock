// The module's clock, timers and transport guards, under Node. Every path
// that reads time on the wasm build goes through the host's `now` and
// `sleep`: the audit budget, a request's timeout, the rate-limit wait, and
// (in central.test.mjs) the App's JSON Web Token.

import assert from "node:assert/strict";
import { before, test } from "node:test";

import { fetchHost } from "../js/host.mjs";
import { fakeClock, loadModule, readRecording, replay } from "./support.mjs";

const BASE = "https://api.github.test";
const REPOSITORY = "/repos/wyrd-company/airlock";

let airlock;
let recording;
before(async () => {
  airlock = await loadModule();
  recording = readRecording("audit-airlock.json");
});

function request() {
  return JSON.stringify({ token: recording.token, ...recording.request, githubApi: BASE });
}

/**
 * The recording as a fetch, with `around(path, answer)` able to replace or
 * follow any answer. Records each request's path and timeout.
 */
function replayed(around = (_path, answer) => answer()) {
  const replay_ = replay(recording, { base: BASE });
  const seen = [];
  const fetch = async (url, init) => {
    const parsed = new URL(url);
    const path = parsed.pathname + parsed.search;
    seen.push({ path });
    return around(path, () =>
      replay_.answer({ method: init.method, url: parsed, headers: Object.fromEntries(init.headers) }),
    );
  };
  return { fetch, seen, unexpected: replay_.unexpected };
}

/** A host whose fetch also records the timeout the module asked for. */
function host(fetch, clock) {
  const inner = fetchHost({ fetch, now: clock.read, sleep: clock.sleep });
  const timeouts = [];
  return {
    timeouts,
    fetch: (req) => {
      timeouts.push({ url: req.url, timeoutMs: req.timeoutMs });
      return inner.fetch(req);
    },
    sleep: inner.sleep,
    now: inner.now,
  };
}

async function settle(promise) {
  try {
    return { report: JSON.parse(await promise) };
  } catch (error) {
    return { error };
  }
}

test("waits out a rate limit on the host's timer, until the reset the host's clock gives", async () => {
  const clock = fakeClock();
  let limited = false;
  const fake = replayed((path, answer) => {
    if (path.startsWith("/user/installations") && !limited) {
      limited = true;
      return new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
        status: 403,
        headers: {
          "x-ratelimit-remaining": "0",
          "x-ratelimit-reset": String(clock.now / 1000 + 7),
        },
      });
    }
    return answer();
  });
  const { report, error } = await settle(airlock.audit(host(fake.fetch, clock), request()));
  assert.equal(error, undefined);
  assert.deepEqual(clock.sleeps, [7000]);
  assert.equal(fake.seen.filter((seen) => seen.path.startsWith("/user/installations")).length, 2);
  assert.equal(report.outcome, "nonconformant");
});

test("a Retry-After given as an HTTP date is not parsed, and the wait falls back to a second", async () => {
  const clock = fakeClock();
  let limited = false;
  const fake = replayed((path, answer) => {
    if (path.startsWith("/user/installations") && !limited) {
      limited = true;
      return new Response("{}", {
        status: 429,
        headers: { "retry-after": "Sat, 21 Nov 2026 07:30:00 GMT" },
      });
    }
    return answer();
  });
  const { error } = await settle(airlock.audit(host(fake.fetch, clock), request()));
  assert.equal(error, undefined);
  assert.deepEqual(clock.sleeps, [1000]);
});

test("the audit budget runs on the host's clock, and a request after it is never sent", async () => {
  const clock = fakeClock();
  const fake = replayed((path, answer) => {
    const response = answer();
    // The repository's settings arrive five minutes and a second late.
    if (path === REPOSITORY) clock.now += 301_000;
    return response;
  });
  const { report, error } = await settle(airlock.audit(host(fake.fetch, clock), request()));
  const text = error ? error.message : JSON.stringify(report.run_errors);
  assert.match(text, /300 second audit budget was exhausted/);
  const at = fake.seen.findIndex((seen) => seen.path === REPOSITORY);
  assert.ok(at >= 0);
  assert.equal(fake.seen.length, at + 1, "a request was sent after the budget ran out");
});

test("a request's timeout is cut to what is left of the budget", async () => {
  const clock = fakeClock();
  const fake = replayed((path, answer) => {
    const response = answer();
    if (path === REPOSITORY) clock.now += 295_000;
    return response;
  });
  const recorded = host(fake.fetch, clock);
  const { error } = await settle(airlock.audit(recorded, request()));
  assert.equal(error, undefined);
  const at = recorded.timeouts.findIndex((entry) => entry.url === `${BASE}${REPOSITORY}`);
  assert.equal(recorded.timeouts[0].timeoutMs, 30_000);
  assert.equal(recorded.timeouts[at].timeoutMs, 30_000);
  assert.equal(recorded.timeouts[at + 1].timeoutMs, 5_000);
});

test("a clock that steps back does not give the budget back", async () => {
  const clock = fakeClock();
  let ahead = false;
  const fake = replayed((path, answer) => {
    const response = answer();
    if (path === REPOSITORY) ahead = true;
    return response;
  });
  const start = clock.now;
  // One reading 295 s on, then the clock is back where it started. The
  // budget has five seconds left from that reading on, whatever the clock
  // says after it.
  const now = () => {
    if (ahead) {
      ahead = false;
      return start + 295_000;
    }
    return start;
  };
  const recorded = host(fake.fetch, { read: now, sleep: clock.sleep });
  const { error } = await settle(airlock.audit(recorded, request()));
  assert.equal(error, undefined);
  const at = recorded.timeouts.findIndex((entry) => entry.url === `${BASE}${REPOSITORY}`);
  const after = recorded.timeouts.slice(at + 1);
  assert.ok(after.length > 0);
  for (const entry of after) {
    assert.ok(entry.timeoutMs <= 5_000, `${entry.url} was given ${entry.timeoutMs} ms`);
  }
});

test("the settings' observation time is the server's Date header, kept as text", async () => {
  const clock = fakeClock();
  const fake = replayed();
  const { report } = await settle(airlock.audit(host(fake.fetch, clock), request()));
  const exchange = recording.exchanges.find((candidate) => candidate.path === REPOSITORY);
  const date = exchange.headers.find(([name]) => name === "date")[1];
  assert.equal(report.repository.settings_observed_at, date);
  assert.deepEqual(fake.unexpected, []);
});

test("a host that hands back more than the byte limit is refused by the module", async () => {
  const clock = fakeClock();
  const fake = replayed();
  const inner = fetchHost({ fetch: fake.fetch, now: clock.read, sleep: clock.sleep });
  const greedy = {
    ...inner,
    // A host that ignores maxResponseBytes.
    fetch: async (req) => ({ status: 200, headers: [], body: new Uint8Array(req.maxResponseBytes + 1) }),
  };
  const { error } = await settle(airlock.audit(greedy, request()));
  assert.ok(error);
  assert.match(error.message, /byte limit/);
});

test("a host's timeout is a budget failure, and a refused connection a transport one", async () => {
  for (const [name, pattern] of [
    ["TimeoutError", /timed out/],
    ["ConnectError", /could not connect/],
  ]) {
    const failing = {
      fetch: async () => {
        const error = new Error(name === "TimeoutError" ? "the request timed out" : "the request could not connect");
        error.name = name;
        throw error;
      },
      sleep: async () => {},
      now: () => 1_800_000_000_000,
    };
    const { error } = await settle(airlock.audit(failing, request()));
    assert.ok(error, name);
    assert.match(error.message, pattern);
  }
});

test("a token whose grant cannot be enumerated is refused before any request", async () => {
  for (const token of ["github_pat_unverifiable", "ghs_installation", "not-a-token"]) {
    const fake = replayed();
    const { error } = await settle(
      airlock.audit(
        fetchHost({ fetch: fake.fetch }),
        JSON.stringify({ token, ...recording.request, githubApi: BASE }),
      ),
    );
    assert.ok(error, token);
    assert.equal(error.kind, "refused", token);
    assert.deepEqual(fake.seen, [], token);
    assert.ok(!error.message.includes(token), "the refusal repeats the token");
  }
});
