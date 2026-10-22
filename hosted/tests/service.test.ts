// relationships: { verifies: ../src/service/service.ts }
import { describe, expect, it, vi } from "vitest";
import { createService } from "../src/service/service.ts";
import { fixtureStore } from "../src/service/store.ts";
import { fixtureReports } from "../src/service/fixtures.ts";
import worker from "../src/service/worker.ts";
import {
  receiveWebhook,
  sweep,
  unavailableWebhook,
} from "../src/service/scheduling.ts";
import {
  IntegrationUnavailable,
  unavailableAdmin,
  unavailableProposals,
  unavailableStepUp,
} from "../src/service/integrations.ts";
const service = createService(fixtureStore(fixtureReports));
const request = (path: string, method = "GET") =>
  new Request(`http://localhost${path}`, { method });

describe("local report service", () => {
  it("returns only summary cards across organizations", async () => {
    const response = await service(request("/api/organizations"));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.json();
    expect(body.mode).toBe("local-fixtures");
    expect(body.organizations).toHaveLength(4);
    expect(body.organizations[0]).toEqual({
      account: "example-org",
      repositories: 3,
      blocking: 3,
      advisory: 3,
      incomplete: 1,
      unassigned: 1,
      observation: { value: "2026-10-22T00:00:00Z", provenance: "capture" },
      unknownAssignments: 0,
    });
    expect(JSON.stringify(body)).not.toContain("field-notes");
    expect(JSON.stringify(body)).not.toContain("instances");
  });
  it("returns one selected org, worst first, retaining original AND result", async () => {
    const response = await service(request("/api/organizations/example-org"));
    expect(response.status).toBe(200);
    const { organization } = await response.json();
    expect(
      organization.repositories.map(
        (repo: { repository: string }) => repo.repository,
      ),
    ).toEqual([
      "example-org/field-notes",
      "example-org/garden-planner",
      "example-org/trail-map",
    ]);
    const combined = organization.repositories[0].results[0];
    expect(combined.rule.instances).toHaveLength(2);
    expect(combined.rule.severity).toBe("blocking");
    expect(combined.warnings).toHaveLength(1);
    expect(
      combined.rule.instances.map(
        (instance: { config_commit: string }) => instance.config_commit,
      ),
    ).toEqual(["a".repeat(40), "b".repeat(40)]);
    expect(JSON.stringify(organization)).not.toContain("sample-team");
    expect(
      organization.unassigned.map(
        (repo: { repository: string }) => repo.repository,
      ),
    ).toEqual(["example-org/weekend-sketches"]);
  });
  it("keeps invalid-rule incomplete, waived/not-applicable passed and observed null", async () => {
    const reports = structuredClone(fixtureReports);
    const repo = reports[0].repositories[1];
    repo.rules.push({
      ...repo.rules[repo.rules.length - 1],
      id: "waived",
      flavor: "waived",
    });
    repo.rules.push({
      ...repo.rules[repo.rules.length - 1],
      id: "not-applicable",
      flavor: "not-applicable",
    });
    const localService = createService(fixtureStore(reports));
    const { organization } = await (
      await localService(request("/api/organizations/example-org"))
    ).json();
    const result = organization.repositories[0].results.find(
      (value: { rule: { id: string } }) => value.rule.id === "ownership-review",
    );
    expect(result.groups).toEqual(["not-evaluated"]);
    expect(result.rule.instances[0].diagnostic.code).toBe("invalid-rule");
    expect(result.rule.instances[0].conditions[0].observed_digest).toBeNull();
    expect(organization.repositories[0].incomplete).toBe(1);
    expect(organization.repositories[0].blocking).toBe(3);
    expect(organization.repositories[0].advisory).toBe(2);
    for (const flavor of ["waived", "not-applicable"]) {
      const passed = organization.repositories[0].results.find(
        (value: { rule: { id: string } }) => value.rule.id === flavor,
      );
      expect(passed.rule.result).toBe("pass");
      expect(passed.rule.flavor).toBe(flavor);
      expect(passed.groups).toEqual([]);
    }
    const { organizations } = await (
      await localService(request("/api/organizations"))
    ).json();
    expect(organizations[0]).toMatchObject({
      blocking: 3,
      advisory: 3,
      incomplete: 1,
    });
  });
  it("refuses missing/cross-org paths and makes HEAD side effect free", async () => {
    expect(
      (await service(request("/api/organizations/absent-org"))).status,
    ).toBe(404);
    expect(
      (await service(request("/api/organizations/example-org/sample-team")))
        .status,
    ).toBe(404);
    expect((await service(request("/api/organizations/%"))).status).toBe(400);
    const head = await service(
      request("/api/organizations/example-org", "HEAD"),
    );
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });
  it.each(["POST", "PUT", "PATCH", "DELETE"])(
    "has no %s write path, including with an API token",
    async (method) => {
      const response = await service(
        new Request("http://localhost/api/organizations/example-org/apply", {
          method,
          headers: { Authorization: "Bearer synthetic-test-value" },
        }),
      );
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({
        error: "integration-unavailable",
      });
      expect(
        (await (await service(request("/api/session"))).json()).admin,
      ).toBe(false);
    },
  );
  it("fixture store isolates caller mutation", async () => {
    const store = fixtureStore(fixtureReports);
    const first = await store.get("example-org");
    if (!first.ok || !first.value) throw new Error("Missing fixture");
    first.value.repositories.length = 0;
    const second = await store.get("example-org");
    if (!second.ok || !second.value) throw new Error("Missing fixture");
    expect(second.value.repositories).toHaveLength(4);
  });
});
describe("Worker deployment boundary", () => {
  const assets = { fetch: vi.fn(async () => new Response("local-assets")) };
  it.each([
    ["http://localhost/api/organizations", {}],
    [
      "https://preview.example/api/organizations",
      { LOCAL_FIXTURES: "enabled" },
    ],
    [
      "https://localhost.preview.example/api/organizations",
      { LOCAL_FIXTURES: "enabled" },
    ],
  ])(
    "does not enable fixture or live reads on %s without both local conditions",
    async (url, env) => {
      const response = await worker.fetch(new Request(url), {
        ...env,
        ASSETS: assets,
      });
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({
        error: "hosted-integration-unavailable",
      });
    },
  );
  it("serves the admitted local API and actual static asset binding", async () => {
    const env = { LOCAL_FIXTURES: "enabled", ASSETS: assets };
    expect(
      (await worker.fetch(request("/api/organizations"), env)).status,
    ).toBe(200);
    expect(await (await worker.fetch(request("/"), env)).text()).toBe(
      "local-assets",
    );
    expect((await worker.fetch(request("/", "POST"), env)).status).toBe(405);
  });
});
describe("unsupported integrations stay closed", () => {
  it("refuses admin, proposal and batch confirmation even for plausible browser inputs", async () => {
    const person = { subject: "sample-person", tabSession: "sample-tab" };
    await expect(
      unavailableAdmin.beginAtFirstReview(person),
    ).rejects.toBeInstanceOf(IntegrationUnavailable);
    await expect(
      unavailableStepUp.confirm(person, {
        organization: "example-org",
        digest: "synthetic-digest",
        changes: [],
      }),
    ).rejects.toBeInstanceOf(IntegrationUnavailable);
    await expect(
      unavailableProposals.propose(
        "example-org",
        "a".repeat(40),
        "proposed content",
      ),
    ).rejects.toBeInstanceOf(IntegrationUnavailable);
    await expect(worker.scheduled()).rejects.toBeInstanceOf(
      IntegrationUnavailable,
    );
  });
  it("does not queue unverified webhooks", async () => {
    const enqueue = vi.fn();
    await expect(
      receiveWebhook(request("/api/webhook", "POST"), unavailableWebhook, {
        enqueue,
      }),
    ).rejects.toBeInstanceOf(IntegrationUnavailable);
    expect(enqueue).not.toHaveBeenCalled();
  });
  it("queues the actual verified target and every sweep org; dispatch failure propagates", async () => {
    const jobs: unknown[] = [];
    const queue = {
      async enqueue(job: unknown) {
        jobs.push(job);
      },
    };
    await receiveWebhook(
      request("/api/webhook", "POST"),
      {
        async verify() {
          return {
            organization: "example-org",
            repository: "example-org/field-notes",
          };
        },
      },
      queue,
    );
    await sweep(
      {
        async list() {
          return ["example-org", "sample-team"];
        },
      },
      queue,
    );
    expect(jobs).toEqual([
      {
        organization: "example-org",
        repository: "example-org/field-notes",
        cause: "webhook",
      },
      { organization: "example-org", repository: null, cause: "sweep" },
      { organization: "sample-team", repository: null, cause: "sweep" },
    ]);
    await expect(
      sweep(
        {
          async list() {
            return ["example-org"];
          },
        },
        {
          async enqueue() {
            throw new Error("queue unavailable");
          },
        },
      ),
    ).rejects.toThrow("queue unavailable");
  });
});
