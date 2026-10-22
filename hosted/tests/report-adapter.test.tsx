// relationships: { verifies: ../src/service/report-adapter.ts, references: ../fixtures/configurable-report.json }
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import fixture from "../fixtures/configurable-report.json" with { type: "json" };
import type { EngineReport } from "../src/shared/engine-report.ts";
import { adaptReport } from "../src/service/report-adapter.ts";
import { engineReportStore } from "../src/service/store.ts";
import { createService } from "../src/service/service.ts";
import { projectOrganization, summarize } from "../src/service/projection.ts";
import {
  Assignments,
  Observation,
  RepositoryTable,
  RepositoryResults,
  RuleRow,
  RuleCatalog,
  UnassignedRepositories,
} from "../src/browser/App.tsx";
import { filterRepositories } from "../src/browser/view.ts";

const request = (path: string, method = "GET") =>
  new Request(`http://localhost/api/organizations${path}`, { method });
async function consumer(report: unknown = fixture) {
  const service = createService(engineReportStore([{ report }]));
  const response = await service(request("/sample"));
  expect(response.status).toBe(200);
  const detail = await response.json();
  const summary = await (await service(request(""))).json();
  return { view: detail.organization, summary: summary.organizations[0] };
}
function projected(report: unknown = fixture) {
  const result = adaptReport(report);
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return projectOrganization(result.value);
}
// Labeled, representable boundary cases start from the engine fixture and
// explicitly replace the fields under test. They are not engine emission proof.
function boundary(): EngineReport {
  const parsed = adaptReport(fixture);
  if (!parsed.ok) throw new Error("Engine fixture invalid");
  return {
    ...parsed.value,
    repositories: parsed.value.repositories.map((repo) => ({
      ...repo,
      rules: repo.rules.map((rule) => ({
        ...rule,
        instances: rule.instances.map((instance) => ({
          ...instance,
          fixes: instance.fixes.map((fix) => fix.plan),
        })),
      })),
    })),
  };
}

describe("actual engine report consumers", () => {
  it("separates explicit unassigned repositories exactly once through API and rendered consumers", async () => {
    const report = boundary();
    report.unassigned_repositories.push(report.unassigned_repositories[0]);
    const { view, summary } = await consumer(report);
    expect(
      view.repositories.map((repo: { repository: string }) => repo.repository),
    ).toEqual(["sample/sample-kit"]);
    expect(view.unassigned).toHaveLength(1);
    expect(view.unassigned[0]).toEqual(report.repositories[0]);
    expect(summary).toMatchObject({
      repositories: 1,
      unassigned: 1,
      unknownAssignments: 0,
      blocking: 2,
      incomplete: 1,
    });
    const html = renderToStaticMarkup(
      <>
        <RepositoryTable
          account="sample"
          repositories={view.repositories}
          filter="all"
          search=""
        />
        <UnassignedRepositories repositories={view.unassigned} />
      </>,
    );
    expect(html.match(/class="repo-row"/g)).toHaveLength(1);
    expect(html.match(/<summary>other-kit/g)).toHaveLength(1);
    expect(html).toContain("Unassigned");
    expect(html).toContain("not matched");
    expect(html).toContain("c".repeat(40));
  });
  it("retains real AND values, source commits, evidence, diagnostics and scoped warnings", async () => {
    const { view } = await consumer();
    const repo = view.repositories[0];
    expect(repo.audited_commit).toBe("c".repeat(40));
    expect(repo.assignments).toEqual([
      { id: "selected", matched: true, diagnostic: null },
    ]);
    const [and, unavailable] = repo.results;
    expect(and.rule).toMatchObject({
      id: "sample-measure",
      result: "fail",
      flavor: "gap",
      severity: "blocking",
    });
    expect(and.rule).not.toHaveProperty("statement");
    expect(
      and.rule.instances.map((i: { result: string; config_commit: string }) => [
        i.result,
        i.config_commit,
      ]),
    ).toEqual([
      ["fail", "a".repeat(40)],
      ["pass", "b".repeat(40)],
    ]);
    expect(and.rule.instances[0].conditions[0]).toEqual(
      fixture.repositories[1].rules[0].instances[0].conditions[0],
    );
    expect(and.rule.instances[0]).toMatchObject({
      statement: "The sample meets the configured measure.",
      reason: null,
      relaxation_reason: null,
      mode: "value",
      diagnostic: null,
    });
    expect(and.fixes).toEqual([
      {
        kind: "agent",
        plan: {
          kind: "agent",
          guidance: "Expand the sample and document the result.",
        },
      },
    ]);
    expect(and.groups).toEqual(["agent"]);
    expect(and.warnings).toEqual(fixture.repositories[1].warnings);
    expect(unavailable.warnings).toEqual([]);
    expect(unavailable.groups).toEqual(["not-evaluated"]);
    expect(unavailable.rule.instances[0]).toMatchObject({
      statement: null,
      reason: null,
      diagnostic: {
        code: "invalid-rule",
        reason: "unknown evaluation type external-judgment-not-adopted",
      },
    });
    const html = renderToStaticMarkup(
      <>
        <RuleRow result={and} />
        <RuleRow result={unavailable} />
        <Observation value={view.observation} />
      </>,
    );
    expect(html.match(/<summary>/g)).toHaveLength(2);
    for (const text of [
      "Org + repo · AND",
      "Observed digest",
      "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
      "invalid-rule",
      "Statement unavailable",
      "relaxation-without-reason",
      "Audit time unavailable",
    ])
      expect(html).toContain(text);
    expect(html).not.toContain("Derived fix");
    expect(html).not.toContain("Declaration");
  });
  it("omits unsupported metadata and keeps store reads isolated", async () => {
    const report = boundary();
    Object.assign(report.repositories[1], {
      archived: false,
      language: "invented",
      visibility: "invented",
      default_branch: "invented",
    });
    const store = engineReportStore([{ report }]);
    const read = await store.get("sample");
    if (!read.ok || !read.value) throw new Error("Missing report");
    read.value.repositories.length = 0;
    const next = await store.list();
    if (!next.ok) throw new Error("Missing reports");
    expect(next.value[0].repositories).toHaveLength(2);
    expect(JSON.stringify((await consumer(report)).view)).not.toMatch(
      /archived|language|visibility|default_branch|origin|observed_at/,
    );
  });
});

describe("labeled representable boundary consumers", () => {
  it("keeps zero-rule unknown assignments visibly incomplete and out of healthy assigned counts", async () => {
    const report = boundary();
    report.unassigned_repositories = [];
    report.repositories[0].assignments[0] = {
      id: "selected",
      matched: null,
      diagnostic: {
        code: "probe-unavailable",
        reason: "Selection could not be observed",
      },
    };
    const { view, summary } = await consumer(report);
    const unknown = view.repositories.find(
      (repo: { repository: string }) => repo.repository === "sample/other-kit",
    );
    expect(unknown.assignments).toEqual(report.repositories[0].assignments);
    expect(unknown.incomplete).toBe(1);
    expect(summary).toMatchObject({
      repositories: 1,
      unknownAssignments: 1,
      unassigned: 0,
      incomplete: 2,
    });
    expect(view.unassigned).toEqual([]);
    const html = renderToStaticMarkup(
      <RepositoryTable
        account="sample"
        repositories={[unknown]}
        filter="all"
        search=""
      />,
    );
    expect(html).toContain("Assignment unknown");
    expect(html).toContain("selected: unknown");
    expect(html).not.toContain("All evaluated rules pass");
    expect(html).not.toContain("repo-indicator green");
    const assignments = renderToStaticMarkup(
      <Assignments org={view} onProposal={() => {}} />,
    );
    expect(assignments).toContain("probe-unavailable");
    expect(assignments).toContain("Unknown — incomplete");
  });
  it("preserves pass, waiver and representable not-applicable separately from actual emission", async () => {
    const report = boundary();
    const repo = report.repositories[1];
    repo.rules = ["passed", "waived", "not-applicable"].map(
      (flavor, index) => ({
        ...repo.rules[0],
        id: `boundary-${index}`,
        result: "pass",
        flavor:
          flavor === "passed"
            ? "passed"
            : flavor === "waived"
              ? "waived"
              : "not-applicable",
        severity: "none",
        instances: [
          {
            ...repo.rules[0].instances[0],
            result: "pass",
            flavor:
              flavor === "passed"
                ? "passed"
                : flavor === "waived"
                  ? "waived"
                  : "not-applicable",
            reason: "Labeled boundary case",
            severity: "none",
            conditions: [],
            fixes: [],
          },
        ],
      }),
    );
    const { view, summary } = await consumer(report);
    expect(
      view.repositories[0].rules.map(
        (rule: { result: string; flavor: string }) => [
          rule.result,
          rule.flavor,
        ],
      ),
    ).toEqual([
      ["pass", "passed"],
      ["pass", "waived"],
      ["pass", "not-applicable"],
    ]);
    expect(summary).toMatchObject({ blocking: 0, advisory: 0, incomplete: 0 });
    const html = renderToStaticMarkup(
      <RepositoryResults
        results={view.repositories[0].results}
        filter="all"
        sort="report"
        selected={new Set()}
        onToggle={() => {}}
        onReview={() => {}}
      />,
    );
    for (const flavor of ["passed", "waived", "not-applicable"])
      expect(html).toContain(flavor);
    expect(html).not.toContain('class="result-group"');
  });
  it("preserves mixed severities, null evidence, action input and multi-fixer order without inventing origin", async () => {
    const report = boundary();
    const rule = report.repositories[1].rules[0];
    rule.severity = "advisory";
    const org = rule.instances[0],
      repo = rule.instances[1];
    org.severity = "advisory";
    org.mode = "floor";
    org.relaxation_reason = "Explicit exception";
    org.conditions[0] = {
      ...org.conditions[0],
      expected: { minimum: [2, null, true] },
      observed_digest: null,
      diagnostic: {
        code: "evidence-unavailable",
        reason: "No digest was retained",
      },
    };
    org.fixes = [
      { kind: "not-fixable", reason: "Needs independent work" },
      {
        kind: "action",
        fixer: "airlock",
        action: "propose-config",
        input: { nested: [1, false] },
      },
      {
        kind: "action",
        fixer: "person",
        action: "review-setting",
        input: null,
      },
      { kind: "agent", guidance: "Inspect the measure" },
    ];
    repo.fixes = [
      {
        kind: "action",
        fixer: "person",
        action: "must-not-be-actionable",
        input: {},
      },
    ];
    const { view } = await consumer(report);
    const output = view.repositories[0].results[0];
    expect(output.rule.severity).toBe("advisory");
    expect(
      output.rule.instances.map((i: { severity: string; result: string }) => [
        i.result,
        i.severity,
      ]),
    ).toEqual([
      ["fail", "advisory"],
      ["pass", "blocking"],
    ]);
    expect(output.fixes.map((fix: { kind: string }) => fix.kind)).toEqual([
      "not-fixable",
      "airlock-pr",
      "you",
      "agent",
    ]);
    expect(output.groups).toEqual([
      "you",
      "airlock-pr",
      "agent",
      "not-fixable",
    ]);
    expect(output.fixes.map((fix: { plan: unknown }) => fix.plan)).toEqual(
      org.fixes,
    );
    for (const group of ["you", "airlock-pr", "agent", "not-fixable"] as const)
      expect(
        filterRepositories(view.repositories, "sample", group),
      ).toHaveLength(1);
    const html = renderToStaticMarkup(
      <>
        <RuleRow result={output} />
        <RuleCatalog org={view} onProposal={() => {}} />
      </>,
    );
    for (const text of [
      "You",
      "Airlock PR",
      "propose-config",
      "nested",
      "Explicit exception",
      "evidence-unavailable",
      "Unavailable",
      "advisory",
      "blocking",
    ])
      expect(html).toContain(text);
    rule.flavor = "not-evaluated";
    expect(projected(report).repositories[0].results[0].groups).toEqual([
      "not-evaluated",
    ]);
  });
  it("labels supplemental capture/audit time and accepts unavailable time", () => {
    for (const provenance of ["capture", "audit"] as const) {
      const result = adaptReport(fixture, {
        provenance,
        value: "2026-01-01T00:00:00Z",
      });
      if (!result.ok) throw new Error("Invalid explicit time");
      const html = renderToStaticMarkup(
        <Observation value={result.value.observation} />,
      );
      expect(html).toContain(
        provenance === "capture" ? "Capture time" : "Audit time",
      );
    }
    expect(summarize(projected()).observation).toEqual({
      value: null,
      provenance: "unavailable",
    });
    expect(
      adaptReport(fixture, { provenance: "audit", value: "invalid" }).ok,
    ).toBe(false);
  });
});

describe("malformed actual input is unavailable", () => {
  it("rejects an unassigned identity without its promised metadata row", async () => {
    const report = boundary();
    report.repositories = report.repositories.slice(1);
    const response = await createService(engineReportStore([{ report }]))(
      request("/sample"),
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.path).toBe(
      "report.unassigned_repositories",
    );
  });

  it.each([
    [
      "required structure",
      () => ({ account: "sample" }),
      "report.organization_config",
    ],
    [
      "result enum",
      () => {
        const r = boundary();
        Object.assign(r.repositories[1].rules[0], { result: "success" });
        return r;
      },
      "report.repositories[1].rules[0].result",
    ],
    [
      "fix tag",
      () => {
        const r = boundary();
        Object.assign(r.repositories[1].rules[0].instances[0].fixes[0], {
          kind: "run",
        });
        return r;
      },
      "report.repositories[1].rules[0].instances[0].fixes[0].kind",
    ],
    [
      "assignment tristate",
      () => {
        const r = boundary();
        Object.assign(r.repositories[0].assignments[0], { matched: "unknown" });
        return r;
      },
      "report.repositories[0].assignments[0].matched",
    ],
    [
      "nullable required field",
      () => {
        const r = boundary();
        Reflect.deleteProperty(
          r.repositories[1].rules[0].instances[0],
          "statement",
        );
        return r;
      },
      "report.repositories[1].rules[0].instances[0].statement",
    ],
  ] as const)(
    "returns typed 503 for %s on both read endpoints and bodyless HEAD",
    async (_, input, path) => {
      const service = createService(engineReportStore([{ report: input() }]));
      for (const suffix of ["", "/sample"]) {
        const response = await service(request(suffix));
        expect(response.status).toBe(503);
        expect(await response.json()).toEqual({
          error: {
            code: "invalid-engine-report",
            path,
            reason: expect.any(String),
          },
        });
        const head = await service(request(suffix, "HEAD"));
        expect(head.status).toBe(503);
        expect(await head.text()).toBe("");
      }
    },
  );
});
