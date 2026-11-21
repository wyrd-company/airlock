// relationships: { verifies: ../src/service/projection.ts }
import { describe, expect, it } from "vitest";
import { projectOrganization } from "../src/service/projection.ts";
import { fixtureReports } from "../src/service/fixtures.ts";
import type {
  Fixer,
  OrganizationReport,
  RuleInstance,
  RuleResult,
} from "../src/shared/report.ts";

function instance(fixers: Fixer[]): RuleInstance {
  return {
    source: "organization",
    config_commit: "a".repeat(40),
    mode: "value",
    result: "fail",
    flavor: "gap",
    statement: "Requirement",
    severity: "blocking",
    relaxation_reason: null,
    diagnostic: null,
    reason: "Requirement is not met",
    conditions: [],
    fixes: fixers.map((kind) => ({
      kind,
      plan:
        kind === "you" || kind === "airlock-pr"
          ? {
              kind: "action",
              fixer: kind === "you" ? "person" : "airlock",
              action: "boundary-action",
              input: null,
            }
          : kind === "agent"
            ? { kind: "agent", guidance: `Fix by ${kind}` }
            : { kind: "not-fixable", reason: `Fix by ${kind}` },
    })),
  };
}
function syntheticRule(id: string, fixers: Fixer[]): RuleResult {
  return {
    id,
    result: "fail",
    flavor: "gap",
    severity: "blocking",
    instances: [instance(fixers)],
  };
}
function project(rule: RuleResult) {
  const report: OrganizationReport = structuredClone(fixtureReports[0]);
  report.repositories = [{ ...report.repositories[0], rules: [rule] }];
  return projectOrganization(report).repositories[0].results[0];
}

describe("fixer projection", () => {
  it.each(["you", "airlock-pr", "agent", "not-fixable"] as const)(
    "places a single %s fix in its own group",
    (kind) => {
      const output = project(syntheticRule("one-fixer", [kind]));
      expect(output.groups).toEqual([kind]);
      expect(output.fixes.map((fix) => fix.kind)).toEqual([kind]);
    },
  );
  it("keeps every failing-instance fixer in display order without duplicating groups", () => {
    const rule = syntheticRule("many-fixers", ["not-fixable", "agent"]);
    rule.instances.push({
      ...instance(["airlock-pr", "you", "agent"]),
      source: "repository",
      config_commit: "b".repeat(40),
    });
    expect(project(rule).groups).toEqual([
      "you",
      "airlock-pr",
      "agent",
      "not-fixable",
    ]);
    expect(project(rule).fixes).toHaveLength(5);
  });
  it("excludes fixes from passing instances of a failing AND result", () => {
    const rule = syntheticRule("mixed-instances", ["agent"]);
    rule.instances.push({
      ...instance(["you", "airlock-pr"]),
      source: "repository",
      result: "pass",
      flavor: "passed",
    });
    const result = project(rule);
    expect(result.groups).toEqual(["agent"]);
    expect(result.fixes).toEqual([
      { kind: "agent", plan: { kind: "agent", guidance: "Fix by agent" } },
    ]);
  });
  it("puts a failure without a failing-instance fix in not-fixable", () => {
    const result = project(syntheticRule("no-fix", []));
    expect(result.rule.result).toBe("fail");
    expect(result.fixes).toEqual([]);
    expect(result.groups).toEqual(["not-fixable"]);
  });
  it("gives not-evaluated precedence over every fixer", () => {
    const rule = syntheticRule("not-observed", [
      "you",
      "airlock-pr",
      "agent",
      "not-fixable",
    ]);
    rule.flavor = "not-evaluated";
    rule.instances[0].flavor = "not-evaluated";
    expect(project(rule).groups).toEqual(["not-evaluated"]);
  });
});

function orderingReport(
  entries: { name: string; rules: RuleResult[] }[],
): OrganizationReport {
  const report = structuredClone(fixtureReports[0]);
  report.repositories = entries.map(({ name, rules }) => ({
    ...report.repositories[0],
    repository: `example-org/${name}`,
    repository_config: null,
    rules,
    warnings: [],
  }));
  return report;
}
const blocking = () => syntheticRule("required-setting", ["you"]);
const advisory = () => ({
  ...syntheticRule("documentation", ["agent"]),
  severity: "advisory" as const,
});
describe("repository ordering and warning attribution", () => {
  it("orders advisory gaps before opposing names when blocking counts tie", () => {
    const report = orderingReport([
      { name: "a-fewer-gaps", rules: [blocking()] },
      { name: "z-more-gaps", rules: [blocking(), advisory()] },
    ]);
    const rows = projectOrganization(report).repositories;
    expect(
      rows.map((row) => [row.blocking, row.advisory, row.incomplete]),
    ).toEqual([
      [1, 1, 0],
      [1, 0, 0],
    ]);
    expect(rows.map((row) => row.repository)).toEqual([
      "example-org/z-more-gaps",
      "example-org/a-fewer-gaps",
    ]);
  });
  it("orders incomplete results before opposing names when blocking and advisory counts tie", () => {
    const unknown = blocking();
    unknown.flavor = "not-evaluated";
    unknown.instances[0].flavor = "not-evaluated";
    const report = orderingReport([
      { name: "a-evaluated", rules: [blocking()] },
      { name: "z-incomplete", rules: [unknown] },
    ]);
    const rows = projectOrganization(report).repositories;
    expect(
      rows.map((row) => [row.blocking, row.advisory, row.incomplete]),
    ).toEqual([
      [1, 0, 1],
      [1, 0, 0],
    ]);
    expect(rows.map((row) => row.repository)).toEqual([
      "example-org/z-incomplete",
      "example-org/a-evaluated",
    ]);
  });
  it("prioritizes advisory counts over incomplete counts when blocking counts tie", () => {
    const unknown = blocking();
    unknown.flavor = "not-evaluated";
    unknown.instances[0].flavor = "not-evaluated";
    const report = orderingReport([
      { name: "a-incomplete", rules: [unknown] },
      { name: "z-advisory", rules: [blocking(), advisory()] },
    ]);
    const rows = projectOrganization(report).repositories;
    expect(
      rows.map((row) => [row.blocking, row.advisory, row.incomplete]),
    ).toEqual([
      [1, 1, 0],
      [1, 0, 1],
    ]);
    expect(rows.map((row) => row.repository)).toEqual([
      "example-org/z-advisory",
      "example-org/a-incomplete",
    ]);
  });
  it("uses repository names only after all failure counts tie", () => {
    const report = orderingReport([
      { name: "z-notes", rules: [blocking(), advisory()] },
      { name: "a-notes", rules: [blocking(), advisory()] },
    ]);
    expect(
      projectOrganization(report).repositories.map((row) => row.repository),
    ).toEqual(["example-org/a-notes", "example-org/z-notes"]);
  });
  it("attaches a relaxation warning only to its matching rule", () => {
    const report = orderingReport([
      { name: "field-notes", rules: [blocking(), advisory()] },
    ]);
    report.repositories[0].warnings = [
      {
        rule: "required-setting",
        code: "relaxation-without-reason",
        reason: "This setting was relaxed without a reason.",
      },
      {
        rule: "absent-rule",
        code: "relaxation-without-reason",
        reason: "A different requirement was relaxed.",
      },
    ];
    const results = projectOrganization(report).repositories[0].results;
    expect(
      results.find((row) => row.rule.id === "documentation")!.warnings,
    ).toEqual([]);
    expect(
      results.find((row) => row.rule.id === "required-setting")!.warnings,
    ).toEqual([
      {
        rule: "required-setting",
        code: "relaxation-without-reason",
        reason: "This setting was relaxed without a reason.",
      },
    ]);
  });
});
