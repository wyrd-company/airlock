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
    reason: "Requirement is not met",
    conditions: [],
    fixes: fixers.map((kind) => ({
      kind,
      origin: "derived",
      description: `Fix by ${kind}`,
    })),
  };
}
function syntheticRule(id: string, fixers: Fixer[]): RuleResult {
  return {
    id,
    statement: `Requirement ${id}`,
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
      expect(output.fixes).toEqual([
        { kind, origin: "derived", description: `Fix by ${kind}` },
      ]);
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
      { kind: "agent", origin: "derived", description: "Fix by agent" },
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
