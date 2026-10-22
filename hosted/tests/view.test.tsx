// relationships: { verifies: ../src/browser/view.ts, references: ../src/browser/App.tsx }
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  RepositoryResults,
  RepositoryTable,
  RuleCatalog,
} from "../src/browser/App.tsx";
import {
  filterRepositories,
  incompleteLabel,
  observedRuleCatalog,
  partitionResults,
} from "../src/browser/view.ts";
import { projectOrganization } from "../src/service/projection.ts";
import { fixtureReports } from "../src/service/fixtures.ts";
import type { Fixer, ResultView } from "../src/shared/report.ts";

function result(
  id: string,
  groups: Fixer[],
  severity: "blocking" | "advisory" | "none" = "blocking",
): ResultView {
  const base = structuredClone(
    projectOrganization(fixtureReports[0]).repositories[0].results[0],
  );
  return {
    ...base,
    rule: { ...base.rule, id, statement: `Requirement ${id}`, severity },
    groups,
  };
}
function panel(
  results: ResultView[],
  filter: Parameters<typeof partitionResults>[1] = "all",
  sort: Parameters<typeof partitionResults>[2] = "report",
) {
  return renderToStaticMarkup(
    <RepositoryResults
      results={results}
      filter={filter}
      sort={sort}
      selected={new Set()}
      onToggle={() => {}}
      onReview={() => {}}
    />,
  );
}
const rowCount = (html: string) =>
  (html.match(/class="repo-row"/g) ?? []).length;

describe("shared organization queue", () => {
  it("matches secondary fixers of failing results and excludes passes", () => {
    const repositories = structuredClone(
      projectOrganization(fixtureReports[0]).repositories,
    );
    repositories[0].results = [result("shared-work", ["you", "agent"])];
    const passed = result("passed", ["agent"]);
    passed.rule.result = "pass";
    passed.rule.flavor = "passed";
    repositories[1].results = [passed];
    repositories[2].results = [result("other-work", ["you"])];
    expect(
      filterRepositories(repositories, "FIELD", "agent").map(
        (repo) => repo.repository,
      ),
    ).toEqual(["example-org/field-notes"]);
    const props = {
      account: "example-org",
      repositories,
      filter: "agent" as const,
    };
    const shown = renderToStaticMarkup(
      <RepositoryTable {...props} search="" />,
    );
    expect(rowCount(shown)).toBe(1);
    expect(shown).toContain("field-notes");
    expect(shown).not.toContain("garden-planner");
    expect(shown).not.toContain("No repositories match this view.");
    for (const search of ["garden-planner", "missing"]) {
      const empty = renderToStaticMarkup(
        <RepositoryTable {...props} search={search} />,
      );
      expect(rowCount(empty)).toBe(0);
      expect(empty).toContain("No repositories match this view.");
    }
  });
  it("pluralizes incomplete counts in a rendered repository row", () => {
    const repositories = structuredClone(
      projectOrganization(fixtureReports[0]).repositories,
    );
    repositories[0].incomplete = 2;
    expect(
      renderToStaticMarkup(
        <RepositoryTable
          account="example-org"
          repositories={repositories}
          filter="all"
          search="field"
        />,
      ),
    ).toContain("2 results couldn&#x27;t be evaluated");
    expect(incompleteLabel(1)).toBe("1 result couldn't be evaluated");
  });
});
describe("shared repository result partition", () => {
  it("places a multi-fixer result once in its primary group and keeps passes collapsed", () => {
    const shared = result("shared-work", ["you", "agent"]);
    const agent = result("agent-work", ["agent"]);
    const pass = result("passed-work", []);
    pass.rule.result = "pass";
    pass.rule.flavor = "passed";
    const partition = partitionResults([shared, agent, pass], "all", "report");
    expect(
      partition.groups.map(({ group, results }) => [
        group,
        results.map((result) => result.rule.id),
      ]),
    ).toEqual([
      ["you", ["shared-work"]],
      ["airlock-pr", []],
      ["agent", ["agent-work"]],
      ["not-fixable", []],
      ["not-evaluated", []],
    ]);
    expect(partition.passing.map((result) => result.rule.id)).toEqual([
      "passed-work",
    ]);
    const html = panel([shared, agent, pass]);
    expect(html.match(/class="rule-row /g)).toHaveLength(3);
    expect(html.match(/data-result-group="you"/g)).toHaveLength(1);
    const you = html.match(/data-result-group="you"([\s\S]*?)<\/section>/)![1];
    const agentSection = html.match(
      /data-result-group="agent"([\s\S]*?)<\/section>/,
    )![1];
    expect(you).toContain("shared-work");
    expect(agentSection).not.toContain("shared-work");
    expect(agentSection).toContain("agent-work");
    expect(html).toContain('<details class="passes">');
    expect(html).toContain("You + Agent");
  });
  it("filters result states without flattening groups or opening passes", () => {
    const org = projectOrganization(fixtureReports[0]);
    const results = org.repositories[0].results;
    const ids = (filter: Parameters<typeof partitionResults>[1]) => {
      const view = partitionResults(results, filter, "report");
      return [
        ...view.groups.flatMap((group) => group.results),
        ...view.passing,
      ].map((result) => result.rule.id);
    };
    expect(ids("pass")).toEqual(["license-present"]);
    expect(ids("fail")).toEqual([
      "default-branch-protection",
      "readme-installation",
      "contribution-guide",
      "release-evidence",
      "ownership-review",
    ]);
    expect(ids("not-evaluated")).toEqual(["ownership-review"]);
    expect(ids("blocking")).toEqual([
      "default-branch-protection",
      "release-evidence",
      "ownership-review",
    ]);
    expect(ids("advisory")).toEqual([
      "readme-installation",
      "contribution-guide",
    ]);
    const passHtml = panel(results, "pass");
    expect(passHtml).not.toContain('class="result-group"');
    expect(passHtml).toContain('<details class="passes">');
    expect(passHtml).toContain("Showing 1 of 6 results");
    const failureHtml = panel(results, "fail");
    expect(failureHtml).toContain('data-result-group="you"');
    expect(failureHtml).toContain('data-result-group="not-evaluated"');
    expect(failureHtml).not.toContain("license-present");
    expect(failureHtml).toContain('<details class="passes">');
  });
  it("sorts inside the retained fixer groups and does not mutate report order", () => {
    const results = [
      result("m-low", ["you"], "none"),
      result("a-middle", ["you"], "advisory"),
      result("z-high", ["you"], "blocking"),
      result("agent-result", ["agent"]),
    ];
    const youIds = (sort: Parameters<typeof partitionResults>[2]) =>
      partitionResults(results, "all", sort).groups[0].results.map(
        (result) => result.rule.id,
      );
    expect(youIds("report")).toEqual(["m-low", "a-middle", "z-high"]);
    expect(youIds("severity")).toEqual(["z-high", "a-middle", "m-low"]);
    expect(youIds("rule")).toEqual(["a-middle", "m-low", "z-high"]);
    expect(results.map((result) => result.rule.id)).toEqual([
      "m-low",
      "a-middle",
      "z-high",
      "agent-result",
    ]);
    const html = panel(results, "all", "severity");
    expect(html.indexOf("z-high")).toBeLessThan(html.indexOf("a-middle"));
    expect(html.indexOf("a-middle")).toBeLessThan(html.indexOf("m-low"));
    expect(html).toContain('data-result-group="agent"');
  });
});
describe("observed Rules index", () => {
  it("labels different statements/severities by repository without choosing a global winner", () => {
    const org = structuredClone(projectOrganization(fixtureReports[0]));
    org.repositories = org.repositories.slice(0, 2);
    org.repositories[0].results = [result("shared-rule", ["you"], "advisory")];
    org.repositories[0].results[0].rule.statement = "Building requirement";
    org.repositories[1].results = [result("shared-rule", ["you"], "blocking")];
    org.repositories[1].results[0].rule.statement = "Released requirement";
    const catalog = observedRuleCatalog(org.repositories);
    expect(catalog).toEqual([
      {
        id: "shared-rule",
        observations: [
          {
            repository: "example-org/field-notes",
            maturity: "building",
            statement: "Building requirement",
            severity: "advisory",
          },
          {
            repository: "example-org/garden-planner",
            maturity: "released",
            statement: "Released requirement",
            severity: "blocking",
          },
        ],
      },
    ]);
    const html = renderToStaticMarkup(
      <RuleCatalog org={org} onProposal={() => {}} />,
    );
    const summary = html.match(/<summary>([\s\S]*?)<\/summary>/)![1];
    expect(summary).toContain("shared-rule");
    expect(summary).not.toContain("advisory");
    expect(summary).not.toContain("blocking");
    expect(summary).not.toContain("requirement");
    expect(html).toContain("Building requirement");
    expect(html).toContain("Released requirement");
    expect(html.match(/class="catalog-observation"/g)).toHaveLength(2);
    org.repositories.reverse();
    expect(
      renderToStaticMarkup(<RuleCatalog org={org} onProposal={() => {}} />),
    ).toBe(html);
  });
});
