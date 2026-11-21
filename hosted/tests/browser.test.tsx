// relationships: { verifies: ../src/browser/App.tsx }
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { RuleRow, readRoute } from "../src/browser/App.tsx";
import { fixtureReports } from "../src/service/fixtures.ts";
import { projectOrganization } from "../src/service/projection.ts";
describe("browser projection", () => {
  it("renders one same-id AND row with both sources and relaxation warning", () => {
    const result = projectOrganization(fixtureReports[0]).repositories[0]
      .results[0];
    const html = renderToStaticMarkup(
      <RuleRow result={result} selectable selected toggle={() => {}} />,
    );
    expect(html.match(/<summary>/g)).toHaveLength(1);
    const title = html.match(/class="rule-title">([\s\S]*?)<\/summary>/)![1];
    expect(title.match(/default-branch-protection/g)).toHaveLength(1);
    expect(html).toContain("Org + repo · AND");
    expect(html).toContain("Organization requirement");
    expect(html).toContain("Repository requirement");
    expect(html).toContain("Rule warning");
    expect(html).toContain('aria-label="Select default-branch-protection"');
    expect(html).toContain("a".repeat(40));
    expect(html).toContain("b".repeat(40));
  });
  it("escapes untrusted result strings and displays absent evidence honestly", () => {
    const result = structuredClone(
      projectOrganization(fixtureReports[0]).repositories[0].results[4],
    );
    result.rule.instances[0].statement = "<script>untrusted()</script>";
    const html = renderToStaticMarkup(<RuleRow result={result} />);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("Unavailable");
    expect(html).toContain("invalid-rule");
  });
  it("limits routes to one organization and recognized section", () => {
    expect(readRoute("#/example-org/repos/field-notes")).toEqual({
      organization: "example-org",
      section: "repos",
      repository: "field-notes",
    });
    expect(readRoute("#/")).toEqual({ section: "repos" });
    expect(readRoute("#/sample-team/activity")).toEqual({
      organization: "sample-team",
      section: "repos",
      repository: undefined,
    });
    expect(readRoute("#/%")).toEqual({ section: "repos" });
  });
});
