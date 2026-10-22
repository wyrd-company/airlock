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
    expect(html).toContain("Org + repo · AND");
    expect(html).toContain("Organization requirement");
    expect(html).toContain("Repository requirement");
    expect(html).toContain("Relaxation warning");
    expect(html).toContain('aria-label="Select Protect the default branch"');
    expect(html).toContain("a".repeat(40));
    expect(html).toContain("b".repeat(40));
  });
  it("escapes untrusted result strings and displays absent evidence honestly", () => {
    const result = structuredClone(
      projectOrganization(fixtureReports[0]).repositories[0].results[4],
    );
    result.rule.statement = "<script>untrusted()</script>";
    const html = renderToStaticMarkup(<RuleRow result={result} />);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("Not observed");
    expect(html).toContain("Invalid rule");
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
