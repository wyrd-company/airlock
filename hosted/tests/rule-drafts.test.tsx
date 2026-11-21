// relationships: { verifies: ../src/browser/rule-drafts.ts, references: ../fixtures/rule-drafts/organization.yml }
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import organization from "../fixtures/rule-drafts/organization.yml?raw";
import repository from "../fixtures/rule-drafts/repository.yml?raw";
import {
  inspectDraft,
  uncheckedDraftChecks,
} from "../src/browser/rule-drafts.ts";
import { RuleDraftEditor } from "../src/browser/RuleDraftEditor.tsx";
import { fixtureReports } from "../src/service/fixtures.ts";
import { projectOrganization } from "../src/service/projection.ts";

describe("local rule source inspection", () => {
  it("inspects complete source examples without treating aliases as invalid or rounding their source", () => {
    expect(inspectDraft(organization, "organization").diagnostics).toEqual([
      expect.stringContaining("Local checks incomplete"),
    ]);
    expect(inspectDraft(repository, "repository")).toEqual({
      diagnostics: [],
      incomplete: false,
    });
    expect(organization).toContain("9007199254740993");
    expect(organization).toContain("*present");
  });
  it("reports duplicate keys and direct non-string keys, without coercion", () => {
    expect(
      inspectDraft("rules: {}\nrules: {}\n", "repository").diagnostics.join(
        " ",
      ),
    ).toContain("unique");
    for (const key of ["123", "true", "null", "[x]"])
      expect(
        inspectDraft(
          `rules: {sample: {${key}: value}}\n`,
          "repository",
        ).diagnostics.join(" "),
      ).toContain("non-string key");
    expect(
      inspectDraft('rules: {sample: {"123": value}}\n', "repository")
        .diagnostics,
    ).toEqual([]);
  });
  it("checks the chosen envelope and preserves the core's empty/null repository reading", () => {
    for (const text of ["", "# empty\n", "null\n", "~\n", "{}\n"])
      expect(inspectDraft(text, "repository").diagnostics).toEqual([]);
    expect(inspectDraft("", "organization").diagnostics.join(" ")).toContain(
      "requires",
    );
    expect(
      inspectDraft("rules: []\nassignments: {}\n", "organization").diagnostics,
    ).toContain("rules must be a map.");
    expect(
      inspectDraft("rules: {}\nassignments: {}\n", "repository").diagnostics,
    ).toContain("Unknown repository envelope key: assignments.");
    expect(inspectDraft("rules: {}\n", "organization").diagnostics).toContain(
      "Organization configuration requires a assignments map.",
    );
  });
  it("does not report an aliased envelope map or key as a missing or non-string field", () => {
    const valueAlias = inspectDraft(
      "rules: &rules {}\nassignments: *rules\n",
      "organization",
    );
    expect(valueAlias.incomplete).toBe(true);
    expect(valueAlias.diagnostics.join(" ")).not.toMatch(
      /must be a map|requires/,
    );
    const keyAlias = inspectDraft("&key rules: {}\n*key: {}\n", "organization");
    expect(keyAlias.incomplete).toBe(true);
    expect(keyAlias.diagnostics.join(" ")).not.toMatch(
      /non-string key|requires/,
    );
  });
  it("makes malformed syntax visible and leaves malformed rule bodies explicitly unchecked", () => {
    expect(
      inspectDraft("rules: [\n", "repository").diagnostics.length,
    ).toBeGreaterThan(0);
    expect(
      inspectDraft("rules: {broken: 7}\n", "repository").diagnostics,
    ).toEqual([]);
    expect(uncheckedDraftChecks).toContain("Rule and assignment bodies");
    expect(uncheckedDraftChecks).toContain(
      "not an audit or full configuration validation",
    );
    expect(inspectDraft("rules: {}\n", "repository").diagnostics).toEqual([]);
  });
  it("labels tags, byte/depth and traversal limits as incomplete inspection, not a draft refusal", () => {
    expect(
      inspectDraft("rules: {sample: !example value}\n", "repository")
        .incomplete,
    ).toBe(true);
    expect(
      inspectDraft("#".repeat(512 * 1024 + 1), "repository").diagnostics.join(
        " ",
      ),
    ).toContain("remains editable");
    expect(
      inspectDraft(`rules: ${"[".repeat(35)}0${"]".repeat(35)}\n`, "repository")
        .incomplete,
    ).toBe(true);
    expect(
      inspectDraft(`rules: {sample: [${"0,".repeat(20_001)}]}\n`, "repository")
        .incomplete,
    ).toBe(true);
  });
  it("renders explicit source provenance, lifetime and unavailable submission before loading bytes", () => {
    const org = projectOrganization(fixtureReports[0]);
    const before = structuredClone(org);
    const html = renderToStaticMarkup(<RuleDraftEditor org={org} />);
    expect(html).toContain("Use complete organization example");
    expect(html).toContain("Use pasted source as baseline");
    expect(html).toContain("unverified");
    expect(html).toContain("discards your text");
    expect(html).toContain("disabled");
    expect(html).toContain(org.organizationConfig.commit);
    expect(org).toEqual(before);
  });
});
