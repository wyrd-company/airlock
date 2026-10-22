// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/report.ts }
// Explicit synthetic boundary cases used by legacy consumer tests only.
import type {
  ConfigSource,
  OrganizationReport,
  RepositoryReport,
  RuleInstance,
  RuleResult,
  Severity,
  Fixer,
  Flavor,
} from "../shared/report.ts";
const orgCommit = "a".repeat(40),
  repoCommit = "b".repeat(40);
function source(repository: string, commit: string): ConfigSource {
  return { repository, path: ".github/airlock.yml", commit };
}
function instance(
  reason: string,
  fixer: Fixer,
  flavor: Flavor = "gap",
): RuleInstance {
  return {
    source: "organization",
    config_commit: orgCommit,
    mode: "floor",
    statement: reason,
    severity: "blocking",
    relaxation_reason: null,
    diagnostic:
      flavor === "not-evaluated"
        ? { code: "invalid-rule", reason: "Invalid rule" }
        : null,
    result: "fail",
    flavor,
    reason,
    conditions: [
      {
        index: 0,
        result: "fail",
        flavor,
        diagnostic: null,
        expected: reason,
        probe: "boundary-probe",
        pointer: "",
        evaluation: "boundary-evaluation",
        observed_digest: null,
        reason,
        fix: { kind: "agent", guidance: reason },
      },
    ],
    fixes: [
      {
        kind: fixer,
        plan:
          fixer === "you" || fixer === "airlock-pr"
            ? {
                kind: "action",
                fixer: fixer === "you" ? "person" : "airlock",
                action: "boundary-action",
                input: { explanation: reason },
              }
            : fixer === "agent"
              ? { kind: "agent", guidance: reason }
              : { kind: "not-fixable", reason },
      },
    ],
  };
}
function rule(
  id: string,
  statement: string,
  severity: Severity,
  fixer: Fixer,
  flavor: Flavor = "gap",
): RuleResult {
  return {
    id,
    severity,
    result: "fail",
    flavor,
    instances: [{ ...instance(statement, fixer, flavor), severity }],
  };
}
const pass: RuleResult = {
  id: "license-present",
  severity: "blocking",
  result: "pass",
  flavor: "passed",
  instances: [
    {
      ...instance("License file is present", "agent"),
      result: "pass",
      flavor: "passed",
      fixes: [],
    },
  ],
};
function repository(
  account: string,
  name: string,
  rules: RuleResult[],
  maturity: RepositoryReport["maturity"] = "building",
): RepositoryReport {
  return {
    repository: `${account}/${name}`,
    maturity,
    audited_commit: "c".repeat(40),
    repository_config: source(`${account}/${name}`, repoCommit),
    assignments: [
      { id: "maintained-repositories", matched: true, diagnostic: null },
    ],
    rules,
    warnings: [],
  };
}
const protectedBranch = rule(
  "default-branch-protection",
  "Protect the default branch",
  "blocking",
  "you",
);
protectedBranch.instances.push({
  ...instance("Require one approving review", "you"),
  source: "repository",
  config_commit: repoCommit,
  mode: "value",
  conditions: [
    {
      index: 0,
      result: "fail",
      flavor: "gap",
      diagnostic: null,
      expected: 1,
      probe: "boundary-probe",
      pointer: "/reviews",
      evaluation: "minimum",
      observed_digest: null,
      reason: "Too few reviews",
      fix: { kind: "not-fixable", reason: "Boundary example" },
    },
  ],
});
const primary = repository("example-org", "field-notes", [
  protectedBranch,
  rule(
    "readme-installation",
    "Explain how to install the application",
    "advisory",
    "airlock-pr",
  ),
  rule("contribution-guide", "Explain how to contribute", "advisory", "agent"),
  rule(
    "release-evidence",
    "Publish verifiable release evidence",
    "blocking",
    "not-fixable",
  ),
  {
    ...rule(
      "ownership-review",
      "Evaluate repository ownership",
      "blocking",
      "not-fixable",
      "not-evaluated",
    ),
  },
  pass,
]);
primary.warnings.push({
  rule: protectedBranch.id,
  code: "relaxation-without-reason",
  reason:
    "Repository configuration relaxes the review requirement without a reason.",
});
export const fixtureReports: OrganizationReport[] = [
  "example-org",
  "sample-team",
  "demo-group",
  "test-org",
].map((account, index) => ({
  account,
  organization_config: source(`${account}/.github`, orgCommit),
  observation: { value: "2026-10-22T00:00:00Z", provenance: "capture" },
  repositories:
    index === 0
      ? [
          repository(account, "trail-map", [pass], "stable"),
          primary,
          {
            ...repository(account, "weekend-sketches", []),
            assignments: [
              {
                id: "maintained-repositories",
                matched: false,
                diagnostic: null,
              },
            ],
          },
          repository(
            account,
            "garden-planner",
            [
              rule(
                "readme-overview",
                "Describe the application in the README",
                "advisory",
                "agent",
              ),
              pass,
            ],
            "released",
          ),
        ]
      : [
          repository(
            account,
            "weather-station",
            index === 1
              ? [
                  rule(
                    "readme-overview",
                    "Describe the application in the README",
                    "advisory",
                    "agent",
                  ),
                  pass,
                ]
              : [pass],
            "released",
          ),
        ],
  unassigned_repositories: index === 0 ? [`${account}/weekend-sketches`] : [],
}));
