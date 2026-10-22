// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/report.ts }
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
    result: "fail",
    flavor,
    reason,
    conditions: [
      {
        label: "Requirement",
        expected: reason,
        observed: flavor === "not-evaluated" ? null : "Requirement is not met",
      },
    ],
    fixes: [
      {
        kind: fixer,
        origin: fixer === "not-fixable" ? "block" : "derived",
        description: reason,
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
    statement,
    severity,
    result: "fail",
    flavor,
    instances: [instance(statement, fixer, flavor)],
  };
}
const pass: RuleResult = {
  id: "license-present",
  statement: "A license is declared",
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
    repository_config: source(`${account}/${name}`, repoCommit),
    assignments: ["maintained-repositories"],
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
    { label: "Approving reviews", expected: "At least 1", observed: "0" },
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
    detail_code: "invalid-rule",
  },
  pass,
]);
primary.warnings.push({
  rule_id: protectedBranch.id,
  code: "relaxation-without-reason",
  message:
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
  observed_at: "2026-10-22T00:00:00Z",
  repositories:
    index === 0
      ? [
          repository(account, "trail-map", [pass], "stable"),
          primary,
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
