// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/report.ts }
import {
  groupOrder,
  type OrganizationReport,
  type OrganizationSummary,
  type OrganizationView,
  type RepositoryView,
  type ResultView,
} from "../shared/report.ts";

// The engine owns AND/severity/fix derivation. The adapter only projects its result.
export function projectOrganization(
  report: OrganizationReport,
): OrganizationView {
  const unassignedIds = new Set(report.unassigned_repositories);
  const repositories: RepositoryView[] = report.repositories
    .filter((repo) => !unassignedIds.has(repo.repository)) // Explicit unassigned separation.
    .map((repo) => {
      const results: ResultView[] = repo.rules.map((rule) => {
        const fixes = rule.instances
          .filter((instance) => instance.result === "fail")
          .flatMap((instance) => instance.fixes);
        const groups =
          rule.flavor === "not-evaluated"
            ? ["not-evaluated" as const]
            : groupOrder.filter(
                (group) =>
                  group !== "not-evaluated" &&
                  fixes.some((fix) => fix.kind === group),
              );
        return {
          rule,
          fixes,
          groups:
            rule.result === "fail" && groups.length === 0
              ? ["not-fixable"]
              : groups,
          warnings: repo.warnings.filter((warning) => warning.rule === rule.id),
        };
      });
      const assignmentUnknown = repo.assignments.some(
        (assignment) => assignment.matched === null,
      );
      return {
        ...repo,
        assignmentUnknown,
        results,
        blocking: repo.rules.filter(
          (rule) => rule.result === "fail" && rule.severity === "blocking",
        ).length,
        advisory: repo.rules.filter(
          (rule) => rule.result === "fail" && rule.severity === "advisory",
        ).length,
        incomplete:
          repo.rules.filter((rule) => rule.flavor === "not-evaluated").length +
          (assignmentUnknown ? 1 : 0), // Unknown assignment is incomplete.
      };
    })
    .sort(
      (a, b) =>
        b.blocking - a.blocking ||
        b.advisory - a.advisory ||
        b.incomplete - a.incomplete ||
        a.repository.localeCompare(b.repository),
    );
  return {
    account: report.account,
    organizationConfig: report.organization_config,
    observation: report.observation,
    repositories,
    unassigned: [...unassignedIds].flatMap((name) =>
      report.repositories
        .filter((repo) => repo.repository === name)
        .slice(0, 1),
    ),
  };
}
export function summarize(view: OrganizationView): OrganizationSummary {
  return {
    account: view.account,
    repositories: view.repositories.filter((repo) =>
      repo.assignments.some((a) => a.matched === true),
    ).length,
    unknownAssignments: view.repositories.filter(
      (repo) => repo.assignmentUnknown,
    ).length,
    unassigned: view.unassigned.length,
    blocking: view.repositories.reduce((sum, repo) => sum + repo.blocking, 0),
    advisory: view.repositories.reduce((sum, repo) => sum + repo.advisory, 0),
    incomplete: view.repositories.reduce(
      (sum, repo) => sum + repo.incomplete,
      0,
    ),
    observation: view.observation,
  };
}
