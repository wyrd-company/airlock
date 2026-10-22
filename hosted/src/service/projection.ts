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
  const repositories: RepositoryView[] = report.repositories
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
          warnings: repo.warnings
            .filter((warning) => warning.rule_id === rule.id)
            .map((warning) => warning.message),
        };
      });
      return {
        ...repo,
        results,
        blocking: repo.rules.filter(
          (rule) => rule.result === "fail" && rule.severity === "blocking",
        ).length,
        advisory: repo.rules.filter(
          (rule) => rule.result === "fail" && rule.severity === "advisory",
        ).length,
        incomplete: repo.rules.filter((rule) => rule.flavor === "not-evaluated")
          .length,
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
    observedAt: report.observed_at,
    repositories,
    unassigned: report.unassigned_repositories,
  };
}
export function summarize(view: OrganizationView): OrganizationSummary {
  return {
    account: view.account,
    repositories: view.repositories.length,
    unassigned: view.unassigned.length,
    blocking: view.repositories.reduce((sum, repo) => sum + repo.blocking, 0),
    advisory: view.repositories.reduce((sum, repo) => sum + repo.advisory, 0),
    incomplete: view.repositories.reduce(
      (sum, repo) => sum + repo.incomplete,
      0,
    ),
    observedAt: view.observedAt,
  };
}
