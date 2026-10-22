// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/report.ts }
import {
  groupOrder,
  type RepositoryView,
  type ResultGroup,
  type ResultView,
} from "../shared/report.ts";

export function filterRepositories(
  repositories: RepositoryView[],
  search: string,
  fixer: "all" | ResultGroup,
): RepositoryView[] {
  return repositories.filter(
    (repo) =>
      repo.repository.toLowerCase().includes(search.toLowerCase()) &&
      (fixer === "all" ||
        repo.results.some(
          (result) =>
            result.rule.result === "fail" && result.groups.includes(fixer),
        )),
  );
}

export const resultFilters = [
  ["all", "All results"],
  ["fail", "Failures"],
  ["pass", "Passes"],
  ["not-evaluated", "Couldn't evaluate"],
  ["blocking", "Blocking failures"],
  ["advisory", "Advisory failures"],
] as const;
export type ResultFilter = (typeof resultFilters)[number][0];
export type ResultSort = "report" | "severity" | "rule";

export function partitionResults(
  results: ResultView[],
  filter: ResultFilter,
  sort: ResultSort,
) {
  const visible = results.filter(({ rule }) => {
    if (filter === "all") return true;
    if (filter === "fail" || filter === "pass") return rule.result === filter;
    if (filter === "not-evaluated") return rule.flavor === filter;
    return rule.result === "fail" && rule.severity === filter;
  });
  const severity = { blocking: 0, advisory: 1, none: 2 };
  if (sort !== "report") {
    visible.sort(
      (a, b) =>
        (sort === "severity"
          ? severity[a.rule.severity] - severity[b.rule.severity]
          : 0) || a.rule.id.localeCompare(b.rule.id),
    );
  }
  return {
    count: visible.length,
    groups: groupOrder.map((group) => ({
      group,
      results: visible.filter(
        (result) => result.rule.result === "fail" && result.groups[0] === group,
      ),
    })),
    passing: visible.filter((result) => result.rule.result === "pass"),
  };
}

export function observedRuleCatalog(repositories: RepositoryView[]) {
  const ids = [
    ...new Set(
      repositories.flatMap((repo) => repo.results.map(({ rule }) => rule.id)),
    ),
  ].sort();
  return ids.map((id) => ({
    id,
    observations: repositories
      .flatMap((repo) =>
        repo.results
          .filter(({ rule }) => rule.id === id)
          .map(({ rule }) => ({
            repository: repo.repository,
            maturity: repo.maturity,
            statement: rule.statement,
            severity: rule.severity,
          })),
      )
      .sort((a, b) => a.repository.localeCompare(b.repository)),
  }));
}

export function incompleteLabel(count: number): string {
  return `${count} ${count === 1 ? "result" : "results"} couldn't be evaluated`;
}
