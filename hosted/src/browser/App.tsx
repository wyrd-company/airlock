// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/report.ts }
import { useEffect, useReducer, useRef, useState, type ReactNode } from "react";
import {
  fixDescription,
  groupLabels,
  groupOrder,
  type ObservationTime,
  type RepositoryReport,
  type OrganizationSummary,
  type OrganizationView,
  type RepositoryView,
  type ResultGroup,
  type ResultView,
} from "../shared/report.ts";

import {
  filterRepositories,
  partitionResults,
  resultFilters,
  observedRuleCatalog,
  incompleteLabel,
  updateResultSelection,
  type ResultFilter,
  type ResultSort,
} from "./view.ts";

type Section = "repos" | "rules" | "assignments" | "pull-requests";
interface Route {
  organization?: string;
  section: Section;
  repository?: string;
}
export function readRoute(hash: string): Route {
  const parts = hash
    .replace(/^#\/?/, "")
    .split("/")
    .map((part) => {
      try {
        return decodeURIComponent(part);
      } catch {
        return "";
      }
    });
  if (!parts[0]) return { section: "repos" };
  const section =
    (["repos", "rules", "assignments", "pull-requests"] as const).find(
      (section) => section === parts[1],
    ) ?? "repos";
  return {
    organization: parts[0],
    section,
    repository: section === "repos" ? parts[2] || undefined : undefined,
  };
}
function href(
  organization: string,
  section: Section = "repos",
  repository?: string,
): string {
  return `#/${encodeURIComponent(organization)}/${section}${repository ? `/${encodeURIComponent(repository)}` : ""}`;
}
function useHashRoute(): Route {
  const [route, setRoute] = useState(() => readRoute(location.hash));
  useEffect(() => {
    const update = () => setRoute(readRoute(location.hash));
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return route;
}
async function api<T>(path: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal });
  if (!response.ok)
    throw new Error(
      response.status === 503
        ? "This service is not connected yet."
        : "The report could not be loaded.",
    );
  return response.json() as Promise<T>;
}
function useReport<T>(path: string): { data?: T; error?: string } {
  const [state, setState] = useState<{
    path: string;
    data?: T;
    error?: string;
  }>({ path });
  useEffect(() => {
    const abort = new AbortController();
    api<T>(path, abort.signal)
      .then((data) => setState({ path, data }))
      .catch((error: Error) => {
        if (!abort.signal.aborted) setState({ path, error: error.message });
      });
    return () => abort.abort();
  }, [path]);
  return state.path === path ? state : {};
}
function Arrow() {
  return <span aria-hidden="true">↗</span>;
}
function Count({
  value,
  tone,
  label,
}: {
  value: number;
  tone: string;
  label: string;
}) {
  return (
    <span className={`count ${tone}`} aria-label={`${value} ${label}`}>
      {value}
      <span className="count-label">{label}</span>
    </span>
  );
}
function Tag({ children, tone = "" }: { children: ReactNode; tone?: string }) {
  return <span className={`tag ${tone}`}>{children}</span>;
}
function Commit({ value }: { value: string }) {
  return <code title={value}>{value.slice(0, 8)}</code>;
}
export function App() {
  const route = useHashRoute();
  const { data, error } = useReport<{ organizations: OrganizationSummary[] }>(
    "/api/organizations",
  );
  return (
    <div className="shell">
      <aside className="sidebar">
        <a href="#/" className="brand" aria-label="Airlock overview">
          <span className="brand-mark" aria-hidden="true">
            a<span>↗</span>
          </span>
          <span>
            AIRLOCK<small>REPOSITORY CONFORMANCE</small>
          </span>
        </a>
        <div className="workspace-label">WORKSPACE</div>
        <a
          href="#/"
          className={`overview-link ${!route.organization ? "active" : ""}`}
        >
          <span aria-hidden="true">⊞</span> Overview
        </a>
        <div className="workspace-label">
          ORGANIZATIONS <span>{data?.organizations.length ?? "—"}</span>
        </div>
        <nav aria-label="Organizations">
          {data?.organizations.map((org, index) => (
            <a
              className={`org-link ${route.organization === org.account ? "active" : ""}`}
              href={href(org.account)}
              key={org.account}
            >
              <span className="org-avatar">
                {String(index + 1).padStart(2, "0")}
              </span>
              {org.account}
              <span
                className={`nav-dot ${org.blocking ? "red" : org.incomplete ? "amber" : "green"}`}
              />
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="safe-label">
            <span className="nav-dot green" /> Read-only preview
          </div>
          <p>No GitHub account connected</p>
          <a href="https://github.com" target="_blank" rel="noreferrer">
            GitHub <Arrow />
          </a>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span>
            Workspace <span aria-hidden="true">/</span>{" "}
            {route.organization ?? "Overview"}
          </span>
          <span className="preview-pill">LOCAL PREVIEW · SAMPLE DATA</span>
        </header>
        <main id="main">
          {error ? (
            <ErrorState message={error} />
          ) : !data ? (
            <p className="loading" role="status">
              Loading conformance reports…
            </p>
          ) : route.organization ? (
            <Organization key={route.organization} route={route} />
          ) : (
            <Overview summaries={data.organizations} />
          )}
        </main>
        <footer>
          <span>AIRLOCK</span>
          <span>See the gap. Know the next step.</span>
          <span>Sample reports · No live changes</span>
        </footer>
      </div>
    </div>
  );
}
function ErrorState({ message }: { message: string }) {
  return (
    <div className="empty" role="alert">
      <h2>Report unavailable</h2>
      <p>{message}</p>
      <a href="#/">Return to overview</a>
    </div>
  );
}
function Overview({ summaries }: { summaries: OrganizationSummary[] }) {
  const blockers = summaries.reduce((total, org) => total + org.blocking, 0);
  return (
    <>
      <div className="eyebrow">YOUR WORKSPACE / OVERVIEW</div>
      <div className="page-heading">
        <div>
          <h1>
            A clear view of
            <br />
            what needs attention.
          </h1>
          <p>Every organization, at a glance. Choose one to get to work.</p>
        </div>
        <div className="overview-total">
          <strong>{String(blockers).padStart(2, "0")}</strong>
          <span>
            blocking results
            <br />
            across your workspace
          </span>
        </div>
      </div>
      <div className="section-heading">
        <h2>
          Organizations <span>{summaries.length}</span>
        </h2>
        <span>Open an organization to view its repositories</span>
      </div>
      <div className="org-grid">
        {summaries.map((org, index) => (
          <a className="org-card" href={href(org.account)} key={org.account}>
            <div className="card-top">
              <span className="card-index">
                ORG / {String(index + 1).padStart(2, "0")}
              </span>
              <Arrow />
            </div>
            <h3>{org.account}</h3>
            <p>
              {org.repositories} assigned{" "}
              {org.repositories === 1 ? "repository" : "repositories"}
              {org.unassigned ? ` · ${org.unassigned} unassigned` : ""}
              {org.unknownAssignments
                ? ` · ${org.unknownAssignments} assignment unknown`
                : ""}
            </p>
            <div className="card-stats">
              <Count value={org.blocking} tone="blocking" label="blocking" />
              <Count value={org.advisory} tone="advisory" label="advisory" />
            </div>
            <div className="card-status">
              <span
                className={`nav-dot ${org.blocking || org.incomplete ? "red" : "green"}`}
              />
              {org.incomplete
                ? incompleteLabel(org.incomplete)
                : org.blocking
                  ? "Settings and files need attention"
                  : "No blocking results"}
            </div>
          </a>
        ))}
      </div>
      <div className="overview-note">
        <span aria-hidden="true">↳</span>
        <p>
          Conformance starts with context.
          <br />
          <span>
            Rules, assignments and fixes stay inside the organization you
            select.
          </span>
        </p>
      </div>
    </>
  );
}
function Organization({ route }: { route: Route }) {
  const { data, error } = useReport<{ organization: OrganizationView }>(
    `/api/organizations/${encodeURIComponent(route.organization!)}`,
  );
  const [filter, setFilter] = useState<"all" | ResultGroup>("all");
  const [search, setSearch] = useState("");
  const [proposal, setProposal] = useState(false);
  if (error) return <ErrorState message={error} />;
  if (!data)
    return (
      <p className="loading" role="status">
        Loading organization…
      </p>
    );
  const org = data.organization;
  const repo = route.repository
    ? org.repositories.find(
        (repo) => repo.repository.split("/")[1] === route.repository,
      )
    : undefined;
  if (route.repository && !repo)
    return (
      <ErrorState message="This repository is not in this organization's report." />
    );
  return (
    <>
      <div className="eyebrow">
        <a href="#/">WORKSPACE</a> / {org.account.toUpperCase()}
      </div>
      <div className="page-heading compact">
        <div>
          <h1>
            {org.account}
            <span className="heading-dot">.</span>
          </h1>
          <p>
            {
              org.repositories.filter((repo) =>
                repo.assignments.some((a) => a.matched === true),
              ).length
            }{" "}
            assigned repositories
            {org.repositories.some((repo) => repo.assignmentUnknown)
              ? " · Assignment unknown — incomplete"
              : ""}{" "}
            · <Observation value={org.observation} />
          </p>
        </div>
        <div className="context-status">
          <span className="nav-dot green" /> Organization context
        </div>
      </div>
      <nav className="tabs" aria-label="Organization sections">
        {(["repos", "rules", "assignments", "pull-requests"] as const).map(
          (section) => (
            <a
              key={section}
              href={href(org.account, section)}
              aria-current={route.section === section ? "page" : undefined}
            >
              {
                {
                  repos: "Repos",
                  rules: "Rules",
                  assignments: "Assignments",
                  "pull-requests": "Pull requests",
                }[section]
              }
            </a>
          ),
        )}
      </nav>
      {repo ? (
        <Repository key={repo.repository} org={org} repo={repo} />
      ) : route.section === "repos" ? (
        <>
          <div className="metric-strip">
            <div>
              <strong>
                {org.repositories.reduce((n, repo) => n + repo.blocking, 0)}
              </strong>
              <span>Blocking results</span>
            </div>
            <div>
              <strong>
                {org.repositories.reduce((n, repo) => n + repo.advisory, 0)}
              </strong>
              <span>Advisory results</span>
            </div>
            <div>
              <strong>
                {org.repositories.reduce((n, repo) => n + repo.incomplete, 0)}
              </strong>
              <span>Couldn't evaluate</span>
            </div>
            <div>
              <strong>{org.unassigned.length}</strong>
              <span>Unassigned repositories</span>
            </div>
          </div>
          <div className="section-heading">
            <h2>
              Repositories <span>{org.repositories.length}</span>
            </h2>
            <span>Worst first</span>
          </div>
          <div className="toolbar">
            <div
              className="filter-tabs"
              role="group"
              aria-label="Work queue filter"
            >
              <button
                aria-pressed={filter === "all"}
                onClick={() => setFilter("all")}
              >
                All repos
              </button>
              {groupOrder.map((group) => (
                <button
                  key={group}
                  aria-pressed={filter === group}
                  onClick={() => setFilter(group)}
                >
                  {groupLabels[group]}
                </button>
              ))}
            </div>
            <input
              aria-label="Find a repository"
              type="search"
              placeholder="Find a repository…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <RepositoryTable
            account={org.account}
            repositories={org.repositories}
            search={search}
            filter={filter}
          />
          <UnassignedRepositories repositories={org.unassigned} />
        </>
      ) : route.section === "rules" ? (
        <RuleCatalog org={org} onProposal={() => setProposal(true)} />
      ) : route.section === "assignments" ? (
        <Assignments org={org} onProposal={() => setProposal(true)} />
      ) : (
        <div className="empty">
          <span className="empty-mark" aria-hidden="true">
            ↗
          </span>
          <h2>Changes arrive as pull requests.</h2>
          <p>Connect GitHub to see proposals for {org.account}.</p>
          <p>Airlock proposes changes. It never merges them.</p>
        </div>
      )}
      {proposal && (
        <ProposalDialog organization={org} onClose={() => setProposal(false)} />
      )}
    </>
  );
}
export function RepositoryTable({
  account,
  repositories,
  search,
  filter,
}: {
  account: string;
  repositories: RepositoryView[];
  search: string;
  filter: "all" | ResultGroup;
}) {
  const visible = filterRepositories(repositories, search, filter);
  return (
    <>
      <div className="repo-table">
        <div className="repo-table-head">
          <span>REPOSITORY</span>
          <span>MATURITY</span>
          <span>RESULTS</span>
          <span>ASSIGNMENT</span>
          <span />
        </div>
        {visible.map((repo) => (
          <a
            className="repo-row"
            key={repo.repository}
            href={href(account, "repos", repo.repository.split("/")[1])}
          >
            <div className="repo-name">
              <span
                className={`repo-indicator ${repo.blocking ? "red" : repo.advisory || repo.incomplete ? "amber" : "green"}`}
              />
              <strong>{repo.repository.split("/")[1]}</strong>
              <small>
                {repo.assignmentUnknown
                  ? "Assignment unknown — incomplete"
                  : repo.incomplete
                    ? incompleteLabel(repo.incomplete)
                    : repo.blocking + repo.advisory
                      ? "Has open gaps"
                      : "All evaluated rules pass"}
              </small>
            </div>
            <span>
              <Tag>{repo.maturity}</Tag>
            </span>
            <div className="row-counts">
              <Count value={repo.blocking} tone="blocking" label="blocking" />
              <Count value={repo.advisory} tone="advisory" label="advisory" />
            </div>
            <span className="assignment-name">
              {repo.assignments
                .map(
                  (a) =>
                    `${a.id}: ${a.matched === true ? "assigned" : a.matched === false ? "not matched" : "unknown"}`,
                )
                .join(", ")}
            </span>
            <Arrow />
          </a>
        ))}
      </div>
      {visible.length === 0 && (
        <div className="empty">No repositories match this view.</div>
      )}
    </>
  );
}

function Repository({
  org,
  repo,
}: {
  org: OrganizationView;
  repo: RepositoryView;
}) {
  const [{ selected, filter: resultFilter }, updateSelection] = useReducer(
    updateResultSelection,
    { filter: "all", selected: new Set<string>() },
  );
  const [review, setReview] = useState(false);
  const [resultSort, setResultSort] = useState<ResultSort>("report");
  const failing = repo.results.filter(
    (result) => result.rule.result === "fail",
  );
  function toggle(id: string) {
    updateSelection({ type: "toggle", id });
  }
  return (
    <div className="repository-detail" key={repo.repository}>
      <a className="back-link" href={href(org.account)}>
        ← All repositories
      </a>
      <div className="repo-heading">
        <div>
          <div className="eyebrow">{org.account} / REPOSITORY</div>
          <h2>{repo.repository.split("/")[1]}</h2>
          <div className="repo-meta">
            <Tag>{repo.maturity}</Tag>
            <span>
              {repo.assignments
                .map(
                  (a) =>
                    `${a.id}: ${a.matched === true ? "assigned" : a.matched === false ? "not matched" : "unknown"}`,
                )
                .join(", ")}
            </span>
          </div>
        </div>
        <div className="row-counts">
          <Count value={repo.blocking} tone="blocking" label="blocking" />
          <Count value={repo.advisory} tone="advisory" label="advisory" />
        </div>
      </div>
      <div className="provenance">
        <span>
          AUDITED REVISION <Commit value={repo.audited_commit} />
        </span>
        <span>CONFIG COMMITS</span>
        <span>
          Organization <Commit value={org.organizationConfig.commit} />{" "}
          {org.organizationConfig.repository}:{org.organizationConfig.path}
        </span>
        <span>
          Repository{" "}
          {repo.repository_config ? (
            <>
              <Commit value={repo.repository_config.commit} />{" "}
              {repo.repository_config.repository}:{repo.repository_config.path}
            </>
          ) : (
            "No repository configuration"
          )}
        </span>
      </div>
      <div className="toolbar result-controls">
        <label>
          Filter results{" "}
          <select
            aria-label="Filter results"
            value={resultFilter}
            onChange={(event) => {
              updateSelection({
                type: "filter",
                filter: event.target.value as ResultFilter,
              });
            }}
          >
            {resultFilters.map(([value, label]) => (
              <option value={value} key={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort results{" "}
          <select
            aria-label="Sort results"
            value={resultSort}
            onChange={(event) =>
              setResultSort(event.target.value as ResultSort)
            }
          >
            <option value="report">Report order</option>
            <option value="severity">Severity</option>
            <option value="rule">Rule ID</option>
          </select>
        </label>
      </div>
      <RepositoryResults
        results={repo.results}
        filter={resultFilter}
        sort={resultSort}
        selected={selected}
        onToggle={toggle}
        onReview={() => setReview(true)}
      />
      {review && (
        <Modal title="Review settings fixes" onClose={() => setReview(false)}>
          <p>
            Selected changes for <strong>{repo.repository}</strong>.
          </p>
          <ul className="review-list">
            {failing
              .filter((result) => selected.has(result.rule.id))
              .map((result) => (
                <li key={result.rule.id}>
                  <strong>{result.rule.id}</strong>
                  {result.rule.instances
                    .filter((instance) => instance.result === "fail")
                    .map((instance, index) => (
                      <p key={index}>{instance.reason}</p>
                    ))}
                </li>
              ))}
          </ul>
          <p className="notice">
            Settings fixes are unavailable in this preview. Applying a reviewed
            batch requires GitHub authorization and a fresh passkey confirmation
            for its exact changes.
          </p>
          <button className="primary-button" disabled>
            Authorize with GitHub
          </button>
        </Modal>
      )}
    </div>
  );
}
export function RepositoryResults({
  results,
  filter,
  sort,
  selected,
  onToggle,
  onReview,
}: {
  results: ResultView[];
  filter: ResultFilter;
  sort: ResultSort;
  selected: Set<string>;
  onToggle: (id: string) => void;
  onReview: () => void;
}) {
  const partition = partitionResults(results, filter, sort);
  return (
    <>
      <p className="results-summary" role="status">
        Showing {partition.count} of {results.length} results
      </p>
      {partition.groups.map(({ group, results }) => {
        if (!results.length) return null;
        return (
          <section
            className="result-group"
            data-result-group={group}
            key={group}
          >
            <div className="section-heading">
              <h3>
                {groupLabels[group]} <span>{results.length}</span>
              </h3>
              {group === "you" ? (
                <button
                  className="primary-button"
                  disabled={selected.size === 0}
                  onClick={onReview}
                >
                  Review fixes{" "}
                  {selected.size > 0 && <span>{selected.size}</span>}{" "}
                  <span aria-hidden="true">→</span>
                </button>
              ) : (
                <span>
                  {group === "airlock-pr" || group === "agent"
                    ? "File changes through a pull request"
                    : group === "not-evaluated"
                      ? "An evaluation needs attention"
                      : "No automatic fix"}
                </span>
              )}
            </div>
            {results.map((result) => (
              <RuleRow
                key={result.rule.id}
                result={result}
                selectable={group === "you"}
                selected={selected.has(result.rule.id)}
                toggle={() => onToggle(result.rule.id)}
              />
            ))}
          </section>
        );
      })}
      <details className="passes">
        <summary>
          <span className="nav-dot green" /> Passing rules{" "}
          <span>{partition.passing.length}</span>
        </summary>
        {partition.passing.map((result) => (
          <RuleRow key={result.rule.id} result={result} />
        ))}
      </details>
    </>
  );
}

export function RuleRow({
  result,
  selectable = false,
  selected = false,
  toggle,
}: {
  result: ResultView;
  selectable?: boolean;
  selected?: boolean;
  toggle?: () => void;
}) {
  const { rule } = result;
  return (
    <div className={`rule-row ${selected ? "selected" : ""}`}>
      {selectable && (
        <input
          className="rule-checkbox"
          type="checkbox"
          aria-label={`Select ${rule.id}`}
          checked={selected}
          onChange={toggle}
        />
      )}
      <details>
        <summary>
          <div className="rule-title">
            <strong>{rule.id}</strong>
            <div>
              {rule.instances.length > 1 && <span>Org + repo · AND</span>}
              {result.groups.length > 1 && (
                <span>
                  {result.groups.map((group) => groupLabels[group]).join(" + ")}
                </span>
              )}
            </div>
          </div>
          <div className="rule-badges">
            {result.warnings.length > 0 && (
              <Tag tone="warning">Rule warning</Tag>
            )}
            <Tag
              tone={
                rule.result === "pass"
                  ? "passed"
                  : rule.flavor === "not-evaluated"
                    ? "unknown"
                    : rule.severity
              }
            >
              {rule.flavor === "not-evaluated"
                ? "Couldn't evaluate"
                : rule.result === "pass"
                  ? rule.flavor
                  : rule.severity}
            </Tag>
            <span className="disclosure" aria-hidden="true">
              +
            </span>
          </div>
        </summary>
        <div className="rule-detail">
          <p>
            Engine aggregate: {rule.result} · {rule.flavor} · {rule.severity}
          </p>
          {result.warnings.map((warning, index) => (
            <p className="notice" key={index}>
              <code>{warning.code}</code> · {warning.reason}
            </p>
          ))}
          <div className="instance-grid">
            {rule.instances.map((instance, index) => (
              <div className="instance" key={index}>
                <div className="instance-heading">
                  <h4>
                    {instance.source === "organization"
                      ? "Organization requirement"
                      : "Repository requirement"}
                  </h4>
                  <Tag>{instance.mode}</Tag>
                </div>
                <div className="instance-commit">
                  Config <Commit value={instance.config_commit} />
                  <span>{instance.flavor}</span>
                </div>
                <p>{instance.statement ?? "Statement unavailable"}</p>
                <p>
                  Result {instance.result} · Severity {instance.severity}
                </p>
                <p>Reason: {instance.reason ?? "unavailable"}</p>
                <p>
                  Relaxation reason:{" "}
                  {instance.relaxation_reason ?? "unavailable"}
                </p>
                {instance.diagnostic && (
                  <p className="notice">
                    <code>{instance.diagnostic.code}</code> ·{" "}
                    {instance.diagnostic.reason}
                  </p>
                )}
                <dl>
                  {instance.conditions.map((condition, index) => (
                    <div key={index}>
                      <dt>
                        Condition {condition.index} · {condition.probe}{" "}
                        {condition.pointer} · {condition.evaluation}
                      </dt>
                      <dd>
                        Result {condition.result} · {condition.flavor}
                      </dd>
                      <dd>
                        <span>Expected JSON</span>
                        <code>{JSON.stringify(condition.expected)}</code>
                      </dd>
                      <dd>
                        <span>Observed digest</span>
                        <code>
                          {condition.observed_digest ?? "Unavailable"}
                        </code>
                      </dd>
                      <dd>{condition.reason}</dd>
                      {condition.diagnostic && (
                        <dd>
                          {condition.diagnostic.code} ·{" "}
                          {condition.diagnostic.reason}
                        </dd>
                      )}
                      <dd>
                        Fix plan: <code>{JSON.stringify(condition.fix)}</code>
                      </dd>
                    </div>
                  ))}
                </dl>
                {instance.fixes.map((fix, index) => (
                  <div className="fix-detail" key={index}>
                    <span>{groupLabels[fix.kind]} · Fix plan</span>
                    <p>{fixDescription(fix.plan)}</p>
                    <pre>{JSON.stringify(fix.plan, null, 2)}</pre>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}
export function RuleCatalog({
  org,
  onProposal,
}: {
  org: OrganizationView;
  onProposal: () => void;
}) {
  const rules = observedRuleCatalog(org.repositories);
  return (
    <>
      <div className="section-heading">
        <h2>
          Rules <span>{rules.length}</span>
        </h2>
        <button className="secondary-button" onClick={onProposal}>
          Propose config edit <Arrow />
        </button>
      </div>
      <p className="section-description">
        Observed requirements by repository inside {org.account}. Statements and
        effective severity belong to each repository. Source config:{" "}
        <Commit value={org.organizationConfig.commit} />
      </p>
      {rules.map(({ id, observations }) => (
        <details className="catalog-entry" key={id}>
          <summary>
            <code>{id}</code>
            <span>
              {observations.length}{" "}
              {observations.length === 1 ? "repository" : "repositories"}
            </span>
            <span aria-hidden="true">+</span>
          </summary>
          {observations.map((observation) => (
            <div className="catalog-observation" key={observation.repository}>
              <a
                href={href(
                  org.account,
                  "repos",
                  observation.repository.split("/")[1],
                )}
              >
                {observation.repository.split("/")[1]} <Arrow />
              </a>
              <Tag>{observation.maturity}</Tag>
              <Tag tone={observation.severity}>{observation.severity}</Tag>
              {observation.statements.map((instance, index) => (
                <p key={index}>
                  {instance.source} ·{" "}
                  {instance.statement ?? "Statement unavailable"} ·{" "}
                  {instance.severity} ·{" "}
                  <Commit value={instance.config_commit} />
                </p>
              ))}
            </div>
          ))}
        </details>
      ))}
    </>
  );
}
export function Assignments({
  org,
  onProposal,
}: {
  org: OrganizationView;
  onProposal: () => void;
}) {
  const assignments = [
    ...new Set(
      [...org.repositories, ...org.unassigned].flatMap((repo) =>
        repo.assignments.map((a) => a.id),
      ),
    ),
  ];
  return (
    <>
      <div className="section-heading">
        <h2>
          Assignments <span>{assignments.length}</span>
        </h2>
        <button className="secondary-button" onClick={onProposal}>
          Propose config edit <Arrow />
        </button>
      </div>
      <p className="section-description">
        Organization configuration{" "}
        <Commit value={org.organizationConfig.commit} />
      </p>
      {assignments.map((assignment) => (
        <section className="assignment-card" key={assignment}>
          <h3>{assignment}</h3>
          <p>Assignment observations: assigned, not matched, or unknown</p>
          {[...org.repositories, ...org.unassigned].flatMap((repo) =>
            repo.assignments
              .filter((a) => a.id === assignment)
              .map((a) => (
                <div key={repo.repository}>
                  {repo.repository} ·{" "}
                  {a.matched === true
                    ? "Assigned"
                    : a.matched === false
                      ? "Not matched"
                      : "Unknown — incomplete"}
                  {a.diagnostic && (
                    <p>
                      {a.diagnostic.code} · {a.diagnostic.reason}
                    </p>
                  )}
                </div>
              )),
          )}
        </section>
      ))}
    </>
  );
}
function ProposalDialog({
  organization,
  onClose,
}: {
  organization: OrganizationView;
  onClose: () => void;
}) {
  return (
    <Modal title="Propose a config edit" onClose={onClose}>
      <p>
        Draft a proposed change for <strong>{organization.account}</strong> at
        config <Commit value={organization.organizationConfig.commit} />.
      </p>
      <label className="draft-label" htmlFor="proposal">
        Proposed change
      </label>
      <textarea
        id="proposal"
        rows={6}
        placeholder="Describe the assignment or rule configuration to change…"
      />
      <p className="notice">
        Configuration pull requests are unavailable in this preview. Your draft
        stays in this dialog. Airlock never merges proposals.
      </p>
      <button className="primary-button" disabled>
        Open pull request
      </button>
    </Modal>
  );
}
function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog ref={ref} onCancel={onClose} aria-labelledby="dialog-title">
      <div className="dialog-header">
        <span className="eyebrow">
          {title.includes("config")
            ? "CONFIGURATION PROPOSAL"
            : "REVIEWED BATCH"}
        </span>
        <button onClick={onClose} aria-label="Close dialog">
          ×
        </button>
      </div>
      <h2 id="dialog-title">{title}</h2>
      {children}
    </dialog>
  );
}

export function Observation({ value }: { value: ObservationTime }) {
  return value.provenance === "unavailable" ? (
    <span>Audit time unavailable</span>
  ) : (
    <span>
      {value.provenance === "capture" ? "Capture time" : "Audit time"}{" "}
      <time dateTime={value.value}>{new Date(value.value).toUTCString()}</time>
    </span>
  );
}
export function UnassignedRepositories({
  repositories,
}: {
  repositories: RepositoryReport[];
}) {
  if (!repositories.length) return null;
  return (
    <section className="unassigned">
      <h2>
        Unassigned <span>{repositories.length}</span>
      </h2>
      <p>These repositories have no rule assignment. They are not findings.</p>
      {repositories.map((repo) => (
        <details key={repo.repository}>
          <summary>
            {repo.repository.split("/")[1]} <Tag>Unassigned</Tag>
          </summary>
          <p>
            {repo.repository} · {repo.maturity} · Audited revision{" "}
            <Commit value={repo.audited_commit} />
          </p>
          <p>
            {repo.repository_config
              ? `${repo.repository_config.repository}:${repo.repository_config.path}@${repo.repository_config.commit}`
              : "No repository configuration"}
          </p>
          {repo.assignments.map((a) => (
            <p key={a.id}>
              {a.id}:{" "}
              {a.matched === true
                ? "assigned"
                : a.matched === false
                  ? "not matched"
                  : "unknown"}
              {a.diagnostic
                ? ` · ${a.diagnostic.code}: ${a.diagnostic.reason}`
                : ""}
            </p>
          ))}
        </details>
      ))}
    </section>
  );
}
