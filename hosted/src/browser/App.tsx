// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/report.ts }
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  groupLabels,
  groupOrder,
  type OrganizationSummary,
  type OrganizationView,
  type RepositoryView,
  type ResultGroup,
  type ResultView,
} from "../shared/report.ts";

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
              <span className={`nav-dot ${org.blocking ? "red" : "green"}`} />
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
                ? `${org.incomplete} result couldn't be evaluated`
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
            {org.repositories.length} assigned repositories · Observed{" "}
            <time dateTime={org.observedAt}>
              {new Date(org.observedAt).toUTCString()}
            </time>
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
          <div className="repo-table">
            <div className="repo-table-head">
              <span>REPOSITORY</span>
              <span>MATURITY</span>
              <span>RESULTS</span>
              <span>ASSIGNMENT</span>
              <span />
            </div>
            {org.repositories
              .filter(
                (repo) =>
                  repo.repository
                    .toLowerCase()
                    .includes(search.toLowerCase()) &&
                  (filter === "all" ||
                    repo.results.some(
                      (result) =>
                        result.rule.result === "fail" &&
                        result.groups.includes(filter),
                    )),
              )
              .map((repo) => (
                <a
                  className="repo-row"
                  key={repo.repository}
                  href={href(
                    org.account,
                    "repos",
                    repo.repository.split("/")[1],
                  )}
                >
                  <div className="repo-name">
                    <span
                      className={`repo-indicator ${repo.blocking ? "red" : repo.advisory ? "amber" : "green"}`}
                    />
                    <strong>{repo.repository.split("/")[1]}</strong>
                    <small>
                      {repo.incomplete
                        ? `${repo.incomplete} result couldn't be evaluated`
                        : repo.blocking + repo.advisory
                          ? "Has open gaps"
                          : "All evaluated rules pass"}
                    </small>
                  </div>
                  <span>
                    <Tag>{repo.maturity}</Tag>
                  </span>
                  <div className="row-counts">
                    <Count
                      value={repo.blocking}
                      tone="blocking"
                      label="blocking"
                    />
                    <Count
                      value={repo.advisory}
                      tone="advisory"
                      label="advisory"
                    />
                  </div>
                  <span className="assignment-name">
                    {repo.assignments.join(", ")}
                  </span>
                  <Arrow />
                </a>
              ))}
          </div>
          {!org.repositories.some(
            (repo) =>
              repo.repository.toLowerCase().includes(search.toLowerCase()) &&
              (filter === "all" ||
                repo.results.some(
                  (result) =>
                    result.rule.result === "fail" &&
                    result.groups.includes(filter),
                )),
          ) && <div className="empty">No repositories match this view.</div>}
          {org.unassigned.length > 0 && (
            <section className="unassigned">
              <h2>
                Unassigned <span>{org.unassigned.length}</span>
              </h2>
              <p>
                These repositories have no rule assignment. They are not
                findings.
              </p>
              {org.unassigned.map((name) => (
                <div key={name}>
                  <span aria-hidden="true">↳</span>
                  {name.split("/")[1]}
                  <Tag>Unassigned</Tag>
                </div>
              ))}
            </section>
          )}
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
function Repository({
  org,
  repo,
}: {
  org: OrganizationView;
  repo: RepositoryView;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [review, setReview] = useState(false);
  const failing = repo.results.filter(
    (result) => result.rule.result === "fail",
  );
  const passing = repo.results.filter(
    (result) => result.rule.result === "pass",
  );
  function toggle(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
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
            <span>{repo.assignments.join(", ")}</span>
          </div>
        </div>
        <div className="row-counts">
          <Count value={repo.blocking} tone="blocking" label="blocking" />
          <Count value={repo.advisory} tone="advisory" label="advisory" />
        </div>
      </div>
      <div className="provenance">
        <span>CONFIG COMMITS</span>
        <span>
          Organization <Commit value={org.organizationConfig.commit} />
        </span>
        <span>
          Repository{" "}
          {repo.repository_config ? (
            <Commit value={repo.repository_config.commit} />
          ) : (
            "No repository configuration"
          )}
        </span>
      </div>
      {groupOrder.map((group) => {
        const results = failing.filter((result) => result.groups[0] === group);
        if (!results.length) return null;
        return (
          <section className="result-group" key={group}>
            <div className="section-heading">
              <h3>
                {groupLabels[group]} <span>{results.length}</span>
              </h3>
              {group === "you" ? (
                <button
                  className="primary-button"
                  disabled={selected.size === 0}
                  onClick={() => setReview(true)}
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
                toggle={() => toggle(result.rule.id)}
              />
            ))}
          </section>
        );
      })}
      <details className="passes">
        <summary>
          <span className="nav-dot green" /> Passing rules{" "}
          <span>{passing.length}</span>
        </summary>
        {passing.map((result) => (
          <RuleRow key={result.rule.id} result={result} />
        ))}
      </details>
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
                  <strong>{result.rule.statement}</strong>
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
          aria-label={`Select ${rule.statement}`}
          checked={selected}
          onChange={toggle}
        />
      )}
      <details>
        <summary>
          <div className="rule-title">
            <strong>{rule.statement}</strong>
            <div>
              <code>{rule.id}</code>
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
              <Tag tone="warning">Relaxation warning</Tag>
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
          {result.warnings.map((warning) => (
            <p className="notice" key={warning}>
              {warning}
            </p>
          ))}
          {rule.detail_code && (
            <p className="notice">
              Invalid rule · This result could not be evaluated.
            </p>
          )}
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
                <p>{instance.reason}</p>
                <dl>
                  {instance.conditions.map((condition, index) => (
                    <div key={index}>
                      <dt>{condition.label}</dt>
                      <dd>
                        <span>Expected</span>
                        {condition.expected}
                      </dd>
                      <dd>
                        <span>Observed</span>
                        {condition.observed ?? "Not observed"}
                      </dd>
                    </div>
                  ))}
                </dl>
                {instance.fixes.map((fix, index) => (
                  <div className="fix-detail" key={index}>
                    <span>
                      {groupLabels[fix.kind]} ·{" "}
                      {
                        {
                          derived: "Derived fix",
                          complete: "Declaration completes fix",
                          replace: "Declaration replaces fix",
                          block: "Fix blocked",
                        }[fix.origin]
                      }
                    </span>
                    <p>{fix.description}</p>
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
function RuleCatalog({
  org,
  onProposal,
}: {
  org: OrganizationView;
  onProposal: () => void;
}) {
  const rules = [
    ...new Map(
      org.repositories.flatMap((repo) =>
        repo.results.map((result) => [result.rule.id, result.rule] as const),
      ),
    ).values(),
  ];
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
        Requirements assigned inside {org.account}. Source config:{" "}
        <Commit value={org.organizationConfig.commit} />
      </p>
      {rules.map((rule) => (
        <div className="catalog-row" key={rule.id}>
          <div>
            <strong>{rule.statement}</strong>
            <code>{rule.id}</code>
          </div>
          <Tag tone={rule.severity}>{rule.severity}</Tag>
          <span>
            {
              org.repositories.filter((repo) =>
                repo.rules.some((value) => value.id === rule.id),
              ).length
            }{" "}
            repositories
          </span>
        </div>
      ))}
    </>
  );
}
function Assignments({
  org,
  onProposal,
}: {
  org: OrganizationView;
  onProposal: () => void;
}) {
  const assignments = [
    ...new Set(org.repositories.flatMap((repo) => repo.assignments)),
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
          <p>Assigned repositories</p>
          {org.repositories
            .filter((repo) => repo.assignments.includes(assignment))
            .map((repo) => (
              <a
                href={href(org.account, "repos", repo.repository.split("/")[1])}
                key={repo.repository}
              >
                {repo.repository.split("/")[1]} <Arrow />
              </a>
            ))}
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
