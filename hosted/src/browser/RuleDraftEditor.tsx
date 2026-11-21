// relationships: { implements: ../../../docs/hosted-browser.md, references: rule-drafts.ts }
import { useMemo, useState } from "react";
import organizationExample from "../../fixtures/rule-drafts/organization.yml?raw";
import repositoryExample from "../../fixtures/rule-drafts/repository.yml?raw";
import type { OrganizationView } from "../shared/report.ts";
import { inspectDraft, uncheckedDraftChecks } from "./rule-drafts.ts";

export function RuleDraftEditor({ org }: { org: OrganizationView }) {
  const [target, setTarget] = useState("organization");
  return (
    <div className="rule-draft">
      <p className="notice">
        Local draft only. Closing this dialog or changing target discards your
        text. Nothing is saved, submitted, applied or audited.
      </p>
      <label className="draft-label" htmlFor="draft-target">
        Configuration target
      </label>
      <select
        id="draft-target"
        value={target}
        onChange={(event) => setTarget(event.target.value)}
      >
        <option value="organization">Organization · {org.account}</option>
        {[...org.repositories, ...org.unassigned].map((repo) => (
          <option key={repo.repository} value={repo.repository}>
            Repository · {repo.repository}
          </option>
        ))}
      </select>
      <DraftSource key={target} target={target} org={org} />
    </div>
  );
}

function DraftSource({
  target,
  org,
}: {
  target: string;
  org: OrganizationView;
}) {
  const kind = target === "organization" ? "organization" : "repository";
  const repository = [...org.repositories, ...org.unassigned].find(
    (repo) => repo.repository === target,
  );
  const source =
    kind === "organization"
      ? org.organizationConfig
      : repository?.repository_config;
  const [paste, setPaste] = useState("");
  const [draft, setDraft] = useState<{
    baseline: string;
    text: string;
    origin: string;
  }>();
  const checks = useMemo(
    () => (draft ? inspectDraft(draft.text, kind) : undefined),
    [draft, kind],
  );
  return (
    <>
      <p className="draft-source-context">
        Report source reference:{" "}
        {source ? (
          <code>
            {source.repository}:{source.path}@{source.commit}
          </code>
        ) : (
          "Unavailable in this report"
        )}
        . The report supplies no editable source bytes. Pasted text is
        unverified against this commit. Example source is hand-authored sample
        content.
      </p>
      <p className="draft-help">
        {kind === "organization"
          ? "Organization rules need an assignment reference to run. The example references sample-note; other rules demonstrate source shapes only."
          : "Repository rules run only after the repository matches an organization assignment. Editing a same-id rule here does not calculate its AND result."}
      </p>
      {!draft ? (
        <>
          <button
            className="secondary-button"
            onClick={() => {
              const text =
                kind === "organization"
                  ? organizationExample
                  : repositoryExample;
              setDraft({
                baseline: text,
                text,
                origin: "Hand-authored example source",
              });
            }}
          >
            Use complete {kind} example
          </button>
          <label className="draft-label" htmlFor="draft-paste">
            Paste complete {kind} source
          </label>
          <textarea
            id="draft-paste"
            rows={6}
            spellCheck={false}
            value={paste}
            onChange={(event) => setPaste(event.target.value)}
          />
          <button
            className="secondary-button"
            onClick={() =>
              setDraft({
                baseline: paste,
                text: paste,
                origin:
                  "User-supplied source · unverified against report commit",
              })
            }
          >
            Use pasted source as baseline
          </button>
        </>
      ) : (
        <>
          <div className="draft-toolbar">
            <strong>{draft.origin}</strong>
            <button
              className="secondary-button"
              onClick={() => {
                setDraft(undefined);
                setPaste("");
              }}
            >
              Discard draft
            </button>
          </div>
          <p className="draft-change" role="status">
            {draft.text === draft.baseline
              ? "Unchanged from baseline"
              : "Changed from baseline"}{" "}
            · {kind} configuration
          </p>
          <div className="draft-columns">
            <section>
              <h3>Baseline source</h3>
              <pre aria-label="Baseline source">{draft.baseline}</pre>
            </section>
            <section>
              <label className="draft-label" htmlFor="draft-yaml">
                Proposed YAML source
              </label>
              <textarea
                id="draft-yaml"
                rows={18}
                spellCheck={false}
                value={draft.text}
                onChange={(event) =>
                  setDraft({ ...draft, text: event.target.value })
                }
              />
            </section>
          </div>
          <section
            className="draft-checks"
            aria-label="Local syntax and envelope checks"
            aria-live="polite"
          >
            <h3>Local syntax and envelope checks</h3>
            {checks?.diagnostics.length ? (
              <ul>
                {checks.diagnostics.map((message, index) => (
                  <li key={index}>{message}</li>
                ))}
              </ul>
            ) : (
              <p>No local syntax or envelope diagnostics found.</p>
            )}
            <p>{uncheckedDraftChecks}</p>
            <p>
              Alias expansion, explicit tags, scalar-schema differences and core
              YAML budget parity remain unchecked. Unknown or malformed rule
              bodies stay in your draft.
            </p>
          </section>
          <section className="draft-preview">
            <h3>Complete proposed configuration</h3>
            <p>Exact current editor text · unvalidated local preview</p>
            <pre aria-label="Complete proposed configuration">{draft.text}</pre>
          </section>
        </>
      )}
      <p className="notice">
        Configuration pull requests are unavailable. Airlock never merges
        proposals. This preview is not an authorized change or an audit result.
      </p>
      <button className="primary-button" disabled>
        Open pull request
      </button>
    </>
  );
}
