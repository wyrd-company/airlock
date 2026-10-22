// relationships: { implements: ../../../docs/hosted-browser.md, references: ../shared/engine-report.ts }
import type {
  AssignmentResult,
  ConditionResult,
  ConfigSource,
  Diagnostic,
  EngineFix,
  EngineInstance,
  EngineReport,
  EngineRepository,
  EngineRule,
  Json,
} from "../shared/engine-report.ts";
import type {
  FixDisposition,
  ObservationTime,
  OrganizationReport,
} from "../shared/report.ts";
export interface ReportError {
  code: "invalid-engine-report";
  path: string;
  reason: string;
}
export type ReadResult<T> =
  { ok: true; value: T } | { ok: false; error: ReportError };
class InvalidReport extends Error {
  constructor(
    readonly path: string,
    reason: string,
  ) {
    super(reason);
  }
}
function invalid(path: string, expected: string): never {
  throw new InvalidReport(path, `Expected ${expected}`);
}
function object(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return invalid(path, "object");
  return Object.fromEntries(Object.entries(value));
}
function string(value: unknown, path: string): string {
  return typeof value === "string" ? value : invalid(path, "string");
}
function choice<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  const found = allowed.find((item) => item === value);
  return found === undefined ? invalid(path, allowed.join(" | ")) : found;
}
function array<T>(
  value: unknown,
  path: string,
  parse: (value: unknown, path: string) => T,
): T[] {
  return Array.isArray(value)
    ? value.map((item, i) => parse(item, `${path}[${i}]`))
    : invalid(path, "array");
}
function nullable<T>(
  value: unknown,
  path: string,
  parse: (value: unknown, path: string) => T,
): T | null {
  return value === null ? null : parse(value, path);
}
function json(value: unknown, path: string): Json {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return array(value, path, json);
  if (typeof value === "object")
    return Object.fromEntries(
      Object.entries(object(value, path)).map(([key, item]) => [
        key,
        json(item, `${path}.${key}`),
      ]),
    );
  return invalid(path, "JSON value");
}
function config(value: unknown, path: string): ConfigSource {
  const v = object(value, path);
  if (
    Object.keys(v).some(
      (key) => !["repository", "path", "commit"].includes(key),
    )
  )
    invalid(path, "ConfigSource fields");
  return {
    repository: string(v.repository, `${path}.repository`),
    path: string(v.path, `${path}.path`),
    commit: string(v.commit, `${path}.commit`),
  };
}
function diagnostic(value: unknown, path: string): Diagnostic {
  const v = object(value, path);
  return {
    code: string(v.code, `${path}.code`),
    reason: string(v.reason, `${path}.reason`),
  };
}
function fix(value: unknown, path: string): EngineFix {
  const v = object(value, path);
  const kind = choice(v.kind, `${path}.kind`, [
    "action",
    "agent",
    "not-fixable",
  ]);
  const fields =
    kind === "action"
      ? ["kind", "fixer", "action", "input"]
      : kind === "agent"
        ? ["kind", "guidance"]
        : ["kind", "reason"];
  if (Object.keys(v).some((key) => !fields.includes(key)))
    invalid(path, "tagged fix fields");
  if (kind === "action")
    return {
      kind,
      fixer: choice(v.fixer, `${path}.fixer`, ["person", "airlock"]),
      action: string(v.action, `${path}.action`),
      input: json(v.input, `${path}.input`),
    };
  if (kind === "agent")
    return { kind, guidance: string(v.guidance, `${path}.guidance`) };
  return { kind, reason: string(v.reason, `${path}.reason`) };
}
const result = (v: unknown, p: string) => choice(v, p, ["pass", "fail"]);
const flavor = (v: unknown, p: string) =>
  choice(v, p, ["passed", "waived", "not-applicable", "gap", "not-evaluated"]);
const severity = (v: unknown, p: string) =>
  choice(v, p, ["none", "advisory", "blocking"]);
function condition(value: unknown, path: string): ConditionResult {
  const v = object(value, path);
  if (
    typeof v.index !== "number" ||
    !Number.isSafeInteger(v.index) ||
    v.index < 0
  )
    invalid(`${path}.index`, "nonnegative integer");
  return {
    index: v.index,
    result: result(v.result, `${path}.result`),
    flavor: flavor(v.flavor, `${path}.flavor`),
    diagnostic: nullable(v.diagnostic, `${path}.diagnostic`, diagnostic),
    expected: json(v.expected, `${path}.expected`),
    probe: string(v.probe, `${path}.probe`),
    pointer: string(v.pointer, `${path}.pointer`),
    evaluation: string(v.evaluation, `${path}.evaluation`),
    observed_digest: nullable(
      v.observed_digest,
      `${path}.observed_digest`,
      string,
    ),
    reason: string(v.reason, `${path}.reason`),
    fix: fix(v.fix, `${path}.fix`),
  };
}
function instance(value: unknown, path: string): EngineInstance {
  const v = object(value, path);
  return {
    source: choice(v.source, `${path}.source`, ["organization", "repository"]),
    config_commit: string(v.config_commit, `${path}.config_commit`),
    mode: choice(v.mode, `${path}.mode`, ["value", "floor"]),
    statement: nullable(v.statement, `${path}.statement`, string),
    reason: nullable(v.reason, `${path}.reason`, string),
    relaxation_reason: nullable(
      v.relaxation_reason,
      `${path}.relaxation_reason`,
      string,
    ),
    severity: severity(v.severity, `${path}.severity`),
    result: result(v.result, `${path}.result`),
    flavor: flavor(v.flavor, `${path}.flavor`),
    diagnostic: nullable(v.diagnostic, `${path}.diagnostic`, diagnostic),
    conditions: array(v.conditions, `${path}.conditions`, condition),
    fixes: array(v.fixes, `${path}.fixes`, fix),
  };
}
function rule(value: unknown, path: string): EngineRule {
  const v = object(value, path);
  return {
    id: string(v.id, `${path}.id`),
    result: result(v.result, `${path}.result`),
    flavor: flavor(v.flavor, `${path}.flavor`),
    severity: severity(v.severity, `${path}.severity`),
    instances: array(v.instances, `${path}.instances`, instance),
  };
}
function assignment(value: unknown, path: string): AssignmentResult {
  const v = object(value, path);
  if (v.matched !== null && typeof v.matched !== "boolean")
    invalid(`${path}.matched`, "boolean or null");
  return {
    id: string(v.id, `${path}.id`),
    matched: v.matched,
    diagnostic: nullable(v.diagnostic, `${path}.diagnostic`, diagnostic),
  };
}
function repository(value: unknown, path: string): EngineRepository {
  const v = object(value, path);
  return {
    repository: string(v.repository, `${path}.repository`),
    audited_commit: string(v.audited_commit, `${path}.audited_commit`),
    maturity: choice(v.maturity, `${path}.maturity`, [
      "seeded",
      "building",
      "released",
      "stable",
    ]),
    repository_config: nullable(
      v.repository_config,
      `${path}.repository_config`,
      config,
    ),
    assignments: array(v.assignments, `${path}.assignments`, assignment),
    rules: array(v.rules, `${path}.rules`, rule),
    warnings: array(v.warnings, `${path}.warnings`, (item, p) => {
      const w = object(item, p);
      return {
        rule: string(w.rule, `${p}.rule`),
        code: string(w.code, `${p}.code`),
        reason: string(w.reason, `${p}.reason`),
      };
    }),
  };
}
export function projectFix(plan: EngineFix): FixDisposition {
  return {
    kind:
      plan.kind === "action"
        ? plan.fixer === "person"
          ? "you"
          : "airlock-pr"
        : plan.kind,
    plan,
  };
}
export const unavailableTime: ObservationTime = {
  value: null,
  provenance: "unavailable",
};
export function adaptReport(
  input: unknown,
  supplement: unknown = unavailableTime,
): ReadResult<OrganizationReport> {
  try {
    const v = object(input, "report");
    const core: EngineReport = {
      account: string(v.account, "report.account"),
      organization_config: config(
        v.organization_config,
        "report.organization_config",
      ),
      repositories: array(v.repositories, "report.repositories", repository),
      unassigned_repositories: array(
        v.unassigned_repositories,
        "report.unassigned_repositories",
        string,
      ),
    };
    for (const name of core.unassigned_repositories) {
      if (!core.repositories.some((repo) => repo.repository === name))
        invalid(
          "report.unassigned_repositories",
          "repository metadata for every unassigned identity",
        );
    }
    const time = object(supplement, "observation");
    const provenance = choice(time.provenance, "observation.provenance", [
      "audit",
      "capture",
      "unavailable",
    ]);
    let observation: ObservationTime;
    if (provenance === "unavailable") {
      if (time.value !== null)
        invalid("observation.value", "null when unavailable");
      observation = { provenance, value: null };
    } else {
      const value = string(time.value, "observation.value");
      if (!Number.isFinite(Date.parse(value)))
        invalid("observation.value", "explicit timestamp");
      observation = { provenance, value };
    }
    return {
      ok: true,
      value: {
        ...core,
        observation: structuredClone(observation),
        repositories: core.repositories.map((repo) => ({
          ...repo,
          rules: repo.rules.map((r) => ({
            ...r,
            instances: r.instances.map((i) => ({
              ...i,
              fixes: i.fixes.map(projectFix),
            })),
          })),
        })),
      },
    };
  } catch (error) {
    if (!(error instanceof InvalidReport)) throw error;
    return {
      ok: false,
      error: {
        code: "invalid-engine-report",
        path: error.path,
        reason: error.message,
      },
    };
  }
}
