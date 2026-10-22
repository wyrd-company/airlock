// relationships: { implements: ../../../docs/hosted-browser.md }
// Provisional transport input, deliberately independent of airlock-core's public schema.
export type Severity = "none" | "advisory" | "blocking";
export type Flavor =
  "passed" | "waived" | "not-applicable" | "gap" | "not-evaluated";
export type Fixer = "you" | "airlock-pr" | "agent" | "not-fixable";
export interface ConfigSource {
  repository: string;
  path: string;
  commit: string;
}
export interface FixDisposition {
  kind: Fixer;
  origin: "derived" | "complete" | "replace" | "block";
  description: string;
}
export interface RuleInstance {
  source: "organization" | "repository";
  config_commit: string;
  mode: "value" | "floor";
  result: "pass" | "fail";
  flavor: Flavor;
  reason: string;
  conditions: { label: string; expected: string; observed: string | null }[];
  fixes: FixDisposition[];
}
export interface RuleResult {
  id: string;
  statement: string;
  result: "pass" | "fail";
  flavor: Flavor;
  severity: Severity;
  instances: RuleInstance[];
  detail_code?: "invalid-rule";
}
export interface RepositoryReport {
  repository: string;
  maturity: "seeded" | "building" | "released" | "stable";
  repository_config: ConfigSource | null;
  assignments: string[];
  rules: RuleResult[];
  warnings: {
    rule_id: string;
    code: "relaxation-without-reason";
    message: string;
  }[];
}
export interface OrganizationReport {
  account: string;
  organization_config: ConfigSource;
  observed_at: string;
  repositories: RepositoryReport[];
  unassigned_repositories: string[];
}
export const groupOrder = [
  "you",
  "airlock-pr",
  "agent",
  "not-fixable",
  "not-evaluated",
] as const;
export type ResultGroup = (typeof groupOrder)[number];
export const groupLabels: Record<ResultGroup, string> = {
  you: "You",
  "airlock-pr": "Airlock PR",
  agent: "Agent",
  "not-fixable": "Not fixable",
  "not-evaluated": "Couldn't evaluate",
};
export interface ResultView {
  rule: RuleResult;
  groups: ResultGroup[];
  fixes: FixDisposition[];
  warnings: string[];
}
export interface RepositoryView extends RepositoryReport {
  blocking: number;
  advisory: number;
  incomplete: number;
  results: ResultView[];
}
export interface OrganizationView {
  account: string;
  organizationConfig: ConfigSource;
  observedAt: string;
  repositories: RepositoryView[];
  unassigned: string[];
}
export interface OrganizationSummary {
  account: string;
  repositories: number;
  blocking: number;
  advisory: number;
  incomplete: number;
  unassigned: number;
  observedAt: string;
}
