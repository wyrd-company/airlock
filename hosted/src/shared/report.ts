// relationships: { implements: ../../../docs/hosted-browser.md, references: engine-report.ts }
import type {
  EngineFix,
  EngineInstance,
  EngineRepository,
  EngineReport,
  EngineRule,
} from "./engine-report.ts";
export type {
  Severity,
  Flavor,
  ConfigSource,
  AssignmentResult,
  Diagnostic,
} from "./engine-report.ts";
export type Fixer = "you" | "airlock-pr" | "agent" | "not-fixable";
export interface FixDisposition {
  kind: Fixer;
  plan: EngineFix;
}
export interface RuleInstance extends Omit<EngineInstance, "fixes"> {
  fixes: FixDisposition[];
}
export interface RuleResult extends Omit<EngineRule, "instances"> {
  instances: RuleInstance[];
}
export interface RepositoryReport extends Omit<EngineRepository, "rules"> {
  rules: RuleResult[];
}
export type ObservationTime =
  | { value: null; provenance: "unavailable" }
  | { value: string; provenance: "audit" | "capture" };
export interface OrganizationReport extends Omit<EngineReport, "repositories"> {
  repositories: RepositoryReport[];
  observation: ObservationTime;
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
  warnings: EngineRepository["warnings"];
}
export interface RepositoryView extends RepositoryReport {
  blocking: number;
  advisory: number;
  incomplete: number;
  assignmentUnknown: boolean;
  results: ResultView[];
}
export interface OrganizationView {
  account: string;
  organizationConfig: EngineReport["organization_config"];
  observation: ObservationTime;
  repositories: RepositoryView[];
  unassigned: RepositoryReport[];
}
export interface OrganizationSummary {
  account: string;
  repositories: number;
  unknownAssignments: number;
  blocking: number;
  advisory: number;
  incomplete: number;
  unassigned: number;
  observation: ObservationTime;
}
export function fixDescription(plan: EngineFix): string {
  return plan.kind === "action"
    ? plan.action
    : plan.kind === "agent"
      ? plan.guidance
      : plan.reason;
}
