// relationships: { references: ../../../crates/core/src/configurable/report.rs }
// Rust Serde input contract. Optional Rust values serialize as explicit null.
export type Json =
  null | boolean | number | string | Json[] | { [key: string]: Json };
export type Severity = "none" | "advisory" | "blocking";
export type Flavor =
  "passed" | "waived" | "not-applicable" | "gap" | "not-evaluated";
export type ResultKind = "pass" | "fail";
export interface ConfigSource {
  repository: string;
  path: string;
  commit: string;
}
export interface Diagnostic {
  code: string;
  reason: string;
}
export type EngineFix =
  | { kind: "action"; fixer: "person" | "airlock"; action: string; input: Json }
  | { kind: "agent"; guidance: string }
  | { kind: "not-fixable"; reason: string };
export interface ConditionResult {
  index: number;
  result: ResultKind;
  flavor: Flavor;
  diagnostic: Diagnostic | null;
  expected: Json;
  probe: string;
  pointer: string;
  evaluation: string;
  observed_digest: string | null;
  reason: string;
  fix: EngineFix;
}
export interface EngineInstance {
  source: "organization" | "repository";
  config_commit: string;
  mode: "value" | "floor";
  statement: string | null;
  reason: string | null;
  relaxation_reason: string | null;
  severity: Severity;
  result: ResultKind;
  flavor: Flavor;
  diagnostic: Diagnostic | null;
  conditions: ConditionResult[];
  fixes: EngineFix[];
}
export interface EngineRule {
  id: string;
  result: ResultKind;
  flavor: Flavor;
  severity: Severity;
  instances: EngineInstance[];
}
export interface AssignmentResult {
  id: string;
  matched: boolean | null;
  diagnostic: Diagnostic | null;
}
export interface Warning {
  rule: string;
  code: string;
  reason: string;
}
export interface EngineRepository {
  repository: string;
  audited_commit: string;
  maturity: "seeded" | "building" | "released" | "stable";
  repository_config: ConfigSource | null;
  assignments: AssignmentResult[];
  rules: EngineRule[];
  warnings: Warning[];
}
export interface EngineReport {
  account: string;
  organization_config: ConfigSource;
  repositories: EngineRepository[];
  unassigned_repositories: string[];
}
