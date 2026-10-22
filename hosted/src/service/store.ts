// relationships: { implements: ../../../docs/hosted-browser.md }
import type { OrganizationReport } from "../shared/report.ts";
export interface ReportStore {
  list(): Promise<OrganizationReport[]>;
  get(account: string): Promise<OrganizationReport | null>;
}
// Test/local data only. Live organization visibility needs a verified IdP contract.
export function fixtureStore(reports: OrganizationReport[]): ReportStore {
  const snapshot = structuredClone(reports);
  return {
    async list() {
      return structuredClone(snapshot);
    },
    async get(account) {
      return structuredClone(
        snapshot.find((report) => report.account === account) ?? null,
      );
    },
  };
}
