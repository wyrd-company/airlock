// relationships: { implements: ../../../docs/hosted-browser.md }
import type { OrganizationReport } from "../shared/report.ts";
import { adaptReport, type ReadResult } from "./report-adapter.ts";
export interface ReportStore {
  list(): Promise<ReadResult<OrganizationReport[]>>;
  get(account: string): Promise<ReadResult<OrganizationReport | null>>;
}
// Trusted synthetic view reports for unit boundary cases only.
export function fixtureStore(reports: OrganizationReport[]): ReportStore {
  const snapshot = structuredClone(reports);
  return {
    async list() {
      return { ok: true, value: structuredClone(snapshot) };
    },
    async get(account) {
      return {
        ok: true,
        value: structuredClone(
          snapshot.find((report) => report.account === account) ?? null,
        ),
      };
    },
  };
}
// Invalid input stays unavailable, never an empty or healthy report.
export function engineReportStore(
  inputs: { report: unknown; observation?: unknown }[],
): ReportStore {
  const parsed = inputs.map(({ report, observation }) =>
    adaptReport(report, observation),
  );
  return {
    async list() {
      const values: OrganizationReport[] = [];
      for (const report of parsed) {
        if (!report.ok) return report;
        values.push(structuredClone(report.value));
      }
      return { ok: true, value: values };
    },
    async get(account) {
      const list = await this.list();
      return list.ok
        ? {
            ok: true,
            value:
              list.value.find((report) => report.account === account) ?? null,
          }
        : list;
    },
  };
}
