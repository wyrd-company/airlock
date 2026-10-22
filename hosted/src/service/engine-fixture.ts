// relationships: { references: ../../fixtures/configurable-report.json, implements: ../../../docs/hosted-browser.md }
import report from "../../fixtures/configurable-report.json" with { type: "json" };
import observation from "../../fixtures/observation.json" with { type: "json" };
import { engineReportStore } from "./store.ts";
// The engine supplies no audit time. Capture/commit time cannot supply audit time.
export const actualFixtureStore = () =>
  engineReportStore([{ report, observation }]);
