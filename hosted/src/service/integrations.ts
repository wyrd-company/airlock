// relationships: { implements: ../../../docs/hosted-browser.md }
// Ports express obligations, not a settled external protocol or proof of integration.
export class IntegrationUnavailable extends Error {
  constructor(public readonly integration: string) {
    super(`${integration} is not connected`);
  }
}
export interface BrowserPerson {
  subject: string;
  tabSession: string;
}
export interface AdminSession {
  person: BrowserPerson;
  githubActor: string;
  githubTokenExpiresAt: string;
  state: "active" | "signed-out" | "tab-closed" | "expired";
}
export interface ReviewedChange {
  repository: string;
  ruleId: string;
  setting: string;
  before: unknown;
  after: unknown;
}
export interface ReviewedBatch {
  organization: string;
  digest: string;
  changes: readonly ReviewedChange[];
}
export interface TruenameStepUp {
  // Must verify browser/person presence, exact digest and one-use consumption server-side.
  confirm(person: BrowserPerson, batch: ReviewedBatch): Promise<void>;
}
export interface AdminAuthorization {
  beginAtFirstReview(person: BrowserPerson): Promise<AdminSession>;
  end(
    session: AdminSession,
    cause: "signed-out" | "tab-closed" | "expired",
  ): Promise<void>;
}
export interface ConfigurationProposals {
  // Must enforce PR-only changes and the separately unresolved cannot-merge boundary.
  propose(
    organization: string,
    configCommit: string,
    patch: string,
  ): Promise<{ url: string }>;
}
export const unavailableStepUp: TruenameStepUp = {
  async confirm() {
    throw new IntegrationUnavailable("Truename batch confirmation");
  },
};
export const unavailableAdmin: AdminAuthorization = {
  async beginAtFirstReview() {
    throw new IntegrationUnavailable("Airlock Admin browser authorization");
  },
  async end() {
    throw new IntegrationUnavailable("Airlock Admin session");
  },
};
export const unavailableProposals: ConfigurationProposals = {
  async propose() {
    throw new IntegrationUnavailable("Configuration pull requests");
  },
};
// Intentionally no token input, refresh, settings writer, merge operation or live default.
