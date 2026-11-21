// relationships: { implements: ../../../docs/hosted-browser.md }
import { IntegrationUnavailable } from "./integrations.ts";
export interface AuditRequest {
  organization: string;
  repository: string | null;
  cause: "webhook" | "sweep";
}
export interface VerifiedWebhook {
  organization: string;
  repository: string | null;
}
export interface WebhookVerifier {
  // The live adapter must verify signature, installation and org scope before returning.
  verify(request: Request): Promise<VerifiedWebhook>;
}
export interface AuditQueue {
  enqueue(request: AuditRequest): Promise<void>;
}
export interface InstalledOrganizations {
  list(): Promise<string[]>;
}
export async function receiveWebhook(
  request: Request,
  verifier: WebhookVerifier,
  queue: AuditQueue,
): Promise<void> {
  const verified = await verifier.verify(request);
  await queue.enqueue({ ...verified, cause: "webhook" });
}
export async function sweep(
  organizations: InstalledOrganizations,
  queue: AuditQueue,
): Promise<void> {
  // Serialized dispatch keeps the initial interface independent of batching/queue choices.
  for (const organization of await organizations.list()) {
    await queue.enqueue({ organization, repository: null, cause: "sweep" });
  }
}
export const unavailableWebhook: WebhookVerifier = {
  async verify() {
    throw new IntegrationUnavailable("GitHub webhook verification");
  },
};
