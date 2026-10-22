// relationships: { implements: ../../../docs/hosted-browser.md }
import { createService, json } from "./service.ts";
import { fixtureReports } from "./fixtures.ts";
import { fixtureStore } from "./store.ts";
import { IntegrationUnavailable } from "./integrations.ts";
interface Environment {
  LOCAL_FIXTURES?: string;
  ASSETS: { fetch(request: Request): Promise<Response> };
}
const fixtureService = createService(fixtureStore(fixtureReports));
export default {
  async fetch(request: Request, environment: Environment): Promise<Response> {
    // Explicit local config AND loopback: deploying this config does not expose fixture APIs.
    const hostname = new URL(request.url).hostname;
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(hostname);
    if (environment.LOCAL_FIXTURES !== "enabled" || !local)
      return json({ error: "hosted-integration-unavailable" }, 503);
    if (new URL(request.url).pathname.startsWith("/api/"))
      return fixtureService(request);
    if (request.method !== "GET" && request.method !== "HEAD")
      return json({ error: "method-not-allowed" }, 405);
    return environment.ASSETS.fetch(request);
  },
  async scheduled(): Promise<void> {
    // A real schedule must use installed-org visibility and a durable audit queue.
    throw new IntegrationUnavailable("Scheduled audit dispatch");
  },
};
