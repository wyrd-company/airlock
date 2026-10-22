// relationships: { implements: ../../../docs/hosted-browser.md }
import type { ReportStore } from "./store.ts";
import { projectOrganization, summarize } from "./projection.ts";
const headers = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};
export function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers });
}
export function createService(store: ReportStore) {
  return async (request: Request): Promise<Response> => {
    const path = new URL(request.url).pathname;
    // These are local fixture reads, not an authentication implementation.
    if (request.method !== "GET" && request.method !== "HEAD")
      return json({ error: "integration-unavailable" }, 503);
    let response: Response;
    if (path === "/api/organizations") {
      const reports = await store.list();
      if (!reports.ok) response = json({ error: reports.error }, 503);
      else
        response = json({
          mode: "local-fixtures",
          organizations: reports.value.map((report) =>
            summarize(projectOrganization(report)),
          ),
        });
    } else if (path.startsWith("/api/organizations/")) {
      let account: string;
      try {
        account = decodeURIComponent(path.slice("/api/organizations/".length));
      } catch {
        return json({ error: "invalid-organization" }, 400);
      }
      const result = await store.get(account);
      if (!result.ok) response = json({ error: result.error }, 503);
      else {
        const report = result.value;
        response = report
          ? json({
              mode: "local-fixtures",
              organization: projectOrganization(report),
            })
          : json({ error: "organization-not-found" }, 404);
      }
    } else if (path === "/api/session") {
      response = json({
        state: "unavailable",
        admin: false,
        stepUp: false,
        proposals: false,
      });
    } else response = json({ error: "not-found" }, 404);
    return request.method === "HEAD"
      ? new Response(null, {
          status: response.status,
          headers: response.headers,
        })
      : response;
  };
}
