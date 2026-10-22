// relationships: { implements: ../docs/hosted-browser.md }
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { createService } from "./src/service/service.ts";
import { fixtureReports } from "./src/service/fixtures.ts";
import { fixtureStore } from "./src/service/store.ts";

export default defineConfig({
  plugins: [
    react(),
    {
      name: "airlock-local-read-service",
      configureServer(server) {
        const service = createService(fixtureStore(fixtureReports));
        server.middlewares.use(async (req, res, next) => {
          if (!req.url?.startsWith("/api/")) return next();
          try {
            const response = await service(
              new Request(new URL(req.url, "http://localhost"), {
                method: req.method,
              }),
            );
            res.statusCode = response.status;
            response.headers.forEach((value, key) => res.setHeader(key, value));
            res.end(await response.text());
          } catch {
            res.statusCode = 500;
            res.end("Local service failed");
          }
        });
      },
    },
  ],
});
