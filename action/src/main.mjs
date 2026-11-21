// The Airlock action: repository mode on the WebAssembly engine.
//
// This file decides only what the action's inputs mean and what its outputs
// say. The audit itself, and every check on the token, run in the module
// (crates/wasm, docs/wasm.md). See docs/action.md for the contract.

/** The variables that describe the run, as the module reads them. */
export const ACTIONS_VARIABLES = [
  "GITHUB_ACTIONS",
  "GITHUB_REPOSITORY",
  "GITHUB_WORKFLOW_REF",
  "GITHUB_WORKFLOW_SHA",
  "GITHUB_JOB",
];

/** The artifact the report is uploaded as, which the Airlock Worker reads. */
export const ARTIFACT_NAME = "airlock-findings";

export const CENTRAL_MOVED =
  "central mode is no longer part of this action: the Airlock Worker's scheduled central audit " +
  "audits every repository of the owner. This action runs repository mode only; remove `mode: central` " +
  "and its inputs.";

/**
 * Run the action.
 *
 * @param {{
 *   input: (name: string) => string,
 *   env: Record<string, string | undefined>,
 *   setSecret: (value: string) => void,
 *   setOutput: (name: string, value: string) => void,
 *   exportVariable: (name: string, value: string) => void,
 *   info: (message: string) => void,
 *   error: (message: string) => void,
 *   warning: (message: string) => void,
 *   setFailed: (message: string) => void,
 *   writeFile: (path: string, text: string) => void,
 *   audit: (request: string) => Promise<string>,
 *   upload: (path: string, extension: string) => Promise<void>,
 * }} io
 */
export async function run(io) {
  const { env } = io;

  // Mask both tokens before anything else is read or written, so no later
  // line of the log can carry either one.
  const token = io.input("token") || (env.AIRLOCK_TOKEN ?? "").trim();
  const runToken = io.input("run-token");
  for (const secret of [token, runToken]) if (secret) io.setSecret(secret);
  const redact = (text) => {
    let out = String(text);
    for (const secret of [token, runToken]) if (secret) out = out.split(secret).join("[redacted]");
    return out;
  };

  const mode = io.input("mode") || "repository";
  const format = io.input("format") || "json";
  let failOnIncomplete = io.input("fail-on-incomplete") || "true";
  const reference = io.input("ref");
  const policy = io.input("policy");
  const repository = io.input("repository") || (env.GITHUB_REPOSITORY ?? "").trim();

  let validation;
  let extension = "txt";
  if (format === "json") extension = "json";
  else if (format !== "text") validation = "format must be 'json' or 'text'.";
  if (failOnIncomplete !== "true" && failOnIncomplete !== "false") {
    validation = "fail-on-incomplete must be 'true' or 'false'.";
    failOnIncomplete = "true";
  }
  // The override is honoured only in repository mode, so a run whose mode is
  // anything else never ends as a success without its audit.
  const override = failOnIncomplete === "false";
  const repositoryMode = mode === "repository";
  if (mode === "central") validation = CENTRAL_MOVED;
  else if (!repositoryMode) validation = "mode must be 'repository', the only mode this action runs.";
  const forgive = repositoryMode && override;

  const invocation = (env.GITHUB_ACTION || "airlock").replace(/[^A-Za-z0-9_.-]/g, "_");
  const directory = env.RUNNER_TEMP || env.TMPDIR || "/tmp";
  const findingsLocation =
    `${directory}/airlock-findings-${env.GITHUB_RUN_ID || "local"}-${env.GITHUB_RUN_ATTEMPT || "1"}` +
    `-${invocation}.${extension}`;
  const documentMode = mode.replace(/[^a-z]/g, "");

  const finish = async (outcome, complete, document) => {
    io.writeFile(findingsLocation, document);
    io.info(document);
    io.setOutput("outcome", outcome);
    io.setOutput("complete", String(complete));
    io.setOutput("findings-location", findingsLocation);
    io.exportVariable("AIRLOCK_FINDINGS", findingsLocation);
    io.exportVariable("AIRLOCK_OUTCOME", outcome);
    io.exportVariable("AIRLOCK_COMPLETE", String(complete));
    let uploaded = true;
    try {
      await io.upload(findingsLocation, extension);
    } catch (error) {
      uploaded = false;
      io.setFailed(redact(`the report could not be uploaded as the ${ARTIFACT_NAME} artifact: ${error?.message ?? error}`));
    }
    if (!uploaded) return;
    if (outcome === "nonconformant") {
      io.setFailed("Airlock found blocking gaps: the outcome is nonconformant.");
    } else if (outcome !== "conformant") {
      if (forgive) io.warning("The audit is incomplete; fail-on-incomplete is false, so the step succeeds.");
      else io.setFailed("The audit is incomplete.");
    }
  };

  // The stable document for a run that did not audit. Its message is the
  // action's own, or the module's, which the module has already redacted.
  const incomplete = async (message) => {
    const safe = redact(message);
    io.error(safe);
    const document =
      extension === "json"
        ? `${JSON.stringify({ outcome: "incomplete", complete: false, mode: documentMode, message: safe })}\n`
        : `incomplete — complete: false\nmode: ${documentMode}\n${safe}\n`;
    await finish("incomplete", false, document);
  };

  if (validation) return incomplete(validation);
  if (!token) {
    return incomplete(
      "repository mode needs the token input, the run's own token, or AIRLOCK_TOKEN, a credential Airlock can prove is read-only.",
    );
  }
  if (!repository) return incomplete("repository is required when GITHUB_REPOSITORY is unavailable.");

  const actions = {};
  for (const name of ACTIONS_VARIABLES) if (env[name] !== undefined) actions[name] = env[name];
  const request = { token, repository, format, actions };
  if (runToken) request.runToken = runToken;
  if (reference) request.reference = reference;
  if (policy) request.policy = policy;
  if (env.GITHUB_API_URL) request.githubApi = env.GITHUB_API_URL;

  let result;
  try {
    result = JSON.parse(await io.audit(JSON.stringify(request)));
  } catch (error) {
    const kind = typeof error?.kind === "string" ? `${error.kind}: ` : "";
    return incomplete(`Airlock did not audit (${kind}${error?.message ?? "the engine failed"}).`);
  }
  const outcome = ["conformant", "nonconformant"].includes(result.outcome) ? result.outcome : "incomplete";
  return finish(outcome, outcome !== "incomplete" && result.complete === true, redact(result.document));
}
