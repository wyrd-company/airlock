// relationships: { implements: ../../../docs/hosted-browser.md, references: ../../../crates/core/src/configurable/config.rs }
import {
  isAlias,
  isMap,
  isScalar,
  isSeq,
  LineCounter,
  parseDocument,
} from "yaml";

export type ConfigKind = "organization" | "repository";
export interface DraftChecks {
  diagnostics: string[];
  incomplete: boolean;
}
export const uncheckedDraftChecks =
  "Rule and assignment bodies, registered probes/evaluations/fixes, floors, hierarchy, scopes, source authenticity, observations and core YAML budget parity are not checked. This is not an audit or full configuration validation.";

/** Optional AST inspection only. Its result never owns or rewrites source text. */
export function inspectDraft(text: string, kind: ConfigKind): DraftChecks {
  const diagnostics: string[] = [];
  let incomplete = false;
  // Existing core defaults bound optional inspection, never editing or preview.
  if (new TextEncoder().encode(text).byteLength > 512 * 1024)
    return {
      diagnostics: [
        "Local checks unavailable above the core default 512 KiB. Full source remains editable.",
      ],
      incomplete: true,
    };
  try {
    const lines = new LineCounter();
    const doc = parseDocument(text, {
      version: "1.2",
      schema: "core",
      merge: false,
      intAsBigInt: true,
      uniqueKeys: true,
      stringKeys: false,
      keepSourceTokens: true,
      prettyErrors: false,
      lineCounter: lines,
    });
    for (const issue of [...doc.errors, ...doc.warnings]) {
      const { line, col } = lines.linePos(issue.pos[0]);
      diagnostics.push(`Line ${line}:${col}: ${issue.message}`);
    }
    let nodes = 0;
    function walk(node: unknown, depth: number): void {
      if (++nodes > 20_000 || depth > 32) {
        incomplete = true;
        return;
      }
      if (isAlias(node)) {
        incomplete = true;
        return; // Do not expand aliases or mistake AST counts for expanded nodes.
      }
      if (node && typeof node === "object" && "tag" in node && node.tag)
        incomplete = true;
      if (isMap(node)) {
        for (const pair of node.items) {
          if (
            !isAlias(pair.key) &&
            !(isScalar(pair.key) && typeof pair.key.value === "string")
          )
            diagnostics.push(
              "Mapping keys must be strings; a direct non-string key was found.",
            );
          walk(pair.key, depth + 1);
          walk(pair.value, depth + 1);
          if (nodes > 20_000) break;
        }
      } else if (isSeq(node)) {
        for (const item of node.items) {
          walk(item, depth + 1);
          if (nodes > 20_000) break;
        }
      }
    }
    walk(doc.contents, 0);
    const root = doc.contents;
    // The core reads empty/null roots as an empty map, including repository {}.
    if (root === null || (isScalar(root) && root.value === null)) {
      if (kind === "organization")
        diagnostics.push(
          "Organization configuration requires rules and assignments maps.",
        );
    } else if (isAlias(root)) {
      incomplete = true;
    } else if (!isMap(root)) {
      diagnostics.push("Configuration must have a mapping at its root.");
    } else {
      const allowed =
        kind === "organization"
          ? ["rules", "assignments", "repositories"]
          : ["rules"];
      for (const pair of root.items) {
        if (isScalar(pair.key) && typeof pair.key.value === "string") {
          const key = pair.key.value;
          if (!allowed.includes(key))
            diagnostics.push(`Unknown ${kind} envelope key: ${key}.`);
          else if (isAlias(pair.value)) incomplete = true;
          else if (!isMap(pair.value))
            diagnostics.push(`${key} must be a map.`);
        }
      }
      if (
        kind === "organization" &&
        !root.items.some(({ key }) => isAlias(key))
      )
        for (const required of ["rules", "assignments"])
          if (
            !root.items.some(
              ({ key }) => isScalar(key) && key.value === required,
            )
          )
            diagnostics.push(
              `Organization configuration requires a ${required} map.`,
            );
    }
    if (incomplete)
      diagnostics.push(
        "Local checks incomplete: aliases, explicit tags or inspection bounds need core validation. Alias/key expansion and scalar/budget parity are unchecked.",
      );
    return { diagnostics, incomplete };
  } catch {
    return {
      diagnostics: [
        "Local checks unavailable. The current source remains editable and previewable.",
      ],
      incomplete: true,
    };
  }
}
