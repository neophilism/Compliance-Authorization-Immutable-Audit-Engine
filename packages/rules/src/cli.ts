import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import {
  evaluateRuleSet,
  parseEvaluationContext,
  parseRuleSetText,
} from "./index.js";

const [ruleSetPath, contextPath] = process.argv.slice(2);

if (!ruleSetPath || !contextPath) {
  console.error(
    "usage: npm run rules:evaluate -- <ruleset.yaml|json> <context.json>",
  );
  process.exitCode = 2;
} else {
  const extension = extname(ruleSetPath).toLowerCase();
  const format =
    extension === ".yaml" || extension === ".yml"
      ? "yaml"
      : extension === ".json"
        ? "json"
        : null;

  if (!format) {
    console.error("ruleset file must use .json, .yaml, or .yml");
    process.exitCode = 2;
  } else {
    try {
      const [ruleText, contextText] = await Promise.all([
        readFile(ruleSetPath, "utf8"),
        readFile(contextPath, "utf8"),
      ]);

      const ruleSet = parseRuleSetText(ruleText, format);
      const context = parseEvaluationContext(JSON.parse(contextText));
      const result = evaluateRuleSet(ruleSet, context);

      console.log(JSON.stringify(result, null, 2));
      process.exitCode =
        result.status === "fail"
          ? 1
          : result.status === "unknown"
            ? 3
            : 0;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "evaluation failed";
      console.error(message);
      process.exitCode = 2;
    }
  }
}
