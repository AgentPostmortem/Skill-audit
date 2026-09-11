import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText } from "../src/scan.js";

test("SKILL-SEC-003 detects process.env and os.getenv secret reads", () => {
  for (const [source, file] of [
    ["const key = process.env.AWS_SECRET;\n", "setup.js"],
    ['token = os.getenv("API_TOKEN")\n', "setup.py"],
    ["```js\nconst key = process.env.AWS_SECRET;\n```\n", "SKILL.md"],
    ['```py\ntoken = os.getenv("API_TOKEN")\n```\n', "SKILL.md"],
  ]) {
    const findings = scanText(source, file, null).filter((f) => f.rule === "SKILL-SEC-003");
    assert.equal(findings.length, 1, `${file}: ${source}`);
    assert.equal(findings[0].severity, "medium");
  }
});

test("SKILL-SEC-003 keeps existing env-dump matchers", () => {
  for (const source of [
    "printenv\n",
    "for k, v in os.environ.items():\n",
    "require('dotenv').config()\n",
    "cat .env\n",
  ]) {
    const findings = scanText(source, "setup.sh", null).filter((f) => f.rule === "SKILL-SEC-003");
    assert.equal(findings.length, 1, source);
  }
});
