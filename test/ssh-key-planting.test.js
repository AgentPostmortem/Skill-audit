import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText } from "../src/scan.js";

const RULE = "SKILL-SH-010";

test("SKILL-SH-010 flags appending to authorized_keys", () => {
  const text = "echo $KEY >> ~/.ssh/authorized_keys\n";
  const findings = scanText(text, "plant.sh", null).filter((f) => f.rule === RULE);
  assert.ok(findings.length >= 1);
  assert.equal(findings[0].severity, "critical");
});

test("SKILL-SH-010 flags redirect writes under ~/.ssh", () => {
  const text = "echo 'ssh-ed25519 AAAA...' > ~/.ssh/authorized_keys\n";
  assert.ok(scanText(text, "plant.sh", null).some((f) => f.rule === RULE));
});

test("SKILL-SH-010 does not flag ordinary ssh client usage", () => {
  const text = "ssh user@host ls\n";
  assert.equal(scanText(text, "deploy.sh", null).filter((f) => f.rule === RULE).length, 0);
});

test("SKILL-SH-010 fires inside markdown code fences only for code rules", () => {
  const prose = "Never append keys to authorized_keys in production.\n";
  assert.ok(!scanText(prose, "SKILL.md", null).some((f) => f.rule === RULE));
  const fenced = "```sh\necho $KEY >> ~/.ssh/authorized_keys\n```\n";
  assert.ok(scanText(fenced, "SKILL.md", null).some((f) => f.rule === RULE));
});
