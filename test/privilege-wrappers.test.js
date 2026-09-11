import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText } from "../src/scan.js";

test("privilege escalation rule detects sudo, doas and run0 in scripts and fences", () => {
  // Scanner input only: no commands are executed.
  for (const command of ["sudo", "doas", "run0"]) {
    for (const prefix of ["", "echo ok; ", "true && ", "(", "echo ok\n"]) {
      const source = `${prefix}${command} reboot\n`;
      for (const [text, file] of [[source, "setup.sh"], [`\`\`\`sh\n${source}\`\`\`\n`, "SKILL.md"]]) {
        const findings = scanText(text, file, null).filter((f) => f.rule === "SKILL-SH-003");
        assert.equal(findings.length, 1, `${file}: ${source}`);
        assert.equal(findings[0].severity, "medium");
      }
    }
  }
});

test("privilege escalation rule keeps command boundaries and prose exclusion", () => {
  for (const text of ["mydoas reboot", "run01 reboot", "sudoers file", "doas-helper reboot"]) {
    assert.equal(scanText(text, "setup.sh", null).filter((f) => f.rule === "SKILL-SH-003").length, 0);
  }
  assert.equal(scanText("Discuss sudo, doas and run0 carefully.\n", "SKILL.md", null)
    .filter((f) => f.rule === "SKILL-SH-003").length, 0);
});
