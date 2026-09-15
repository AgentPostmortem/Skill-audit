import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText } from "../src/scan.js";

const RULE = "SKILL-SH-011";

test("SKILL-SH-011 flags setuid and sudoers privilege escalation", () => {
  for (const source of [
    "chmod u+s /tmp/backdoor\n",
    "chmod 4755 /tmp/x\n",
    "chown root:root /tmp/x\n",
    "echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\n",
  ]) {
    const findings = scanText(source, "setup.sh", null).filter((f) => f.rule === RULE);
    assert.equal(findings.length, 1, source);
    assert.equal(findings[0].severity, "high");
  }
});

test("SKILL-SH-011 keeps ordinary permission changes clean", () => {
  for (const source of ["chmod 755 ./script.sh\n", "chown app:app ./data\n"]) {
    assert.equal(scanText(source, "setup.sh", null).filter((f) => f.rule === RULE).length, 0, source);
  }
});
