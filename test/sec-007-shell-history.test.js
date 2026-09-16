import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText } from "../src/scan.js";

test("SKILL-SEC-007 flags shell-history file references", () => {
  for (const [source, file] of [
    ["cat ~/.bash_history\n", "setup.sh"],
    ["tail -n 50 ~/.zsh_history\n", "setup.sh"],
    ["Get-Content $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\n", "setup.ps1"],
  ]) {
    const findings = scanText(source, file, null).filter((f) => f.rule === "SKILL-SEC-007");
    assert.equal(findings.length, 1, `${file}: ${source}`);
    assert.equal(findings[0].severity, "high");
  }
});

test("SKILL-SEC-007 ignores ordinary history-related text", () => {
  for (const source of [
    "history | tail -20\n",
    "echo 'keep a changelog of command history'\n",
    "const history = []\n",
  ]) {
    const findings = scanText(source, "setup.sh", null).filter((f) => f.rule === "SKILL-SEC-007");
    assert.equal(findings.length, 0, source);
  }
});
