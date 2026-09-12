// Output formatters: text (human), json, sarif (GitHub code scanning / CI).
import { SEVERITY_ORDER } from "./rules.js";
import { sevRank } from "./scan.js";

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_COLOR = { critical: 41, high: 31, medium: 33, low: 36, info: 90 };
const badge = (sev) => c(SEV_COLOR[sev] || 0, ` ${sev.toUpperCase()} `);

export function counts(findings) {
  const out = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of findings) out[f.severity]++;
  return out;
}

function skippedSummary(skipped) {
  return skipped.map((s) => {
    const why = s.reason === "oversized"
      ? `exceeds ${(2_000_000 / 1_000_000).toFixed(0)} MB limit (${s.size} bytes)`
      : "could not be read";
    return `  ${c("33", "!")} ${s.file} — not scanned (${why})`;
  });
}

export function formatSkippedWarnings(skipped) {
  if (!skipped?.length) return "";
  return skipped.map((s) => {
    const why = s.reason === "oversized"
      ? `exceeds 2 MB limit (${s.size} bytes)`
      : "could not be read";
    return `skill-audit: skipped ${s.file} — not scanned (${why})\n`;
  }).join("");
}

export function textReport({ findings, files, skillName, skipped = [] }) {
  const lines = [];
  lines.push("");
  lines.push(c("1", `skill-audit  ·  ${skillName}`) + c("90", `  (${files} file${files === 1 ? "" : "s"} scanned)`));
  lines.push("");
  if (skipped.length) {
    lines.push(c("33", "  Skipped files (not scanned):"));
    lines.push(...skippedSummary(skipped));
    lines.push("");
  }
  if (!findings.length && !skipped.length) {
    lines.push(c("32", "  ✓ No issues found."));
    lines.push("");
    return lines.join("\n");
  }
  if (!findings.length && skipped.length) {
    lines.push(c("33", "  No rule findings, but some files were not scanned (see above)."));
    lines.push("");
    return lines.join("\n");
  }
  for (const f of findings) {
    lines.push(`${badge(f.severity)} ${c("1", f.title)}  ${c("90", f.rule)}`);
    lines.push(`   ${c("90", f.file + ":" + f.line)}`);
    if (f.snippet) lines.push(`   ${c("90", "› ")}${f.snippet}`);
    lines.push(`   ${c("90", f.remediation)}`);
    lines.push("");
  }
  const ct = counts(findings);
  const summary = SEVERITY_ORDER.slice().reverse().filter((s) => ct[s]).map((s) => `${ct[s]} ${s}`).join(", ");
  lines.push(c("1", `  ${findings.length} finding${findings.length === 1 ? "" : "s"}: `) + summary);
  lines.push("");
  return lines.join("\n");
}

export function jsonReport(result) {
  return JSON.stringify({
    tool: "skill-audit",
    skill: result.skillName,
    filesScanned: result.files,
    skipped: result.skipped ?? [],
    summary: counts(result.findings),
    findings: result.findings,
  }, null, 2);
}

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

export function sarifReport(result) {
  const findings = result.findings;
  const ruleIds = [...new Set(findings.map((f) => f.rule))];
  const rules = ruleIds.map((id) => {
    const f = findings.find((x) => x.rule === id);
    return {
      id,
      name: id.replace(/-/g, ""),
      shortDescription: { text: f.title },
      fullDescription: { text: f.remediation },
      defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
      properties: { category: f.category, severity: f.severity },
    };
  });
  const results = findings.map((f) => ({
    ruleId: f.rule,
    level: SARIF_LEVEL[f.severity],
    message: { text: `${f.title} — ${f.remediation}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.file },
        region: { startLine: f.line, snippet: { text: f.snippet } },
      },
    }],
    properties: { severity: f.severity, category: f.category },
  }));
  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "skill-audit", informationUri: "https://github.com/AgentPostmortem/skill-audit", rules } },
      results,
    }],
  }, null, 2);
}

/** exit code: 1 if any finding is >= failOn severity or any file was skipped, else 0. */
export function exitCode(findings, failOn, skipped = []) {
  if (skipped.length) return 1;
  const threshold = sevRank(failOn);
  return findings.some((f) => sevRank(f.severity) >= threshold) ? 1 : 0;
}
