// skill-audit CLI: parse args, scan, print, set exit code.
import { existsSync } from "node:fs";
import { scanSkill } from "./scan.js";
import { textReport, jsonReport, sarifReport, exitCode, formatSkippedWarnings } from "./report.js";
import { RULES, SEVERITY_ORDER } from "./rules.js";

const HELP = `skill-audit — a security scanner for agent skills

  Scans a Claude/agent Skill (SKILL.md + its scripts) for security risks before
  you trust it: prompt-injection hidden in the prose, dangerous shell, secret and
  credential access, network exfiltration, obfuscation, and over-broad permissions.

USAGE
  skill-audit <path> [options]

ARGUMENTS
  <path>                 A skill directory or a single SKILL.md (default: ".")

OPTIONS
  --format <fmt>         text | json | sarif            (default: text)
  --fail-on <severity>   critical|high|medium|low|info  (default: high)
                         exit 1 if any finding is at or above this severity
  --rules                list every rule and exit
  -h, --help             show this help
  -v, --version          show version

EXAMPLES
  npx skill-audit ./my-skill
  npx skill-audit ./my-skill --format sarif > skill-audit.sarif
  npx skill-audit ~/.claude/skills/some-skill --fail-on medium
`;

function parseArgs(argv) {
  const opts = { path: null, format: "text", failOn: "high", help: false, version: false, rules: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--rules") opts.rules = true;
    else if (a === "--format") opts.format = argv[++i];
    else if (a === "--fail-on") opts.failOn = argv[++i];
    else if (a.startsWith("--format=")) opts.format = a.split("=")[1];
    else if (a.startsWith("--fail-on=")) opts.failOn = a.split("=")[1];
    else if (!a.startsWith("-")) {
      if (opts.path !== null) return { error: "skill-audit: only one path is supported; scan each target separately\n" };
      opts.path = a;
    }
    else return { error: `skill-audit: unknown option "${a}"\n` };
  }
  return opts;
}

export function run(argv, { version }) {
  const o = parseArgs(argv);
  if (o.error) { process.stderr.write(o.error); return 2; }
  if (o.help) { process.stdout.write(HELP); return 0; }
  if (o.version) { process.stdout.write(version + "\n"); return 0; }
  if (o.rules) {
    for (const r of RULES) process.stdout.write(`${r.id}  [${r.severity}]  ${r.category} — ${r.title}\n`);
    return 0;
  }
  if (!["text", "json", "sarif"].includes(o.format)) {
    process.stderr.write(`skill-audit: unknown --format "${o.format}"\n`); return 2;
  }
  if (!SEVERITY_ORDER.includes(o.failOn)) {
    process.stderr.write(`skill-audit: unknown --fail-on "${o.failOn}"\n`); return 2;
  }
  const target = o.path || ".";
  if (!existsSync(target)) { process.stderr.write(`skill-audit: path not found: ${target}\n`); return 2; }

  const result = scanSkill(target);
  const skipped = result.skipped ?? [];
  if (skipped.length) process.stderr.write(formatSkippedWarnings(skipped));
  if (o.format === "json") process.stdout.write(jsonReport(result) + "\n");
  else if (o.format === "sarif") process.stdout.write(sarifReport(result) + "\n");
  else process.stdout.write(textReport(result));

  return exitCode(result.findings, o.failOn, skipped);
}
