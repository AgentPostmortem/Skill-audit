// Walk a skill (a directory or a single SKILL.md), read its text files, and run the rules.
import { closeSync, existsSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { join, extname, basename, relative } from "node:path";
import { RULES, matchesOf } from "./rules.js";

const CODE_EXT = new Set([".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".psm1"]);
const TEXT_EXT = new Set([".md", ".markdown", ".mdx", ".txt", ".json", ".yaml", ".yml", ".toml"]);
const SKIP_DIR = new Set([".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"]);
const MAX_BYTES = 2_000_000;

function hasShebang(file) {
  try {
    const fd = openSync(file, "r");
    try {
      const header = Buffer.alloc(64);
      const bytesRead = readSync(fd, header, 0, header.length, 0);
      return bytesRead >= 2 && header[0] === 0x23 && header[1] === 0x21;
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
}

/** Collect scannable files from a path (file or dir). */
export function collectFiles(target) {
  const out = [];
  const st = existsSync(target) ? statSync(target) : null;
  if (!st) return out;
  if (st.isFile()) {
    const name = basename(target);
    const e = extname(name).toLowerCase();
    if (CODE_EXT.has(e) || TEXT_EXT.has(e) || (e === "" && hasShebang(target))) out.push(target);
    return out;
  }
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIR.has(name)) continue;
      const p = join(dir, name);
      const s = statSync(p);
      if (s.isDirectory()) walk(p);
      else if (s.isFile()) {
        const e = extname(name).toLowerCase();
        if (CODE_EXT.has(e) || TEXT_EXT.has(e) || (e === "" && hasShebang(p))) out.push(p);
      }
    }
  };
  walk(target);
  return out;
}

const lineAt = (text, index) => text.slice(0, index).split("\n").length;
const snippetAt = (text, index) => {
  const start = text.lastIndexOf("\n", index) + 1;
  let end = text.indexOf("\n", index);
  if (end === -1) end = text.length;
  return text.slice(start, end).trim().slice(0, 160);
};

const isMarkdown = (file) => [".md", ".markdown", ".mdx"].includes(extname(file).toLowerCase());
const isProseFile = (file) => {
  const e = extname(file).toLowerCase();
  return isMarkdown(file) || e === ".txt" || e === ".yaml" || e === ".yml";
};
const isCode = (file) => CODE_EXT.has(extname(file).toLowerCase());

/** Ranges of fenced code blocks inside markdown, so "code" rules also fire on them. */
function codeBlockRanges(text) {
  const ranges = [];
  let pos = 0;
  while (pos < text.length) {
    const open = text.indexOf("```", pos);
    if (open === -1) break;
    const lineEnd = text.indexOf("\n", open);
    if (lineEnd === -1) break;
    const contentStart = lineEnd + 1;
    const close = text.indexOf("```", contentStart);
    const end = close === -1 ? text.length : close + 3;
    ranges.push([open, end]);
    pos = end;
  }
  return ranges;
}
const inRanges = (i, ranges) => ranges.some(([a, b]) => i >= a && i < b);

function ruleApplies(rule, { proseFile }) {
  if (rule.appliesTo === "any") return true;
  if (rule.appliesTo === "prose") return proseFile;
  if (rule.appliesTo === "code") return true; // code rules run on scripts AND md code blocks
  return false;
}

/** Scan one file's text and return findings. */
export function scanText(text, file, root) {
  const findings = [];
  const markdown = isMarkdown(file);
  const proseFile = isProseFile(file);
  const blocks = markdown ? codeBlockRanges(text) : null;
  const rel = root ? relative(root, file) || basename(file) : file;

  for (const rule of RULES) {
    if (!ruleApplies(rule, { proseFile })) continue;
    const hits = rule.pattern ? matchesOf(text, rule.pattern) : rule.detect(text);
    for (const h of hits) {
      // "code" rules inside a markdown file only count within fenced code blocks
      if (rule.appliesTo === "code" && markdown && !inRanges(h.index, blocks)) continue;
      // "prose" rules skip fenced code (they target instructions, not commands) -- markdown only
      if (rule.appliesTo === "prose" && markdown && inRanges(h.index, blocks)) continue;
      findings.push({
        rule: rule.id, severity: rule.severity, category: rule.category, title: rule.title,
        remediation: rule.remediation, file: rel, line: lineAt(text, h.index),
        snippet: snippetAt(text, h.index),
      });
    }
  }
  return findings;
}

function relPath(file, root) {
  return root ? relative(root, file) || basename(file) : file;
}

/** Scan a skill target (dir or file). Returns { findings, files, skillName, skipped }. */
export function scanSkill(target) {
  const root = existsSync(target) && statSync(target).isDirectory() ? target : null;
  const files = collectFiles(target);
  const findings = [];
  const skipped = [];
  let scanned = 0;
  for (const f of files) {
    const rel = relPath(f, root);
    let text;
    try {
      const size = statSync(f).size;
      if (size > MAX_BYTES) {
        skipped.push({ file: rel, reason: "oversized", size });
        continue;
      }
      text = readFileSync(f, "utf8");
    } catch {
      skipped.push({ file: rel, reason: "unreadable" });
      continue;
    }
    scanned++;
    findings.push(...scanText(text, f, root));
  }
  findings.sort((a, b) =>
    sevRank(b.severity) - sevRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  return { findings, files: scanned, skillName: detectName(target, files), skipped };
}

function detectName(target, files) {
  const skill = files.find((f) => basename(f).toLowerCase() === "skill.md");
  if (skill) {
    try {
      const m = readFileSync(skill, "utf8").match(/^\s*name\s*:\s*(.+)$/mi);
      if (m) return m[1].trim().replace(/^["']|["']$/g, "");
    } catch { /* ignore */ }
  }
  return basename(target.replace(/\/+$/, "")) || target;
}

import { SEVERITY_ORDER } from "./rules.js";
export const sevRank = (s) => SEVERITY_ORDER.indexOf(s);
