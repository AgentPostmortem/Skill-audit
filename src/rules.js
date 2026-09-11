// Rule catalogue for skill-audit.
// Each rule: { id, severity, category, title, appliesTo, remediation, pattern? , detect? }
//  - appliesTo: "prose" (markdown text), "code" (scripts + md code blocks), or "any"
//  - pattern: a global RegExp; every match becomes a finding
//  - detect: (text) => [{ index, match }]  for checks a single regex can't express
//
// Severity ladder: critical > high > medium > low > info

export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];

const ZERO_WIDTH = /[​‌‍﻿⁠‪-‮⁦-⁩]/g;

export const RULES = [
  // ---- Prompt injection / instruction override hidden in the skill's prose ----
  { id: "SKILL-INJ-001", severity: "high", category: "prompt-injection", appliesTo: "prose",
    title: "Instruction override ('ignore previous instructions')",
    remediation: "A skill should describe a capability, not tell the agent to discard its own rules.",
    pattern: /ignore\s+(all\s+|any\s+)?(the\s+)?(prior|previous|above|earlier)\s+(instructions|rules|prompts|guidelines)/gi },

  { id: "SKILL-INJ-002", severity: "high", category: "prompt-injection", appliesTo: "prose",
    title: "Directs the agent to hide activity from the user",
    remediation: "Skills must not instruct the agent to conceal what it does from the user.",
    // [^.]{0,25} (not [^.\n]) so a line-wrapped "do not tell the\nuser" is still caught.
    pattern: /(do\s*not|don'?t|never)\s+(tell|inform|show|reveal|mention|notify|alert)\b[^.]{0,25}\buser/gi },

  { id: "SKILL-INJ-003", severity: "high", category: "prompt-injection", appliesTo: "prose",
    title: "Instructs the agent to act without confirmation",
    remediation: "Destructive or sensitive actions should keep a human confirmation step; a skill removing it is a red flag.",
    pattern: /(without\s+(asking|confirmation|permission|approval)|do\s*not\s+ask|no\s+need\s+to\s+(ask|confirm)|skip\s+(the\s+)?confirmation)/gi },

  { id: "SKILL-INJ-004", severity: "medium", category: "prompt-injection", appliesTo: "prose",
    title: "Tells the agent to disable or bypass safety",
    remediation: "Legit skills never ask the agent to turn off guardrails, moderation, or security checks.",
    pattern: /(disable|bypass|turn\s+off|ignore|override)\b[^.\n]{0,25}(safety|guardrail|security|moderation|filter|policy)/gi },

  { id: "SKILL-INJ-005", severity: "critical", category: "prompt-injection", appliesTo: "any",
    title: "Stated intent to exfiltrate secrets",
    remediation: "The skill text describes sending secrets/tokens/credentials somewhere. Treat as malicious until proven otherwise.",
    pattern: /(exfiltrate|leak|send|upload|post|forward)\b[^.\n]{0,30}(secret|token|password|credential|private\s*key|api[\s_-]?key|\.env)/gi },

  { id: "SKILL-INJ-006", severity: "high", category: "obfuscation", appliesTo: "any",
    title: "Hidden zero-width or bidirectional Unicode",
    remediation: "Invisible characters are used to smuggle instructions past human review. Remove them.",
    detect: (t) => matchesOf(t, ZERO_WIDTH) },

  { id: "SKILL-INJ-007", severity: "medium", category: "prompt-injection", appliesTo: "prose",
    title: "Auto-run / always-execute directive",
    remediation: "A skill should run on demand, not command the agent to always/automatically execute things.",
    pattern: /(always|automatically|on\s+every\s+(message|turn|request))\s+(run|execute|invoke|call)\b/gi },

  // ---- Dangerous shell ----
  { id: "SKILL-SH-001", severity: "critical", category: "dangerous-shell", appliesTo: "code",
    title: "Recursive force-delete of a broad path",
    remediation: "rm -rf against /, $HOME, or ~ can wipe a machine. Never ship this in a skill.",
    pattern: /\brm\s+-[a-z]*[rf][a-z]*\s+[^\n]*(\s\/(\s|$)|\s~(\/|\s|$)|\$HOME|\/\*)/gi },

  { id: "SKILL-SH-002", severity: "critical", category: "dangerous-shell", appliesTo: "code",
    title: "Pipe a download straight into a shell",
    remediation: "curl|sh / wget|bash runs unreviewed remote code. Download, inspect, then run.",
    pattern: /(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|node)\b/gi },

  { id: "SKILL-SH-003", severity: "medium", category: "dangerous-shell", appliesTo: "code",
    title: "Privilege escalation via sudo, doas, or run0",
    remediation: "A skill running sudo, doas, or run0 can change the whole system. Confirm it is truly required.",
    pattern: /(^|[\s;&|(])(?:sudo|doas|run0)\s+/gm },

  { id: "SKILL-SH-004", severity: "critical", category: "dangerous-shell", appliesTo: "code",
    title: "Fork bomb",
    remediation: "This pattern exhausts the process table and hangs the machine.",
    pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/g },

  { id: "SKILL-SH-005", severity: "high", category: "dangerous-shell", appliesTo: "code",
    title: "World-writable permissions (chmod 777)",
    remediation: "chmod 777 removes all access control on the target. Use least privilege.",
    pattern: /\bchmod\s+(-R\s+)?0?777\b/gi },

  { id: "SKILL-SH-006", severity: "critical", category: "dangerous-shell", appliesTo: "code",
    title: "Raw disk / device write",
    remediation: "dd, mkfs, or writing to /dev/sd* can destroy data irreversibly.",
    pattern: /(\bdd\s+if=|\bmkfs\b|>\s*\/dev\/(sd|nvme|disk))/gi },

  { id: "SKILL-SH-007", severity: "high", category: "dangerous-shell", appliesTo: "code",
    title: "Reverse shell / raw TCP",
    remediation: "nc -e, /dev/tcp, or bash -i piped to a socket opens a backdoor.",
    pattern: /(\bnc\b\s+[^\n]*-e|\/dev\/tcp\/|bash\s+-i\b[^\n]*(>&|\|))/gi },

  // ---- Secrets & credentials ----
  { id: "SKILL-SEC-001", severity: "high", category: "secret-access", appliesTo: "any",
    title: "Reads SSH / private keys",
    remediation: "Accessing id_rsa, .pem, or ~/.ssh is rarely legitimate for a skill.",
    pattern: /(\.ssh\/id_[a-z0-9]+|\bid_rsa\b|-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----|\.pem\b)/gi },

  { id: "SKILL-SEC-002", severity: "high", category: "secret-access", appliesTo: "any",
    title: "Reads cloud / package credential files",
    remediation: "~/.aws/credentials, .npmrc, .netrc, .git-credentials hold live secrets.",
    pattern: /(\.aws\/credentials|\.docker\/config\.json|\.npmrc\b|\.git-credentials|\.netrc\b|\.kube\/config)/gi },

  { id: "SKILL-SEC-003", severity: "medium", category: "secret-access", appliesTo: "code",
    title: "Dumps the full environment / dotenv",
    remediation: "printenv, os.environ, or reading .env wholesale often precedes exfiltration.",
    pattern: /(\bprintenv\b|os\.environ\b(?!\.get)|os\.getenv\s*\(|process\.env\b|\bdotenv\b|(cat|source|read|open)\s+[^\n]*\.env\b)/gi },

  { id: "SKILL-SEC-004", severity: "medium", category: "secret-access", appliesTo: "code",
    title: "Accesses the OS keychain / secret store",
    remediation: "Reading the keychain, keyring, or secret-tool exposes stored credentials.",
    pattern: /(security\s+find-generic-password|gnome-keyring|\bsecret-tool\b|keychain)/gi },

  // ---- Network exfiltration ----
  { id: "SKILL-NET-001", severity: "high", category: "exfiltration", appliesTo: "code",
    title: "Uploads a local file over the network",
    remediation: "curl --data @file / -T / upload-file sends local data out. Verify the destination.",
    pattern: /(curl|wget)\b[^\n]*(--data(-binary)?|-d|-F|--form|--upload-file|-T)\s+[^\n]*@/gi },

  { id: "SKILL-NET-002", severity: "high", category: "exfiltration", appliesTo: "any",
    title: "Contacts a known exfiltration / paste host",
    remediation: "webhook.site, requestbin, ngrok, pastebin, transfer.sh and raw IPs are common drop points.",
    pattern: /(webhook\.site|requestbin\.|\.ngrok\.|pastebin\.com|transfer\.sh|0x0\.st|https?:\/\/(\d{1,3}\.){3}\d{1,3})/gi },

  { id: "SKILL-NET-003", severity: "medium", category: "exfiltration", appliesTo: "code",
    title: "Programmatic outbound POST",
    remediation: "requests.post / fetch / axios.post to an external host can be a data sink. Confirm the endpoint.",
    pattern: /(requests\.post|urllib\.request|http\.client|fetch\s*\(|axios\.(post|put)|new\s+XMLHttpRequest)/gi },

  // ---- Supply chain ----
  { id: "SKILL-SUP-001", severity: "medium", category: "supply-chain", appliesTo: "code",
    title: "Installs arbitrary packages at runtime",
    remediation: "Runtime pip/npm/gem/cargo installs pull unpinned code onto the host. Pin and vet dependencies.",
    pattern: /(pip[0-9]?\s+install|npm\s+i(nstall)?\b|pnpm\s+add|yarn\s+add|gem\s+install|go\s+install|cargo\s+install|npx\s+--yes)/gi },

  { id: "SKILL-SUP-002", severity: "high", category: "supply-chain", appliesTo: "code",
    title: "Clones and immediately executes a repo",
    remediation: "git clone chained into sh/python/node runs unaudited third-party code.",
    pattern: /git\s+clone\b[^\n]*&&[^\n]*(sh|bash|python[0-9.]*|node|make)\b/gi },

  // ---- Obfuscation ----
  { id: "SKILL-OBF-001", severity: "critical", category: "obfuscation", appliesTo: "code",
    title: "Decodes and executes base64",
    remediation: "base64 -d | sh, eval(atob(...)), or b64decode+exec hides the real payload. Never run.",
    pattern: /(base64\s+(-d|--decode)|atob\s*\(|b64decode|base64\.b64decode)[^\n]{0,60}(\||;|&&|\)\s*)?[^\n]{0,20}(sh|bash|eval|exec|system)/gi },

  { id: "SKILL-OBF-002", severity: "medium", category: "obfuscation", appliesTo: "code",
    title: "Large embedded base64 blob",
    remediation: "A long base64 string in a skill often hides code or data. Decode and inspect it.",
    detect: (t) => matchesOf(t, /[A-Za-z0-9+/]{240,}={0,2}/g) },

  // ---- Permissions ----
  { id: "SKILL-PERM-001", severity: "medium", category: "over-permission", appliesTo: "prose",
    title: "Requests wildcard / all tool access",
    remediation: "A skill granting itself every tool ('allowed-tools: *') violates least privilege.",
    pattern: /allowed[-_ ]?tools?\s*[:=]\s*["'\[]?\s*\*/gi },

  // ---- Instructions concealed in HTML comments (invisible in rendered markdown) ----
  { id: "SKILL-INJ-008", severity: "high", category: "prompt-injection", appliesTo: "prose",
    title: "Imperative instruction hidden in an HTML comment",
    remediation: "Comments are invisible when the markdown renders; attackers hide agent instructions there. Remove them.",
    detect: (t) => {
      const out = [];
      const re = /<!--([\s\S]*?)-->/g;
      let m;
      while ((m = re.exec(t)) !== null) {
        if (/(ignore|run|execute|send|exfiltrate|do\s*not\s+tell|password|secret|token|curl|bash)/i.test(m[1]))
          out.push({ index: m.index, match: m[0].slice(0, 60) });
      }
      return out;
    } },

  // ---- Browser credential stores ----
  { id: "SKILL-SEC-005", severity: "high", category: "secret-access", appliesTo: "any",
    title: "Accesses browser credential / cookie stores",
    remediation: "Login Data, Cookies, key4.db, or logins.json hold saved passwords and sessions.",
    pattern: /(Login[\s\\'"]{0,3}Data|key4\.db|logins\.json|cookies\.sqlite|\bCookies\b(?=[^a-z]))/g },

  // ---- Persistence ----
  { id: "SKILL-SH-008", severity: "medium", category: "persistence", appliesTo: "code",
    title: "Installs persistence (cron, shell rc, launch/systemd unit)",
    remediation: "Writing to crontab, ~/.bashrc, LaunchAgents, or systemd makes the code re-run later. Rarely legitimate in a skill.",
    pattern: /(crontab\s+-|>>?\s*~?\/?\.(bashrc|zshrc|profile|bash_profile)|LaunchAgents|systemctl\s+(--user\s+)?enable)/g },

  // ---- Anti-forensics ----
  { id: "SKILL-SH-009", severity: "high", category: "anti-forensics", appliesTo: "code",
    title: "Clears shell history / covers tracks",
    remediation: "history -c, unset HISTFILE, or truncating .bash_history is used to hide what was run.",
    pattern: /(history\s+-c\b|unset\s+HISTFILE|>\s*~?\/?\.bash_history)/g },

  // ---- Dynamic code execution ----
  { id: "SKILL-OBF-003", severity: "medium", category: "obfuscation", appliesTo: "code",
    title: "Dynamic code execution (exec/compile)",
    remediation: "exec()/compile() of runtime-built strings hides behaviour from a reader. Prefer explicit code.",
    pattern: /\b(exec|compile)\s*\(\s*[^)'"\s]/g },
];

function matchesOf(text, re) {
  const out = [];
  let m;
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  while ((m = g.exec(text)) !== null) {
    out.push({ index: m.index, match: m[0] });
    if (m.index === g.lastIndex) g.lastIndex++;
  }
  return out;
}

export { matchesOf };
