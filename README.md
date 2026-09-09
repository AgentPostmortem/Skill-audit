# skill-audit

**A security scanner for agent skills.** Scan a Claude/agent Skill for prompt-injection, dangerous shell, secret access, and network exfiltration **before you trust it** — one command, zero dependencies, SARIF output for CI.

```bash
npx @royalpinto007/skill-audit ./path-to-skill
```

[![npm](https://img.shields.io/npm/v/@royalpinto007/skill-audit.svg)](https://www.npmjs.com/package/@royalpinto007/skill-audit) [![CI](https://github.com/AgentPostmortem/Skill-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentPostmortem/Skill-audit/actions) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
**npm:** https://www.npmjs.com/package/@royalpinto007/skill-audit  ·  **Source:** https://github.com/AgentPostmortem/Skill-audit

---

## Why

Agent **skills** are the new plugin. A skill is a `SKILL.md` plus scripts that an agent will **read as instructions and execute** — and people install them from GitHub, gists, and marketplaces with zero review. That is an unguarded supply chain: a skill can quietly tell the agent to *ignore its own rules*, `curl | bash` a payload, read your `~/.ssh` keys, or POST your `.env` to a webhook, and nothing checks for it.

`skill-audit` is `npm audit` for skills. Point it at a skill and it flags the patterns that should stop you from installing it.

## What it catches

| Category | Examples |
| --- | --- |
| **Prompt injection** | "ignore all previous instructions", "do not tell the user", "act without confirmation", disable/bypass safety, stated intent to exfiltrate |
| **Dangerous shell** | `rm -rf ~`, `curl \| bash`, fork bombs, `chmod 777`, `dd`/`mkfs`, reverse shells |
| **Secret access** | reads `~/.ssh/id_rsa`, `~/.aws/credentials`, `.npmrc`, `.netrc`, dumps the environment, hits the keychain |
| **Exfiltration** | uploads local files, contacts `webhook.site` / `pastebin` / ngrok / raw IPs, programmatic outbound POST |
| **Supply chain** | runtime `pip`/`npm` installs, `git clone && run` |
| **Obfuscation** | `base64 -d \| sh`, large base64 blobs, hidden zero-width / bidi Unicode |
| **Over-permission** | `allowed-tools: *` |

It reads `SKILL.md` **prose** for instruction-injection and reads **scripts and fenced code blocks** for dangerous commands — so a `chmod 777` mentioned in a sentence won't false-positive, but the same command in a code block will.

Directory scans include `.bat`, `.cmd`, `.fish`, and `.psm1` scripts alongside the other supported script and text formats. Extensions are matched case-insensitively, including in nested directories.

See every rule: `npx @royalpinto007/skill-audit --rules`.

## Usage

```bash
npx @royalpinto007/skill-audit <path> [options]

# scan a skill directory
npx @royalpinto007/skill-audit ~/.claude/skills/some-skill

# fail CI on anything medium or worse
npx @royalpinto007/skill-audit ./my-skill --fail-on medium

# machine-readable output
npx @royalpinto007/skill-audit ./my-skill --format json
npx @royalpinto007/skill-audit ./my-skill --format sarif > skill-audit.sarif
```

**Options**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format <text\|json\|sarif>` | `text` | output format |
| `--fail-on <severity>` | `high` | exit `1` if any finding is at or above this severity |
| `--rules` | | list every rule and exit |
| `-h, --help` / `-v, --version` | | |

**Exit codes:** `0` clean (below threshold) · `1` findings at/above `--fail-on` · `2` bad usage.

Unknown options are rejected with exit code `2` before scanning, so a misspelled flag cannot silently change the scan.

## In CI (GitHub Action)

One line — drop it into any workflow. It gates the job and can upload findings to the Security tab:

```yaml
name: skill-audit
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AgentPostmortem/skill-audit@v1
        with:
          path: ./skills          # default "."
          fail-on: high           # critical|high|medium|low|info
          sarif-file: skill-audit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: skill-audit.sarif
```

Prefer the raw CLI? `npx @royalpinto007/skill-audit ./skills --fail-on high` works the same in any pipeline.

## What it is (and isn't)

- It's a **fast static heuristic** — a first line of defense that catches the obvious and the sneaky-but-known. Green is not a proof of safety; **read skills you run.**
- It has **no runtime dependencies** — a security tool shouldn't pull a supply chain of its own.
- False positives are possible by design (it errs toward flagging). Tune with `--fail-on`.

## Related

Part of a small agent-security toolkit: [mcp-audit](https://github.com/AgentPostmortem/MCP-audit) (scan MCP servers), [injection-arena](https://github.com/AgentPostmortem/injection-arena) (learn prompt-injection defense), and the [awesome-llm-guardrails](https://github.com/royalpinto007/awesome-llm-guardrails) list.

## License

MIT
