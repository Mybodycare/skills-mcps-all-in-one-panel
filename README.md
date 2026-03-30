# Skill Panel

All-in-one panel to explore, audit and install **Claude Code skills** and **MCP servers**.

One command. Works on Mac and Windows.

```
npx skill-panel
```

## What it does

- **Explore** skills from GitHub — search, preview, read the SKILL.md
- **Security scan** every skill before installing (37 checks across 9 categories)
- **Install** skills directly to `~/.claude/skills/`
- **Install MCPs** with one click — paste your API key, done
- **See everything** you have installed: skills, MCPs, dependencies
- **Cross-platform** — Windows (winget) and macOS (brew) support

## Security Scanner

The scanner is based on **real documented attacks**, not theoretical patterns:

| Category | Checks | Based on |
|----------|--------|----------|
| Shell & RCE | 6 | CVE-2025-59536, ClawHavoc reverse shells |
| Data Exfiltration | 5 | CVE-2025-55284 (DNS exfil), postmark-mcp (BCC hijack) |
| Prompt Injection | 5 | arXiv study (36% of skills), tool poisoning |
| Malware & Persistence | 5 | MedusaLocker via skills, AMOS stealer |
| Supply Chain | 4 | postmark-mcp, mcp-remote CVE-2025-6514 |
| Classic Injection | 3 | mcp-server-git CVE-2025-68143/44/45 |
| Obfuscation | 3 | Invisible chars, hex encoding |
| Credentials | 3 | Hardcoded API keys (sk-, ghp_, AKIA...) |
| MCP Specific | 3 | Supabase trifecta, tool description manipulation |

**37 checks total.** Blocks installation if critical threats are found.

Smart filtering: excludes `vendor/`, `node_modules/`, `tests/`, `docs/` to reduce false positives.

## MCP Installation

The panel includes a catalog of popular MCP servers. For MCPs that need credentials:

1. Click "Install"
2. Follow the link to get your API key/token
3. Paste it in the input field
4. Click "Install" — the panel writes the config to `~/.claude.json` automatically

No manual file editing needed.

**Included MCPs:** GitHub, Slack, Notion, Supabase, PostgreSQL, Brave Search, Puppeteer, Memory, Google Maps, Filesystem.

## First Run

On first launch, the panel automatically:

1. Creates `~/.claude/skills/` if it doesn't exist
2. Adds a reference to `~/.claude/CLAUDE.md`
3. Checks system dependencies

## Requirements

- Node.js 18+
- That's it. Zero npm dependencies.

## Development

```bash
git clone https://github.com/nilsbonfill/skill-panel
cd skill-panel
npm test     # 161 security scanner tests
npm start    # launch locally
```

## Project Structure

```
skill-panel/
  bin/skill-panel.js       CLI entry point (npx skill-panel)
  lib/
    security-scanner.js    37 checks, shared between frontend and tests
    server.js              Node.js HTTP server
    mcp-installer.js       MCP catalog + auto-config to ~/.claude.json
    installer.js           Skill install/list/uninstall
    discovery.js           Auto-discover installed skills & MCPs
    deps.js                System dependency check (winget/brew)
    github-proxy.js        GitHub API proxy (avoids CORS)
    setup.js               First-run wizard
    platform.js            Cross-platform utilities
  public/
    index.html             Single-page frontend
  test/
    security-scanner.test.js   161 tests based on real CVEs
```

## Why

The AI agent ecosystem has a real security problem:

- **1,184 malicious skills** found on ClawHub (Feb 2026)
- **postmark-mcp**: malicious npm package that BCC'd every email to an attacker
- **CVE-2025-55284**: data exfiltration via DNS from Claude Code
- **84.2%** success rate for tool poisoning attacks with auto-approval
- **82%** of MCP implementations vulnerable to path traversal

This tool exists so you can see what you have, find what you need, and verify it's not going to steal your data.

## License

MIT
