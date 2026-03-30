# Skill Panel

> All-in-one panel to explore, audit and install Claude Code skills & MCP servers.
> One command. Zero dependencies. Mac and Windows.

Panel todo-en-uno para Claude Code. Explora, audita y gestiona skills y servidores MCP desde el navegador. Scanner de seguridad con 37 checks basados en CVEs reales (malware, exfiltration, prompt injection). Instala MCPs con un click: pega tu token y listo. Detecta automticamente todo lo instalado. Mac y Windows.

```bash
# Option 1 — directly from GitHub (no npm account needed)
npx github:Mybodycare/skills-mcps-all-in-one-panel

# Option 2 — if published to npm
npx skill-panel
```

That's it. Opens your browser, shows everything you have, lets you find and install more.

---

## Features

### Explore & Install Skills
- Search GitHub for Claude Code skills
- Preview SKILL.md before installing
- One-click install to `~/.claude/skills/`
- Auto-updates `CLAUDE.md` so Claude knows what skills are available

### Security Scanner (37 checks, 9 categories)

Every skill is scanned before installation. The checks are based on **real documented attacks**, not theoretical patterns:

| Category | Checks | Based on |
|----------|--------|----------|
| Shell & RCE | 6 | CVE-2025-59536, ClawHavoc reverse shells |
| Data Exfiltration | 5 | CVE-2025-55284 (DNS exfil), postmark-mcp BCC hijack |
| Prompt Injection | 5 | arXiv study (36% of skills had PI), tool poisoning |
| Malware & Persistence | 5 | MedusaLocker via skills, AMOS stealer |
| Supply Chain | 4 | postmark-mcp, mcp-remote CVE-2025-6514, typosquatting |
| Classic Injection | 3 | mcp-server-git CVE-2025-68143/44/45 |
| Obfuscation | 3 | Invisible characters, hex encoding, string splitting |
| Credentials | 3 | Hardcoded API keys (sk-, ghp_, AKIA...) |
| MCP Specific | 3 | Supabase trifecta, tool description manipulation |

- **Critical threats block installation** (button disabled, details shown)
- **Smart filtering**: excludes `vendor/`, `node_modules/`, `tests/`, `docs/` to reduce false positives
- **161 tests** covering real attack payloads + false positive verification

### MCP Installation (the missing piece)

Other tools tell you "edit settings.json manually". This one doesn't.

1. Click **Install** on any MCP
2. Follow the link to get your API key/token
3. **Paste it in the input field**
4. Click **Install** — config is written to `~/.claude.json` automatically

No manual file editing. No JSON typos. No "where do I paste this token?".

**Built-in catalog:** GitHub, Slack, Notion, Supabase, PostgreSQL, Brave Search, Puppeteer, Memory, Google Maps, Filesystem.

### Auto-discovery

The panel reads your system and shows you **everything** in one place:
- Skills installed in `~/.claude/skills/`
- MCPs configured in `~/.claude.json` and `~/.claude/.mcp.json`
- System dependencies (Node.js, Python, Git, Bun, FFmpeg...)

### Smart Setup (first run)

On first launch, the panel automatically:

1. Creates `~/.claude/skills/` if needed
2. **Consolidates MCPs** — merges scattered configs into one file
3. **Generates a skill routing table** in `~/.claude/CLAUDE.md`
4. **Instructs Claude** to evaluate available skills before every response

This means Claude will **automatically use your installed skills** when they're relevant to what you're asking.

---

## Why this exists

The AI agent ecosystem has a real security problem:

- **1,184 malicious skills** found on ClawHub (Feb 2026)
- **postmark-mcp**: npm package that silently BCC'd every email to an attacker
- **CVE-2025-55284**: data exfiltration via DNS from Claude Code
- **84.2%** success rate for tool poisoning attacks with auto-approval
- **82%** of MCP implementations vulnerable to path traversal
- **30+ CVEs in 60 days** targeting MCP servers (early 2026)

Skills and MCPs are powerful. But installing them blindly is like running random executables from the internet. This tool exists so you can **see what you have, find what you need, and verify it won't steal your data**.

---

## Requirements

- Node.js 18+
- That's it. **Zero npm dependencies.**

## Development

```bash
git clone https://github.com/Mybodycare/skills-mcps-all-in-one-panel
cd skill-panel
npm test     # 161 security scanner tests
npm start    # launch locally
```

## Project Structure

```
skill-panel/
  bin/skill-panel.js          CLI entry point (npx skill-panel)
  lib/
    security-scanner.js       37 checks — shared between frontend and tests
    server.js                 Node.js HTTP server (injects scanner into HTML)
    mcp-installer.js          MCP catalog + auto-config to ~/.claude.json
    installer.js              Skill install/list/uninstall
    discovery.js              Auto-discover installed skills & MCPs
    deps.js                   System dependency check (winget/brew)
    github-proxy.js           GitHub API proxy (avoids CORS)
    setup.js                  First-run wizard + CLAUDE.md generation
    platform.js               Cross-platform path utilities
  public/
    index.html                Single-page frontend (98KB, no framework)
  test/
    security-scanner.test.js  161 tests based on real CVEs
```

## License

MIT
