'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { getSkillsPath, getClaudeMdPath, getClaudeJsonPath, getMcpJsonPath } = require('./platform');
const { checkSystemDeps } = require('./deps');

const MARKER = '<!-- skill-panel -->';

function isFirstRun() {
  const claudeMdPath = getClaudeMdPath();
  if (!fs.existsSync(claudeMdPath)) return true;
  const content = fs.readFileSync(claudeMdPath, 'utf-8');
  return !content.includes(MARKER);
}

function runSetup() {
  const skillsPath = getSkillsPath();

  console.log('');
  console.log('  Configurando Skill Panel...');
  console.log('');

  // 1. Create ~/.claude/skills/
  fs.mkdirSync(skillsPath, { recursive: true });
  console.log(`  ✅ Skills en: ${skillsPath}`);

  // 2. Consolidate MCPs from multiple locations into ~/.claude.json
  consolidateMCPs();

  // 3. Inject smart skill-routing into CLAUDE.md
  injectClaudeMd();

  // 4. Quick dep check
  const deps = checkSystemDeps();
  const missing = Object.entries(deps)
    .filter(([k, v]) => k !== '_platform' && !v.installed)
    .map(([k]) => k);
  if (missing.length) {
    console.log(`  ⚠️  Deps opcionales faltantes: ${missing.join(', ')}`);
  }

  console.log('  ✅ Setup completado.');
  console.log('');
}

/**
 * Merge MCPs from ~/.claude/.mcp.json into ~/.claude.json
 * so all MCPs are in one place. Keeps .mcp.json intact (no delete).
 */
function consolidateMCPs() {
  const mainPath = getClaudeJsonPath();
  const altPath = getMcpJsonPath();

  let main = {};
  try { main = JSON.parse(fs.readFileSync(mainPath, 'utf-8')); } catch {}
  if (!main.mcpServers) main.mcpServers = {};

  let moved = 0;
  // Read .mcp.json and merge
  try {
    const alt = JSON.parse(fs.readFileSync(altPath, 'utf-8'));
    for (const [name, config] of Object.entries(alt.mcpServers || {})) {
      if (!main.mcpServers[name]) {
        main.mcpServers[name] = config;
        moved++;
      }
    }
  } catch {}

  if (moved > 0) {
    fs.writeFileSync(mainPath, JSON.stringify(main, null, 2), 'utf-8');
    console.log(`  ✅ ${moved} MCP(s) consolidados en ~/.claude.json`);
  }

  const total = Object.keys(main.mcpServers).length;
  console.log(`  📡 ${total} MCPs configurados`);
}

/**
 * Inject a smart skill-routing instruction into ~/.claude/CLAUDE.md
 * This tells Claude to check available skills before answering.
 */
function injectClaudeMd() {
  const claudeMdPath = getClaudeMdPath();

  // Read existing skills to build the routing table
  const skillsPath = getSkillsPath();
  let skillList = [];
  try {
    skillList = fs.readdirSync(skillsPath).filter(name => {
      const dir = path.join(skillsPath, name);
      try { return fs.statSync(dir).isDirectory() && fs.existsSync(path.join(dir, 'SKILL.md')); }
      catch { return false; }
    });
  } catch {}

  const snippet = buildClaudeMdSnippet(skillList);

  if (fs.existsSync(claudeMdPath)) {
    let content = fs.readFileSync(claudeMdPath, 'utf-8');
    if (content.includes(MARKER)) {
      // Replace existing section
      const re = new RegExp(`${MARKER.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}[\\s\\S]*?<!-- /skill-panel -->`, 'm');
      content = content.replace(re, snippet);
    } else {
      content += '\n' + snippet;
    }
    fs.writeFileSync(claudeMdPath, content, 'utf-8');
  } else {
    const dir = path.dirname(claudeMdPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(claudeMdPath, snippet, 'utf-8');
  }
  console.log(`  ✅ CLAUDE.md actualizado (${skillList.length} skills registradas)`);
}

function buildClaudeMdSnippet(skills) {
  const lines = [
    MARKER,
    '## Skills & MCPs — Auto-routing',
    '',
    'Tienes skills especializadas instaladas en `~/.claude/skills/`.',
    'Antes de responder, evalúa si alguna skill aplica al prompt del usuario.',
    '',
    '### Cómo usar las skills',
    '',
    '1. Lee el nombre y descripción de cada skill disponible',
    '2. Si el prompt del usuario encaja con una o varias skills, lee su SKILL.md antes de responder',
    '3. Si ninguna skill aplica, responde normalmente',
    '4. Puedes combinar múltiples skills en una respuesta',
    '',
    '### Skills disponibles',
    '',
  ];

  if (skills.length === 0) {
    lines.push('Ninguna instalada. Usa `npx skill-panel` para instalar skills.');
  } else {
    lines.push('| Skill | Activar cuando |');
    lines.push('|-------|---------------|');

    // Read descriptions from each SKILL.md
    const skillsPath = getSkillsPath();
    for (const name of skills) {
      let desc = '';
      try {
        const content = fs.readFileSync(path.join(skillsPath, name, 'SKILL.md'), 'utf-8');
        const descMatch = content.match(/description:\s*["']?([^"'\n]+)/i);
        if (descMatch) desc = descMatch[1].trim().slice(0, 80);
        if (!desc) {
          const h1 = content.match(/^#\s+(.+)/m);
          if (h1) desc = h1[1].trim().slice(0, 80);
        }
      } catch {}
      lines.push(`| \`${name}\` | ${desc || name} |`);
    }
  }

  lines.push('');
  lines.push('### MCPs disponibles');
  lines.push('');
  lines.push('Los MCPs se cargan automáticamente desde `~/.claude.json`. Usa sus herramientas cuando el usuario lo pida.');
  lines.push('Para gestionar skills y MCPs: `npx skill-panel`');
  lines.push('<!-- /skill-panel -->');

  return lines.join('\n');
}

/**
 * Refresh the CLAUDE.md skill table (called when skills change)
 */
function refreshClaudeMd() {
  injectClaudeMd();
}

module.exports = { isFirstRun, runSetup, refreshClaudeMd, consolidateMCPs };
