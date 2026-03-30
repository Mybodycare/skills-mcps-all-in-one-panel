'use strict';
const fs = require('fs');
const path = require('path');
const { getSkillsPath, getClaudeMdPath } = require('./platform');
const { checkSystemDeps } = require('./deps');

const MARKER = '<!-- skill-panel -->';

function isFirstRun() {
  return !fs.existsSync(getSkillsPath());
}

function runSetup() {
  const skillsPath = getSkillsPath();

  console.log('');
  console.log('  Primera ejecución detectada. Configurando...');
  console.log('');

  // 1. Create ~/.claude/skills/
  fs.mkdirSync(skillsPath, { recursive: true });
  console.log(`  ✅ Creado: ${skillsPath}`);

  // 2. Inject reference into CLAUDE.md (non-destructive)
  const claudeMdPath = getClaudeMdPath();
  const snippet = [
    '', MARKER,
    '## Skill Panel',
    `Skills instaladas en \`${skillsPath}\`.`,
    'Ejecuta `npx skill-panel` para gestionar skills y MCPs.',
    '<!-- /skill-panel -->',
    '',
  ].join('\n');

  if (fs.existsSync(claudeMdPath)) {
    const content = fs.readFileSync(claudeMdPath, 'utf-8');
    if (!content.includes(MARKER)) {
      fs.appendFileSync(claudeMdPath, snippet);
      console.log('  ✅ Referencia añadida a CLAUDE.md');
    } else {
      console.log('  ℹ️  CLAUDE.md ya tiene referencia al Skill Panel');
    }
  } else {
    // Create minimal CLAUDE.md
    const dir = path.dirname(claudeMdPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(claudeMdPath, `# Claude Code Configuration\n${snippet}`, 'utf-8');
    console.log('  ✅ Creado CLAUDE.md con referencia al Skill Panel');
  }

  // 3. Quick dep check (informational)
  const deps = checkSystemDeps();
  const missing = Object.entries(deps)
    .filter(([k, v]) => k !== '_platform' && !v.installed)
    .map(([k]) => k);
  if (missing.length) {
    console.log(`  ⚠️  Dependencias opcionales faltantes: ${missing.join(', ')}`);
    console.log('     (Se pueden instalar desde el panel)');
  }

  console.log('  ✅ Setup completado.');
  console.log('');
}

module.exports = { isFirstRun, runSetup };
