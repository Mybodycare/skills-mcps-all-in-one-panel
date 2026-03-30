#!/usr/bin/env node
'use strict';

const { exec } = require('child_process');
const { isFirstRun, runSetup } = require('../lib/setup');
const { startServer } = require('../lib/server');
const { getSkillsPath } = require('../lib/platform');

const PORT = parseInt(process.env.SKILL_PANEL_PORT || '5757', 10);
const VERSION = require('../package.json').version;

async function main() {
  // Always sync: consolidate MCPs, update CLAUDE.md skill table
  runSetup();

  // Start server
  startServer(PORT);

  const url = `http://localhost:${PORT}`;

  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log(`  ║   Skill Panel v${VERSION.padEnd(24)}║`);
  console.log('  ╠══════════════════════════════════════╣');
  console.log(`  ║  🌐 ${url.padEnd(32)}║`);
  console.log(`  ║  📁 ${getSkillsPath().slice(-32).padEnd(32)}║`);
  console.log('  ║  ⌨️  Ctrl+C para detener            ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  // Open browser
  openBrowser(url);
}

function openBrowser(url) {
  const cmd = process.platform === 'darwin' ? `open "${url}"`
            : process.platform === 'win32'  ? `start "" "${url}"`
            : `xdg-open "${url}"`;
  exec(cmd, () => {}); // ignore errors (headless environments)
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n  Skill Panel detenido.\n');
  process.exit(0);
});

main().catch(err => {
  console.error('  ❌ Error:', err.message);
  process.exit(1);
});
