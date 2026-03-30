'use strict';
const { execFileSync } = require('child_process');
const { isWin, isMac, spawnOpts } = require('./platform');

const DEP_CHECKS = [
  { name: 'node',    cmds: [['node', '--version']] },
  { name: 'python',  cmds: [['python3', '--version'], ['python', '--version']] },
  { name: 'bun',     cmds: [['bun', '--version']] },
  { name: 'ripgrep', cmds: [['rg', '--version']] },
  { name: 'ffmpeg',  cmds: [['ffmpeg', '-version']] },
  { name: 'magick',  cmds: [['magick', '--version']] },
  { name: 'git',     cmds: [['git', '--version']] },
  { name: 'bash',    cmds: [['bash', '--version']] },
];

const WINGET_IDS = {
  node:    'OpenJS.NodeJS.LTS',
  bun:     'Oven-sh.Bun',
  ripgrep: 'BurntSushi.ripgrep.MSVC',
  ffmpeg:  'Gyan.FFmpeg',
  magick:  'ImageMagick.ImageMagick',
  git:     'Git.Git',
  python:  'Python.Python.3.13',
};

const BREW_IDS = {
  node:    'node',
  bun:     'oven-sh/bun/bun',
  ripgrep: 'ripgrep',
  ffmpeg:  'ffmpeg',
  magick:  'imagemagick',
  git:     'git',
  python:  'python@3.13',
};

function checkSystemDeps() {
  const result = { _platform: process.platform };
  for (const dep of DEP_CHECKS) {
    let found = false;
    for (const cmd of dep.cmds) {
      try {
        const out = execFileSync(cmd[0], cmd.slice(1), spawnOpts({ stdio: 'pipe' }));
        const version = out.toString().trim().split('\n')[0];
        result[dep.name] = { installed: true, version };
        found = true;
        break;
      } catch {}
    }
    if (!found) result[dep.name] = { installed: false };
  }
  return result;
}

function installDependency(dep) {
  if (isMac()) {
    const pkg = BREW_IDS[dep];
    if (!pkg) return { success: false, error: `No hay paquete brew para '${dep}'` };
    try {
      execFileSync('brew', ['install', pkg], spawnOpts({ timeout: 180000, stdio: 'pipe' }));
      return { success: true, dep, package: pkg };
    } catch (e) {
      if (e.code === 'ENOENT') return { success: false, error: 'brew no encontrado. Instala Homebrew: https://brew.sh' };
      return { success: false, error: (e.stderr || e.message || '').toString().slice(0, 400) };
    }
  }

  if (isWin()) {
    const pkg = WINGET_IDS[dep];
    if (!pkg) return { success: false, error: `No hay paquete winget para '${dep}'` };
    try {
      execFileSync('winget', [
        'install', '--id', pkg,
        '--silent', '--accept-package-agreements', '--accept-source-agreements'
      ], spawnOpts({ timeout: 180000, stdio: 'pipe' }));
      return { success: true, dep, package: pkg };
    } catch (e) {
      if (e.code === 'ENOENT') return { success: false, error: 'winget no encontrado. Actualiza Windows App Installer.' };
      return { success: false, error: (e.stderr || e.message || '').toString().slice(0, 400) };
    }
  }

  return { success: false, error: `Instala '${dep}' manualmente con tu gestor de paquetes.` };
}

module.exports = { checkSystemDeps, installDependency };
