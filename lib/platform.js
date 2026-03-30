'use strict';
const os = require('os');
const path = require('path');

const isWin  = () => process.platform === 'win32';
const isMac  = () => process.platform === 'darwin';

const getSkillsPath      = () => path.join(os.homedir(), '.claude', 'skills');
const getClaudeConfigPath = () => path.join(os.homedir(), '.claude');
const getClaudeJsonPath   = () => path.join(os.homedir(), '.claude.json');
const getMcpJsonPath      = () => path.join(os.homedir(), '.claude', '.mcp.json');
const getClaudeMdPath     = () => path.join(os.homedir(), '.claude', 'CLAUDE.md');

/** Options for child_process to hide console windows on Windows */
function spawnOpts(extra = {}) {
  return { timeout: 8000, windowsHide: true, ...extra };
}

module.exports = {
  isWin, isMac,
  getSkillsPath, getClaudeConfigPath, getClaudeJsonPath,
  getMcpJsonPath, getClaudeMdPath, spawnOpts,
};
