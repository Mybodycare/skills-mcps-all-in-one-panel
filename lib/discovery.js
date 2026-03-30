'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { getClaudeJsonPath, getMcpJsonPath } = require('./platform');
const { listInstalled } = require('./installer');

function discoverMCPs() {
  const mcps = new Map();
  tryReadMCPs(getClaudeJsonPath(), mcps);
  tryReadMCPs(getMcpJsonPath(), mcps);

  // Project-level MCPs in cwd
  const localMcp = path.join(process.cwd(), '.mcp.json');
  tryReadMCPs(localMcp, mcps);

  return Array.from(mcps.entries()).map(([name, config]) => ({
    name,
    command: config.command || config.url || '',
    args: config.args || [],
    hasEnv: !!(config.env && Object.keys(config.env).length),
    type: config.type || (config.url ? 'sse' : 'stdio'),
  }));
}

function tryReadMCPs(filePath, map) {
  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    const servers = data.mcpServers || {};
    for (const [name, config] of Object.entries(servers)) {
      if (!map.has(name)) map.set(name, config);
    }
  } catch {}
}

function discover() {
  return {
    skills: listInstalled(),
    mcps: discoverMCPs(),
    platform: process.platform,
  };
}

module.exports = { discover, discoverMCPs };
