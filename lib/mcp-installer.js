'use strict';
const fs = require('fs');
const path = require('path');
const { getClaudeJsonPath } = require('./platform');

/**
 * Install an MCP server into ~/.claude.json → mcpServers
 * Handles tokens/API keys automatically — the user just pastes the key.
 */
function installMCP(data) {
  const { name, command, args, envVars } = data;
  //  name: "github"
  //  command: "npx"
  //  args: ["-y", "@modelcontextprotocol/server-github"]
  //  envVars: { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abc123..." }

  if (!name) return { success: false, error: 'Nombre del MCP vacío' };
  if (!command) return { success: false, error: 'Comando del MCP vacío' };

  const configPath = getClaudeJsonPath();
  let config = {};

  // Read existing config
  try {
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    }
  } catch (e) {
    return { success: false, error: `Error leyendo ${configPath}: ${e.message}` };
  }

  // Ensure mcpServers object exists
  if (!config.mcpServers) config.mcpServers = {};

  // Build MCP entry
  const entry = { command, args: args || [] };
  if (envVars && Object.keys(envVars).length > 0) {
    entry.env = envVars;
  }

  // Check if already exists
  const existed = !!config.mcpServers[name];
  config.mcpServers[name] = entry;

  // Write back
  try {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
  } catch (e) {
    return { success: false, error: `Error escribiendo ${configPath}: ${e.message}` };
  }

  return {
    success: true,
    name,
    action: existed ? 'updated' : 'installed',
    configPath,
    message: `MCP "${name}" ${existed ? 'actualizado' : 'instalado'}. Reinicia Claude Code para activarlo.`,
  };
}

/**
 * Uninstall an MCP server from ~/.claude.json
 */
function uninstallMCP(name) {
  if (!name) return { success: false, error: 'Nombre del MCP vacío' };

  const configPath = getClaudeJsonPath();
  let config = {};

  try {
    config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  } catch {
    return { success: false, error: 'No se pudo leer ~/.claude.json' };
  }

  if (!config.mcpServers || !config.mcpServers[name]) {
    return { success: false, error: `MCP "${name}" no encontrado` };
  }

  delete config.mcpServers[name];
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');

  return { success: true, name, message: `MCP "${name}" eliminado. Reinicia Claude Code.` };
}

/**
 * MCP catalog — popular MCPs with their install configs
 * The user only needs to provide the API key/token
 */
const MCP_CATALOG = [
  {
    id: 'github',
    name: 'GitHub',
    icon: '🐙',
    desc: 'Repos, PRs, issues, code search desde Claude.',
    npm: '@modelcontextprotocol/server-github',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-github'],
    credentials: [{
      key: 'GITHUB_PERSONAL_ACCESS_TOKEN',
      label: 'GitHub Personal Access Token',
      url: 'https://github.com/settings/tokens/new?scopes=repo,read:org,read:user',
      placeholder: 'ghp_xxxxxxxxxxxxxxxxxxxx',
      help: 'Crea un token con permisos: repo, read:org, read:user',
    }],
  },
  {
    id: 'slack',
    name: 'Slack',
    icon: '💬',
    desc: 'Envía mensajes, lee canales, busca en Slack.',
    npm: '@anthropic/mcp-server-slack',
    command: 'npx',
    args: ['-y', '@anthropic/mcp-server-slack'],
    credentials: [{
      key: 'SLACK_BOT_TOKEN',
      label: 'Slack Bot Token',
      url: 'https://api.slack.com/apps',
      placeholder: 'xoxb-xxxxxxxxxxxx',
      help: 'Crea una app en Slack → OAuth → Bot Token',
    }],
  },
  {
    id: 'filesystem',
    name: 'Filesystem',
    icon: '📁',
    desc: 'Lee y escribe archivos del sistema local.',
    npm: '@anthropic/mcp-server-filesystem',
    command: 'npx',
    args: ['-y', '@anthropic/mcp-server-filesystem', '/home'],
    credentials: [],
  },
  {
    id: 'postgres',
    name: 'PostgreSQL',
    icon: '🐘',
    desc: 'Consultas SQL, esquema, tablas de PostgreSQL.',
    npm: '@modelcontextprotocol/server-postgres',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-postgres'],
    credentials: [{
      key: 'POSTGRES_CONNECTION_STRING',
      label: 'Connection String',
      url: '',
      placeholder: 'postgresql://user:pass@localhost:5432/mydb',
      help: 'Formato: postgresql://usuario:contraseña@host:puerto/base_de_datos',
    }],
  },
  {
    id: 'brave-search',
    name: 'Brave Search',
    icon: '🦁',
    desc: 'Búsqueda web con Brave Search API.',
    npm: '@anthropic/mcp-server-brave-search',
    command: 'npx',
    args: ['-y', '@anthropic/mcp-server-brave-search'],
    credentials: [{
      key: 'BRAVE_API_KEY',
      label: 'Brave Search API Key',
      url: 'https://brave.com/search/api/',
      placeholder: 'BSA_xxxxxxxxxxxx',
      help: 'Regístrate en Brave Search API (tiene tier gratuito)',
    }],
  },
  {
    id: 'puppeteer',
    name: 'Puppeteer',
    icon: '🌐',
    desc: 'Navega webs, hace screenshots, interactúa con páginas.',
    npm: '@anthropic/mcp-server-puppeteer',
    command: 'npx',
    args: ['-y', '@anthropic/mcp-server-puppeteer'],
    credentials: [],
  },
  {
    id: 'memory',
    name: 'Memory',
    icon: '🧠',
    desc: 'Memoria persistente entre conversaciones via knowledge graph.',
    npm: '@anthropic/mcp-server-memory',
    command: 'npx',
    args: ['-y', '@anthropic/mcp-server-memory'],
    credentials: [],
  },
  {
    id: 'google-maps',
    name: 'Google Maps',
    icon: '🗺️',
    desc: 'Geocoding, direcciones, búsqueda de lugares.',
    npm: '@anthropic/mcp-server-google-maps',
    command: 'npx',
    args: ['-y', '@anthropic/mcp-server-google-maps'],
    credentials: [{
      key: 'GOOGLE_MAPS_API_KEY',
      label: 'Google Maps API Key',
      url: 'https://console.cloud.google.com/apis/credentials',
      placeholder: 'AIza...',
      help: 'Activa Maps Platform en Google Cloud Console',
    }],
  },
  {
    id: 'notion',
    name: 'Notion',
    icon: '📓',
    desc: 'Lee, crea y actualiza páginas y bases de datos de Notion.',
    npm: '@notionhq/mcp-server-notion',
    command: 'npx',
    args: ['-y', '@notionhq/mcp-server-notion'],
    credentials: [{
      key: 'NOTION_API_KEY',
      label: 'Notion Integration Token',
      url: 'https://www.notion.so/my-integrations',
      placeholder: 'ntn_xxxxxxxxxxxx',
      help: 'Crea una integración interna en Notion → copia el token',
    }],
  },
  {
    id: 'supabase',
    name: 'Supabase',
    icon: '🗃️',
    desc: 'SQL, tablas, edge functions, gestión de proyectos Supabase.',
    npm: '@supabase/mcp-server-supabase',
    command: 'npx',
    args: ['-y', '@supabase/mcp-server-supabase'],
    credentials: [{
      key: 'SUPABASE_ACCESS_TOKEN',
      label: 'Supabase Access Token',
      url: 'https://supabase.com/dashboard/account/tokens',
      placeholder: 'sbp_xxxxxxxxxxxx',
      help: 'Dashboard → Account → Access Tokens → Generate new token',
    }],
  },
];

module.exports = { installMCP, uninstallMCP, MCP_CATALOG };
