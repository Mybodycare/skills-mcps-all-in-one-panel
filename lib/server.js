'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { getSkillsPath } = require('./platform');
const { checkSystemDeps, installDependency } = require('./deps');
const { listInstalled, installSkill, uninstallSkill } = require('./installer');
const { discover } = require('./discovery');
const { proxyGitHub, proxyRaw } = require('./github-proxy');
const { installMCP, uninstallMCP, MCP_CATALOG } = require('./mcp-installer');
const { refreshClaudeMd } = require('./setup');

function startServer(port) {
  // Load HTML and inject security scanner
  const htmlPath = path.join(__dirname, '..', 'public', 'index.html');
  let cachedHTML = fs.readFileSync(htmlPath, 'utf-8');

  const scannerPath = path.join(__dirname, 'security-scanner.js');
  const scannerCode = fs.readFileSync(scannerPath, 'utf-8')
    .replace("'use strict';", '')
    .replace(/\/\*\*[\s\S]*?\*\//, '')  // remove JSDoc
    .replace(/module\.exports\s*=\s*\{[^}]+\};?/, '');

  cachedHTML = cachedHTML.replace('/* __SECURITY_SCANNER_INJECT__ */', scannerCode);

  const server = http.createServer(async (req, res) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    const url = new URL(req.url, `http://localhost:${port}`);

    try {
      if (req.method === 'GET') {
        if (url.pathname === '/' || url.pathname === '/index.html') {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(cachedHTML);
        }
        else if (url.pathname === '/ping') { jsonReply(res, { ok: true, vault: getSkillsPath() }); }
        else if (url.pathname === '/list') { jsonReply(res, listInstalled()); }
        else if (url.pathname === '/discover') { jsonReply(res, discover()); }
        else if (url.pathname === '/check-deps') { jsonReply(res, checkSystemDeps()); }
        else if (url.pathname === '/mcp-catalog') { jsonReply(res, MCP_CATALOG); }
        else if (url.pathname.startsWith('/gh/')) { await proxyGitHub(req, res, url.pathname.slice(4)); }
        else if (url.pathname.startsWith('/raw/')) { await proxyRaw(req, res, url.pathname.slice(5)); }
        else { res.writeHead(404); res.end('Not found'); }
      }
      else if (req.method === 'POST') {
        const body = await readBody(req);
        if (url.pathname === '/install') { const r = await installSkill(body); if(r.success) try{refreshClaudeMd();}catch{}; jsonReply(res, r); }
        else if (url.pathname === '/install-dep') { jsonReply(res, installDependency(body.dep)); }
        else if (url.pathname === '/install-mcp') { jsonReply(res, installMCP(body)); }
        else if (url.pathname === '/uninstall-mcp') { jsonReply(res, uninstallMCP(body.name)); }
        else if (url.pathname === '/uninstall') { const r = uninstallSkill(body); if(r.success) try{refreshClaudeMd();}catch{}; jsonReply(res, r); }
        else { res.writeHead(404); res.end('Not found'); }
      }
    } catch (err) {
      jsonReply(res, { error: err.message }, 500);
    }
  });

  server.listen(port, 'localhost', () => {});

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n  ❌ Puerto ${port} ocupado. Usa: SKILL_PANEL_PORT=${port + 1} npx skill-panel\n`);
      process.exit(1);
    }
    throw err;
  });

  return server;
}

function jsonReply(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(data)); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

module.exports = { startServer };
