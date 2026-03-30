'use strict';
const https = require('https');

function proxyRequest(targetUrl, headers, res) {
  return new Promise((resolve) => {
    https.get(targetUrl, { headers }, (upstream) => {
      res.writeHead(upstream.statusCode, {
        'Content-Type': upstream.headers['content-type'] || 'application/json',
        'Access-Control-Allow-Origin': '*',
      });
      upstream.pipe(res);
      upstream.on('end', resolve);
    }).on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
      resolve();
    });
  });
}

async function proxyGitHub(req, res, ghPath) {
  const url = `https://api.github.com/${ghPath}`;
  const headers = {
    'User-Agent': 'SkillPanel/1.0',
    'Accept': 'application/vnd.github.v3+json',
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers['Authorization'] = `token ${token}`;
  return proxyRequest(url, headers, res);
}

async function proxyRaw(req, res, rawPath) {
  const url = `https://raw.githubusercontent.com/${rawPath}`;
  const headers = { 'User-Agent': 'SkillPanel/1.0' };
  return proxyRequest(url, headers, res);
}

module.exports = { proxyGitHub, proxyRaw };
