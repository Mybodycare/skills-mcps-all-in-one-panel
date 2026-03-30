'use strict';
const fs = require('fs');
const path = require('path');
const https = require('https');
const { getSkillsPath } = require('./platform');

const CATEGORIES = {
  'automation':      ['automat', 'workflow', 'schedule', 'task', 'trigger', 'n8n', 'zap'],
  'code-quality':    ['debug', 'review', 'lint', 'refactor', 'clean', 'quality', 'smell'],
  'design-ui':       ['design', 'ui', 'figma', 'css', 'visual', 'layout', 'color'],
  'devops-deploy':   ['deploy', 'docker', 'ci', 'cd', 'infra', 'devops', 'kubernetes'],
  'documentation':   ['doc', 'readme', 'wiki', 'write', 'note', 'spec'],
  'research':        ['research', 'search', 'analyz', 'data', 'scrape', 'investigate'],
  'testing':         ['test', 'unit', 'integr', 'coverage', 'assert', 'mock', 'e2e'],
  'web-development': ['web', 'html', 'javascript', 'frontend', 'css', 'http', 'api', 'gsap'],
  'marketing':       ['market', 'seo', 'content', 'social', 'linkedin', 'campaign'],
  'imaging':         ['image', 'photo', 'generate', 'banana', 'dalle', 'stable'],
};

function detectCategory(text) {
  const lower = text.toLowerCase();
  let best = 'general', bestScore = 0;
  for (const [cat, keywords] of Object.entries(CATEGORIES)) {
    const score = keywords.filter(k => lower.includes(k)).length;
    if (score > bestScore) { bestScore = score; best = cat; }
  }
  return best;
}

function listInstalled() {
  const skillsPath = getSkillsPath();
  if (!fs.existsSync(skillsPath)) return [];
  const result = [];
  for (const name of fs.readdirSync(skillsPath)) {
    const dir = path.join(skillsPath, name);
    try { if (!fs.statSync(dir).isDirectory()) continue; } catch { continue; }
    const skillFile = path.join(dir, 'SKILL.md');
    if (!fs.existsSync(skillFile)) continue;

    let meta = {};
    try { meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf-8')); } catch {}

    let desc = '';
    try {
      const lines = fs.readFileSync(skillFile, 'utf-8').split('\n').slice(0, 20);
      for (const line of lines) {
        const t = line.trim();
        if (t.startsWith('description:')) { desc = t.replace(/^description:\s*["']?/, '').replace(/["']$/, ''); break; }
        if (t.startsWith('# ') && !t.startsWith('---')) { desc = t.replace(/^#+\s*/, ''); break; }
      }
    } catch {}

    result.push({
      name,
      category: meta.category || '',
      source: meta.source || '',
      desc: desc || meta.name || name,
    });
  }
  return result;
}

function fetchSkillMd(owner, repo) {
  return new Promise((resolve) => {
    const paths = ['SKILL.md', 'skill.md', `skills/${repo}/SKILL.md`];
    let idx = 0;
    function tryNext() {
      if (idx >= paths.length) return resolve('');
      const url = `https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${paths[idx]}`;
      idx++;
      https.get(url, { headers: { 'User-Agent': 'SkillPanel/1.0' } }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return tryNext(); }
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => resolve(data));
      }).on('error', tryNext);
    }
    tryNext();
  });
}

async function installSkill(data) {
  const url = (data.url || '').trim().replace(/\/$/, '');
  const name = data.name || '';
  let content = data.content || '';

  if (!url) return { success: false, error: 'URL vacía' };

  const parts = url.replace('https://github.com/', '').split('/');
  if (parts.length < 2) return { success: false, error: 'URL de GitHub no válida' };
  const [owner, repo] = parts;

  const folderName = (name || repo).toLowerCase().replace(/\s+/g, '-').replace(/\//g, '-');

  if (!content) content = await fetchSkillMd(owner, repo);
  const category = detectCategory(content + ' ' + name + ' ' + url);

  const skillDir = path.join(getSkillsPath(), folderName);
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'SKILL.md'), content, 'utf-8');
  fs.writeFileSync(path.join(skillDir, 'meta.json'), JSON.stringify({
    name: folderName, source: url, category, installed: new Date().toISOString(),
  }, null, 2), 'utf-8');

  const rel = path.relative(getSkillsPath(), path.join(skillDir, 'SKILL.md'));
  return { success: true, path: rel, category };
}

function uninstallSkill(data) {
  const name = (data.name || '').trim();
  if (!name) return { success: false, error: 'Nombre vacío' };
  const dir = path.join(getSkillsPath(), name);
  if (!fs.existsSync(dir)) return { success: false, error: `Skill '${name}' no encontrada` };
  fs.rmSync(dir, { recursive: true, force: true });
  return { success: true, name };
}

module.exports = { listInstalled, installSkill, uninstallSkill, detectCategory };
