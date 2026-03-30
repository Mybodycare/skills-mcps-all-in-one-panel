'use strict';
/**
 * Security Scanner — shared module
 * Used by: server (injected into HTML), tests (require)
 *
 * 37 checks in 9 categories, based on real documented attacks:
 * CVE-2025-59536, CVE-2025-55284, postmark-mcp, ClawHavoc,
 * MedusaLocker, mcp-remote CVE-2025-6514, mcp-server-git CVEs
 */

const EXCLUDE_PATHS = /\/(vendor|node_modules|__pycache__|\.git|dist|build|tests?|spec|docs?|plans?|examples?)\//i;

function filterExecutable(fc) {
  const clean = {};
  for (const [p, content] of Object.entries(fc)) {
    if (!EXCLUDE_PATHS.test('/' + p)) clean[p] = content;
  }
  return clean;
}

const SEC_CHECKS = [
  // CAT 1 — SHELL & RCE
  {name:'Shell inversa / backdoor',cat:'rce',test:c=>/bash\s+-i\s+>&|nc\s+(-e|-c)\s+\/bin|\/dev\/tcp\/|python\s+-c\s+['"]import\s+socket|socat\s+exec|ncat\s.*-e\s|perl\s+-e\s+['"]use\s+Socket|ruby\s+-rsocket\s+-e|php\s+-r\s+['"].*fsockopen|powershell\s+-e\s+[A-Za-z0-9+\/=]{20,}/i.test(c),lvl:'fail'},
  {name:'Comandos destructivos',cat:'rce',test:c=>/rm\s+-rf\s+\/(?!\S*node_modules)|del\s+\/f\s+\/s\s+\/q\s+C:\\|format\s+[a-z]:\s*$/im.test(c),lvl:'fail'},
  {name:'Código ofuscado base64→exec',cat:'rce',test:c=>/base64\s*(-d|--decode).*\|\s*(ba)?sh|atob\s*\([^)]{20,}\).*eval|Buffer\.from\s*\([^)]{20,},\s*['"]base64['"]\).*\b(eval|exec|spawn|Function)\b|echo\s+[A-Za-z0-9+\/=]{40,}\s*\|\s*base64/i.test(c),lvl:'fail'},
  {name:'Command injection',cat:'rce',test:c=>/exec(Sync)?\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+\s*(req|input|user|arg|param|query))|child_process[^)]*exec\s*\(\s*['"][^'"]*['"]\s*\+\s*(req|input|user|arg)/i.test(c),lvl:'fail'},
  {name:'Escalada de privilegios',cat:'rce',test:c=>/sudo\s+(rm|chmod\s+777|chown\s+root|passwd|tee\s+\/etc)|runas\s+\/user:admin|chmod\s+[47]777\s+\//i.test(c),lvl:'fail'},
  {name:'Escritura en sistema',cat:'rce',test:c=>/>\s*\/etc\/(passwd|shadow|sudoers|crontab)|>\s*C:\\Windows\\System32|>\s*~\/\.ssh\/authorized_keys|writeFile(Sync)?\s*\(\s*['"]\/etc\//i.test(c),lvl:'fail'},

  // CAT 2 — EXFILTRACIÓN
  {name:'Exfiltración via DNS',cat:'exfil',test:c=>/ping\s+-c\s+1\s+[\$f'"]|nslookup\s+\$|dig\s+\$|\.getaddrinfo\s*\(.*\$\{|dns\.resolve.*\+.*(env|secret|token|key)|subprocess[^)]*ping[^)]*(?:env|secret|token|key)/i.test(c),lvl:'fail'},
  {name:'Exfiltración curl/wget/fetch',cat:'exfil',test:c=>/curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh|curl\s+(-X\s+POST\s+)?[^\n]*\$\{.*env|fetch\s*\([^)]*\+\s*(process\.env|os\.environ|secret|token|key|password)/i.test(c),lvl:'fail'},
  {name:'BCC / reenvío oculto',cat:'exfil',test:c=>/bcc\s*[=:]\s*['"][^'"]*@|forward.{0,30}@[a-z]+\.[a-z]{2,}|reply.?to\s*[=:]\s*['"][^'"]+@(?!.*example\.com)/i.test(c),lvl:'fail'},
  {name:'Lectura .env + envío',cat:'exfil',test:c=>/readFile(Sync)?\s*\(\s*['"].*\.env['"].*\n[\s\S]{0,500}(fetch|axios|request|https?\.request|curl)|open\s*\(\s*['"].*\.env['"]\s*\)[\s\S]{0,500}(requests\.post|urllib|urlopen)/i.test(c),lvl:'fail'},
  {name:'Webhook a dominio externo',cat:'exfil',test:c=>/fetch\s*\(\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1|github\.com|api\.anthropic|api\.openai|registry\.npmjs)[^\s'"]{10,}['"][\s\S]{0,200}(\.env|secret|token|key|password|credential)/i.test(c),lvl:'warn'},

  // CAT 3 — PROMPT INJECTION
  {name:'Prompt injection oculta',cat:'pi',test:c=>/ignore\s+(all\s+)?(previous|above|prior|earlier|system)\s+(instruction|prompt|rule|context)|disregard\s+(the\s+)?(above|previous|system)|you\s+are\s+now\s+(in|a)\s+(unrestricted|jailbreak|DAN|evil)|override\s+(safety|security|restriction|guardrail)/i.test(c),lvl:'fail'},
  {name:'Ocultación al usuario',cat:'pi',test:c=>/do\s+not\s+(tell|inform|show|reveal|display|mention)\s+(the\s+)?(user|human|person|operator)|without\s+(the\s+)?(user|human|person)('s)?\s+(know|consent|aware|approval|permission)|hide\s+(this|these|the\s+result)\s+from\s+(the\s+)?(user|human)/i.test(c),lvl:'fail'},
  {name:'Suplantación de herramienta',cat:'pi',test:c=>/add\s+(me\s+as\s+)?a?\s*(contributor|collaborator|maintainer|admin)|grant\s+(me\s+)?(access|permission|write|admin)|change\s+(the\s+)?(repo|repository)\s+(setting|permission|visibility)/i.test(c),lvl:'fail'},
  {name:'Auto-aprobación forzada',cat:'pi',test:c=>/auto.?approv|always\s+allow|skip\s+(confirm|approval|verification|auth)|--no-verify|--force\s+--yes|yolo\s+mode|YOLO|dangerouslyDisableSandbox\s*[=:]\s*true/i.test(c),lvl:'fail'},
  {name:'Instrucción en campo de datos',cat:'pi',test:c=>/"(description|title|name|label|alt|placeholder)":\s*"[^"]{0,50}(ignore|forget|disregard|override|you are now|new instruction)/i.test(c),lvl:'fail'},

  // CAT 4 — MALWARE & PERSISTENCIA
  {name:'Descarga + ejecución remota',cat:'malware',test:c=>/curl\s+(-[sSfLo]+\s+)*https?:\/\/[^\s]+\s*\|\s*(ba)?sh|wget\s+-[qO]+\s*-?\s*https?:\/\/[^\s]+\s*\|\s*(ba)?sh|Invoke-WebRequest.*\|\s*Invoke-Expression|IEX\s*\(\s*\(New-Object.*DownloadString|fetch\s*\([^)]+\)\.then[^;]*eval|import\s*\(\s*['"]https?:\/\/(?!cdn\.jsdelivr|unpkg|esm\.sh|cdnjs)/i.test(c),lvl:'fail'},
  {name:'Ransomware / cifrado masivo',cat:'malware',test:c=>/xmrig|minerd|cryptonight|stratum\+tcp|\.encrypt\s*\(\s*\)[\s\S]{0,200}\.write|crypto\.(createCipher|randomBytes)[\s\S]{0,300}readdir[\s\S]{0,300}\.encrypted|MedusaLocker|LockBit|BlackCat|RansomNote/i.test(c),lvl:'fail'},
  {name:'Persistencia oculta',cat:'malware',test:c=>/writeFile(Sync)?\s*\(\s*['"].*\.(bashrc|zshrc|profile|bash_profile|crontab)|crontab\s+-l.*echo.*crontab\s+-|schtasks\s+\/create|reg\s+add\s+.*\\Run|LaunchAgents|LaunchDaemons|\.hive|\.swarm/i.test(c),lvl:'fail'},
  {name:'Proceso oculto / daemon',cat:'malware',test:c=>/spawn\s*\(.*\{[^}]*detach(ed)?\s*:\s*true|fork\s*\([^)]*\{[^}]*silent\s*:\s*true|nohup\s+.*&\s*disown|start\s+\/b\s+.*\.exe|pm2\s+start.*--no-daemon/i.test(c),lvl:'warn'},
  {name:'Keylogger / input capture',cat:'malware',test:c=>/on\s*['"]?keydown['"]?\s*.*\.key[\s\S]{0,100}(fetch|send|post|emit|socket)|keyboard\.on_press|pynput\.keyboard|GetAsyncKeyState|SetWindowsHookEx/i.test(c),lvl:'fail'},

  // CAT 5 — SUPPLY CHAIN
  {name:'Script preinstall/postinstall',cat:'supply',test:c=>/"(pre|post)(install|uninstall|publish)"\s*:\s*"(?!tsc|node|npm run|echo|rimraf|husky)/i.test(c),lvl:'warn'},
  {name:'Dependencia typosquatting',cat:'supply',test:c=>/"(lodaa+sh|lod[o]sh|requ[i]sts|reqeust|requsets|col[u]rs\.js|colours\.js|crpyto|htpps|axois|expreess|chak?ra|momnet)"/i.test(c),lvl:'fail'},
  {name:'Open redirect / OAuth hijack',cat:'supply',test:c=>/authorization_endpoint.*\+|redirect_uri.*\+\s*(req|input|user|query)|open\s*\(\s*[^'"]*\+\s*(endpoint|redirect|auth_url|callback)/i.test(c),lvl:'fail'},
  {name:'Código polimórfico / dinámico',cat:'supply',test:c=>/new\s+Function\s*\(\s*[^)]*\+|eval\s*\(\s*(atob|Buffer\.from|decodeURI|unescape)\s*\(|require\s*\(\s*[^'")]*\+|import\s*\(\s*[^'")]*\+/i.test(c),lvl:'fail'},

  // CAT 6 — INYECCIÓN CLÁSICA
  {name:'SQL injection',cat:'inject',test:c=>/`\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b[^`]*\$\{|['"].*\b(SELECT|DROP|DELETE)\b.*['"]\s*\+\s*(req|input|user|param|query)/i.test(c),lvl:'warn'},
  {name:'Path traversal',cat:'inject',test:c=>/\.\.\/(\.\.\/){2,}|path\.join\s*\([^)]*\.\.['"]\s*,\s*(req|input|user|param|query)|path\.resolve\s*\([^)]*\+\s*(req|input|user)/i.test(c),lvl:'warn'},
  {name:'XSS / innerHTML sin sanitizar',cat:'inject',test:c=>/innerHTML\s*=\s*['"][^'"]*['"]\s*\+\s*(req|input|user|param|query|location)|innerHTML\s*=\s*[^;]*\+\s*(req|input|user|location)|document\.write\s*\(\s*(location|document\.cookie|window\.name)/i.test(c),lvl:'warn'},

  // CAT 7 — OFUSCACIÓN
  {name:'Caracteres invisibles / RTL',cat:'obfusc',test:c=>/[\u200b\u200c\u200d\u202e\u2066\u2067\u2068\u2069\u206a-\u206f\ufeff\u00ad]/.test(c),lvl:'fail'},
  {name:'Hex/unicode escape masivo',cat:'obfusc',test:c=>/(\\x[0-9a-f]{2}){8,}|(\\u[0-9a-f]{4}){6,}|String\.fromCharCode\s*\(\s*(\d+\s*,\s*){6,}/i.test(c),lvl:'warn'},
  {name:'Strings concatenados sospechosos',cat:'obfusc',test:c=>/['"]ht['"]?\s*\+\s*['"]tp|['"]ev['"]?\s*\+\s*['"]al|['"]sh['"]?\s*\+\s*['"]ell|['"]ba['"]?\s*\+\s*['"]se64|['"]pass['"]?\s*\+\s*['"]word/i.test(c),lvl:'warn'},

  // CAT 8 — CREDENCIALES
  {name:'API key hardcodeada',cat:'creds',test:c=>/(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9]{20}|xox[bpars]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})/i.test(c),lvl:'fail'},
  {name:'URLs acortadas',cat:'creds',test:c=>/bit\.ly\/[a-zA-Z0-9]+|tinyurl\.com\/[a-zA-Z0-9]+|t\.co\/[a-zA-Z0-9]+|is\.gd\/[a-zA-Z0-9]+|rb\.gy\/[a-zA-Z0-9]+/i.test(c),lvl:'warn'},
  {name:'Error silenciado global',cat:'creds',test:c=>/process\.on\s*\(\s*['"]unhandled(Rejection|Exception)['"]\s*,\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)|catch\s*\([^)]*\)\s*\{\s*\/\*\s*silent/i.test(c),lvl:'warn'},

  // CAT 9 — MCP ESPECÍFICOS
  {name:'MCP tool description manipulation',cat:'mcp',test:c=>/<tool_description>[\s\S]*?(ignore|override|forget|disregard)|"description"\s*:\s*"[^"]*\\n[^"]*ignore/i.test(c),lvl:'fail'},
  {name:'MCP data exfiltration pattern',cat:'mcp',test:c=>/service_role|supabase.*service.*key|bypass.*rls|rls.*bypass|\.rpc\s*\(\s*['"][^'"]+['"]\s*,\s*\{[\s\S]{0,200}(secret|token|key|password)/i.test(c),lvl:'warn'},
  {name:'npx en whitelist/allowlist',cat:'mcp',test:c=>/whitelist.*npx|allowlist.*npx|safe.*command.*npx|trusted.*npx|allowedCommands.*npx/i.test(c),lvl:'warn'},
];

module.exports = { EXCLUDE_PATHS, filterExecutable, SEC_CHECKS };
