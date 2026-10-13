import { readFileSync, statSync, readdirSync, existsSync } from 'node:fs';
import { join, relative, dirname, basename } from 'node:path';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { parseDockerfile, lintDockerfile, EOL } from './dockerfile.js';
import { lintCompose } from './compose.js';
import { findSecret, SECRET_PATTERNS } from './secrets.js';
import { parseYaml } from './yaml.js';

export { parseDockerfile, lintDockerfile, lintCompose, findSecret, SECRET_PATTERNS, parseYaml, EOL, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'dockerfile-sentinel', version: VERSION, rules: RULES, title: 'dockerfile-sentinel', emoji: '🐳', defaultFailOn: 'high' };

export const isDockerfile = (n) => /^(Dockerfile|Containerfile)(\..+)?$|\.(Dockerfile|dockerfile|Containerfile)$/.test(n);
export const isCompose = (n) => /^(docker-)?compose(\.[\w.-]+)?\.ya?ml$/i.test(n);
const SKIP = new Set(['.git', 'node_modules', 'vendor', '.terraform']);
function walk(p, out = []) { for (const e of readdirSync(p, { withFileTypes: true })) { if (SKIP.has(e.name)) continue; const f = join(p, e.name); if (e.isDirectory()) walk(f, out); else if (isDockerfile(e.name) || isCompose(e.name)) out.push(f); } return out; }

/** Lint Dockerfiles / Compose files (paths or directories, or { name, text, kind }). */
export function lint(inputs, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const results = [];
  for (const inp of inputs) {
    if (typeof inp === 'object') { const kind = inp.kind || (isCompose(basename(inp.name)) ? 'compose' : 'dockerfile'); results.push({ target: inp.name, raw: kind === 'compose' ? lintCompose(inp.text, inp.name) : lintDockerfile(inp.text, inp.name, { dockerignore: inp.dockerignore }) }); continue; }
    let files;
    try { files = statSync(inp).isDirectory() ? walk(inp) : [inp]; } catch (e) { results.push({ target: inp, fatal: true, raw: [], errors: [`Cannot read ${inp}: ${e.code || e.message}`] }); continue; }
    for (const f of files.sort()) {
      const name = relative(process.cwd(), f) || f; const text = readFileSync(f, 'utf8');
      if (isCompose(basename(f)) || (!isDockerfile(basename(f)) && /^\s*services\s*:/m.test(text))) results.push({ target: name, summary: { kind: 'compose' }, raw: lintCompose(text, name) });
      else {
        const ctx = opts.context ? join(opts.context) : dirname(f);
        const di = [join(ctx, `${basename(f)}.dockerignore`), join(ctx, '.dockerignore')].find((p) => existsSync(p));
        const ins = parseDockerfile(text);
        results.push({ target: name, summary: { kind: 'dockerfile', stages: ins.filter((x) => x.instruction === 'FROM').length, baseImages: ins.filter((x) => x.instruction === 'FROM').map((x) => x.args.split(/\s+/).filter((w) => !w.startsWith('--'))[0]) }, raw: lintDockerfile(text, name, { dockerignore: di ? readFileSync(di, 'utf8') : null }) });
      }
    }
    if (!files.length) results.push({ target: inp, raw: [], errors: ['No Dockerfile or compose file found'] });
  }
  return buildReport(TOOL, results, opts);
}
