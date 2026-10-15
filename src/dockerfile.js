import { findSecret, isSecretAssignment, mask } from './secrets.js';
import { shellChecks } from './shell.js';
import { RULES } from './rules.js';

/** Inline ignores: "# hadolint ignore=DL3008,SC2086", "# dockerfile-sentinel ignore=rule-id", and "global ignore=" forms. */
export function inlineIgnores(text) {
  const lines = String(text).split(/\r?\n/); const byLine = new Map(); const global = new Set();
  lines.forEach((l, i) => { const m = /^\s*#\s*(hadolint|dockerfile-sentinel)\s+(global\s+)?ignore\s*=\s*([\w,\s-]+)/i.exec(l); if (!m) return; const ids = m[3].split(/[\s,]+/).filter(Boolean); if (m[2]) ids.forEach((x) => global.add(x)); else { let j = i + 1; while (j < lines.length && /^\s*(#.*)?$/.test(lines[j])) j++; byLine.set(j + 1, ids); } });
  return { byLine, global };
}
const ruleIgnored = (rule, ids) => ids && ids.some((x) => x === rule || (RULES[rule]?.hadolint || []).includes(x.toUpperCase()));

/** Parse a Dockerfile into instructions with line numbers (continuations, comments, heredocs, escape directive). */
export function parseDockerfile(text) {
  const lines = String(text).split(/\r?\n/); const out = []; let escape = '\\';
  for (let i = 0; i < Math.min(lines.length, 20); i++) { const m = lines[i].match(/^#\s*escape\s*=\s*(\S)/i); if (m) escape = m[1]; else if (!/^#\s*\w+\s*=/.test(lines[i])) break; }
  for (let i = 0; i < lines.length; i++) {
    let l = lines[i]; if (/^\s*(#.*)?$/.test(l)) continue;
    const start = i + 1; let full = l;
    while (full.trimEnd().endsWith(escape) && i + 1 < lines.length) { full = full.trimEnd().slice(0, -1); i++; while (i < lines.length && /^\s*#/.test(lines[i])) i++; full += ' ' + (lines[i] ?? '').trim(); }
    const m = full.trim().match(/^(\w+)\s*(.*)$/s); if (!m) continue;
    const ins = { instruction: m[1].toUpperCase(), args: m[2].trim(), line: start };
    const hd = ins.args.match(/<<-?["']?(\w+)["']?/);
    if (hd && ['RUN', 'COPY', 'ADD'].includes(ins.instruction)) { const body = []; while (i + 1 < lines.length && lines[i + 1].trim() !== hd[1]) body.push(lines[++i]); i++; ins.heredoc = body.join('\n'); }
    out.push(ins);
  }
  return out;
}
const flags = (args) => { const f = {}; let rest = args; let m; while ((m = rest.match(/^--([\w-]+)(?:=(\S+))?\s+/))) { f[m[1]] = m[2] ?? true; rest = rest.slice(m[0].length); } return { flags: f, rest }; };
function jsonOrWords(s) { if (s.trim().startsWith('[')) { try { return JSON.parse(s); } catch { /* fallthrough */ } } return s.match(/"[^"]*"|'[^']*'|\S+/g)?.map((x) => x.replace(/^["']|["']$/g, '')) || []; }
function kvPairs(s) {
  const out = []; const t = s.trim();
  if (/^[\w.-]+\s+[^=]*$/.test(t) && !/^[\w.-]+=/.test(t)) { const i = t.search(/\s/); return [[t.slice(0, i), t.slice(i + 1).trim()]]; }
  for (const m of t.matchAll(/([\w.-]+)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)/g)) out.push([m[1], m[2].replace(/^["']|["']$/g, '')]);
  return out;
}

export const EOL = [
  [/^(docker\.io\/)?(library\/)?node:(\d+)/, (m) => Number(m[3]) < 20 && Number(m[3]) % 2 === 0 || [11, 13, 15, 17, 19, 21, 23].includes(Number(m[3])) ? `Node.js ${m[3]}` : null],
  [/^(docker\.io\/)?(library\/)?python:(\d)\.(\d+)/, (m) => (m[3] === '2' || (m[3] === '3' && Number(m[4]) < 9) ? `Python ${m[3]}.${m[4]}` : null)],
  [/^(docker\.io\/)?(library\/)?python:2\b/, () => 'Python 2'],
  [/^(docker\.io\/)?(library\/)?ubuntu:(14\.04|16\.04|18\.04|trusty|xenial|bionic|20\.10|21\.04|21\.10|22\.10|23\.04|23\.10)/, (m) => `Ubuntu ${m[3]}`],
  [/^(docker\.io\/)?(library\/)?debian:(7|8|9|10|wheezy|jessie|stretch|buster)\b/, (m) => `Debian ${m[3]}`],
  [/^(docker\.io\/)?(library\/)?centos(:|$)/, () => 'CentOS'],
  [/^(docker\.io\/)?(library\/)?alpine:3\.(\d+)/, (m) => (Number(m[2]) < 18 ? `Alpine 3.${m[2]}` : null)],
  [/^(docker\.io\/)?(library\/)?php:(5|7\.|8\.0)/, (m) => `PHP ${m[3]}`],
  [/^(docker\.io\/)?(library\/)?(openjdk|java):/, () => 'deprecated openjdk image (use eclipse-temurin)'],
  [/^(docker\.io\/)?(library\/)?golang:1\.(\d+)\b/, (m) => (Number(m[2]) < 22 ? `Go 1.${m[2]}` : null)],
  [/^(docker\.io\/)?(library\/)?ruby:(2\.|3\.0)/, (m) => `Ruby ${m[3]}`],
];
const SENSITIVE_COPY = /(^|\/)(\.env(\.[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|\.ssh\/?|\.aws\/?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.docker\/config\.json|credentials\.json|service-account.*\.json|.*\.pem|.*\.key|.*\.p12|.*\.pfx|\.git\/?|kubeconfig|\.kube\/?|terraform\.tfstate)$/i;

/**
 * Lint one Dockerfile.
 * @param {string} text  @param {string} file  @param {{ dockerignore?: string|null }} ctx
 */
export function lintDockerfile(text, file, ctx = {}) {
  const ins = parseDockerfile(text); const raw = [];
  let shell = 'sh'; let pipefail = false;
  const directives = String(text).split(/\r?\n/).slice(0, 20); const syntax = directives.some((l) => /^#\s*syntax\s*=/i.test(l));
  const ign = inlineIgnores(text); const startOf = new Map();
  const add = (rule, line, message, extra = {}) => { const at = startOf.get(line) ?? line; if (ruleIgnored(rule, [...ign.global]) || ruleIgnored(rule, ign.byLine.get(at))) return; raw.push({ rule, file, line, location: `${file}:${line}`, message, ...(RULES[rule]?.cis ? { cis: RULES[rule].cis } : {}), ...extra }); };
  const stages = []; const argDefaults = {};
  for (const x of ins) {
    if (x.instruction === 'ARG' && !stages.length) { const [k, v] = (x.args.split('=')); argDefaults[k.trim()] = v?.trim(); }
    if (x.instruction === 'FROM') stages.push({ from: x, ins: [] }); else if (stages.length) stages[stages.length - 1].ins.push(x);
  }
  if (!stages.length) { add('parse-error', 1, 'No FROM instruction'); return raw; }
  const stageNames = new Set();
  for (const st of stages) {
    const { flags: f, rest } = flags(st.from.args); const [imgRaw, as, name] = rest.split(/\s+/);
    let img = imgRaw.replace(/\$\{?(\w+)(:-[^}]*)?\}?/g, (m0, v, d) => argDefaults[v] ?? (d ? d.slice(2) : m0));
    if (as?.toUpperCase() === 'AS' && name) st.name = name.toLowerCase();
    if (stageNames.has(img.toLowerCase()) || img === 'scratch' || /\$/.test(img)) { if (st.name) stageNames.add(st.name); continue; }
    if (st.name) stageNames.add(st.name);
    const noDigest = !img.includes('@sha256:'); const tag = img.split('@')[0].split('/').pop().split(':')[1];
    if (noDigest && (!tag || tag === 'latest')) add('base-image-latest', st.from.line, `FROM ${img} ${tag ? 'uses :latest' : 'has no tag'}`, { evidence: img, fix: 'Pin a version tag and ideally a digest: FROM image:1.2.3@sha256:…' });
    else if (noDigest) add('base-image-unpinned', st.from.line, `FROM ${img} is not pinned by digest`, { evidence: img, fix: 'Append @sha256:<digest> so rebuilds are reproducible; let Dependabot/Renovate bump it.' });
    for (const [re, fn] of EOL) { const m = img.match(re); const v = m && fn(m); if (v) { add('eol-base-image', st.from.line, `${v} is end-of-life (${img})`, { evidence: img, fix: 'Move to a supported release.' }); break; } }
  }
  const final = stages[stages.length - 1];
  let user = null;
  for (const x of final.ins) if (x.instruction === 'USER') user = { v: x.args.split(':')[0].trim(), line: x.line };
  const finalFrom = final.from.args.split(/\s+/).filter((w) => !w.startsWith('--'))[0];
  const inheritsStage = stageNames.has(finalFrom?.toLowerCase());
  if (!user && !inheritsStage && finalFrom !== 'scratch' && !/distroless.*nonroot|chainguard|:nonroot/.test(finalFrom || '')) add('run-as-root', final.from.line, 'No USER instruction: the container runs as root', { fix: 'Create an unprivileged user and add USER <name> (or a numeric UID) before CMD/ENTRYPOINT.' });
  else if (user && /^(root|0)$/.test(user.v)) add('run-as-root', user.line, `USER ${user.v}`, { fix: 'Switch to an unprivileged user for the final stage.' });
  if (!final.ins.some((x) => x.instruction === 'HEALTHCHECK')) add('no-healthcheck', final.from.line, 'Final stage has no HEALTHCHECK');
  for (const x of ins) {
    const body = x.heredoc ? `${x.args}\n${x.heredoc}` : x.args; const L = x.line;
    const sec = findSecret(body);
    if (sec) add('hardcoded-secret', L, `${sec.name} in ${x.instruction}: ${mask(sec.value)}`, { fix: 'Remove it, rotate the credential, and use BuildKit secrets (RUN --mount=type=secret) or runtime injection.' });
    if (x.instruction === 'ENV' || x.instruction === 'ARG') {
      for (const [k, v] of kvPairs(x.args)) {
        if (x.instruction === 'ENV' && v && isSecretAssignment(k, v) && !sec) add('secret-in-env', L, `ENV ${k} has a literal value (${mask(v)}) baked into every layer`, { evidence: k, fix: 'Inject at runtime (docker run -e / secrets) instead of ENV.' });
        if (x.instruction === 'ARG' && /(PASS|SECRET|TOKEN|KEY|CREDENTIAL)/i.test(k)) add('secret-in-arg', L, `ARG ${k} looks like a secret; build args are visible in docker history`, { evidence: k, fix: 'Use RUN --mount=type=secret,id=… and docker build --secret.' });
        if (/^(NODE_TLS_REJECT_UNAUTHORIZED)$/.test(k) && v === '0' || /^PYTHONHTTPSVERIFY$/.test(k) && v === '0' || /^GIT_SSL_NO_VERIFY$/.test(k) && v && v !== '0' && v !== 'false') add('insecure-tls', L, `${x.instruction} ${k}=${v} disables certificate verification`, { evidence: k });
      }
    }
    if (x.instruction === 'MAINTAINER') add('maintainer-deprecated', L, 'MAINTAINER is deprecated', { fix: 'Use LABEL org.opencontainers.image.authors="…".' });
    if (x.instruction === 'EXPOSE' && /(^|\s)22(\/tcp)?(\s|$)/.test(x.args)) add('ssh-server', L, 'EXPOSE 22 (SSH)', { fix: 'Use docker exec / kubectl exec instead of SSH inside containers.' });
    if (x.instruction === 'COPY' || x.instruction === 'ADD') {
      const { flags: f, rest } = flags(x.args); const parts = jsonOrWords(rest); const srcs = parts.slice(0, -1);
      for (const s of srcs) if (SENSITIVE_COPY.test(s.replace(/\/$/, '') ) || SENSITIVE_COPY.test(s)) add('copy-sensitive-file', L, `${x.instruction} ${s} puts credentials/keys/.git into the image`, { evidence: s, fix: 'Mount it as a BuildKit secret or keep it out of the image.' });
      if (!f.from && srcs.some((s) => s === '.' || s === './' || s === '*') && x.instruction === 'COPY' || (!f.from && x.instruction === 'ADD' && srcs.includes('.'))) {
        if (ctx.dockerignore === null) add('missing-dockerignore', L, `${x.instruction} ${srcs.join(' ')} copies the whole build context but there is no .dockerignore`, { fix: 'Add a .dockerignore with at least .git, .env*, *.pem, node_modules.' });
        else if (typeof ctx.dockerignore === 'string') { const di = ctx.dockerignore.split(/\r?\n/).map((l) => l.trim()); const miss = ['.git', '.env'].filter((p) => !di.some((l) => l === p || l === `${p}*` || l === `**/${p}` || l === `${p}/` || l === `/${p}` || (p === '.env' && /^\.env/.test(l)) || l === '*' || l === '**')); if (miss.length) add('missing-dockerignore', L, `.dockerignore does not exclude ${miss.join(', ')}`, { severity: 'low', fix: `Add ${miss.join(' and ')} to .dockerignore.` }); }
      }
      if (x.instruction === 'ADD') {
        const remote = srcs.filter((s) => /^https?:\/\//i.test(s));
        if (remote.length && !f.checksum) add('add-remote-url', L, `ADD ${remote[0]} without --checksum`, { fix: 'Use ADD --checksum=sha256:… or RUN curl + sha256sum -c.' });
        if (remote.some((s) => /^http:\/\//i.test(s))) add('http-download', L, `ADD over plain HTTP: ${remote.find((s) => /^http:/.test(s))}`);
        if (!remote.length && !srcs.some((s) => /\.(tar(\.(gz|bz2|xz|zst))?|tgz|tbz2?|txz)$/i.test(s) || /^git@|\.git$/.test(s))) add('add-instead-of-copy', L, 'ADD for local files: use COPY (ADD auto-extracts archives and fetches URLs)');
      }
    }
    if (x.instruction === 'SHELL') { const sh = jsonOrWords(x.args); shell = (sh[0] || 'sh').split('/').pop(); pipefail = sh.includes('pipefail'); }
    if (x.instruction === 'RUN') {
      const cmd = body;
      const mounts = [...x.args.matchAll(/--mount=(\S+)/g)].map((m) => Object.fromEntries(m[1].split(',').map((kv) => kv.split('='))));
      if ((mounts.length || x.heredoc) && !syntax) add('buildkit-syntax-missing', L, `RUN ${mounts.length ? '--mount' : 'heredoc'} needs BuildKit; add a syntax directive so older builders fail clearly`, { fix: 'Add "# syntax=docker/dockerfile:1" as the first line.' });
      for (const mt of mounts.filter((m) => m.type === 'secret')) {
        const target = mt.target || mt.dst || mt.destination || `/run/secrets/${mt.id || mt.source}`;
        const esc = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (new RegExp(`(cp|mv|install)\\s+[^;&|]*${esc}\\s+\\S|cat\\s+${esc}\\s*>{1,2}\\s*\\S|${esc}[^;&|]*\\|\\s*tee\\s`).test(cmd)) add('secret-mount-persisted', L, `RUN copies the BuildKit secret ${target} into the image filesystem`, { fix: 'Read the secret where it is used (e.g. --mount=type=secret,id=npmrc,target=/root/.npmrc) and never write it to a path that ends up in the layer.' });
      }
      for (const sc of shellChecks(x.heredoc ? x.heredoc : x.args, { shell, pipefail, heredoc: !!x.heredoc })) add(sc.rule, L, sc.message, { fix: sc.fix });
      if (/\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b|\b(ba)?sh\s+(-c\s+)?["']?\$\((curl|wget)\b|\bbash\s+<\(\s*(curl|wget)/i.test(cmd)) add('curl-pipe-shell', L, 'Downloads a script and pipes it straight into an interpreter', { fix: 'Download to a file, verify a checksum or signature, then run it.' });
      if (/\bcurl\b[^\n;&|]*\s(-k|--insecure)\b|\bwget\b[^\n;&|]*--no-check-certificate|\bpip3?\b[^\n;&|]*--trusted-host|npm\s+config\s+set\s+strict-ssl\s+false|yarn\s+config\s+set\s+strict-ssl\s+false|git\s+config\s+[^\n;&|]*http\.sslverify\s+false|NODE_TLS_REJECT_UNAUTHORIZED=0|--disable-ssl|sslverify=(0|false)/i.test(cmd)) add('insecure-tls', L, 'Disables TLS certificate verification', { fix: 'Fix the CA trust store instead (install ca-certificates or add your corporate CA).' });
      if (/--allow-unauthenticated|--force-yes|--nogpgcheck|gpgcheck=0|--allow-untrusted|--no-verify-signatures|AllowInsecureRepositories|--insecure-skip-tls-verify/i.test(cmd)) add('gpg-check-disabled', L, 'Package signature verification disabled', { fix: 'Import the repository key and keep signature checks on.' });
      if (/\b(curl|wget)\b[^\n;&|]*\bhttp:\/\/(?!localhost|127\.0\.0\.1)/i.test(cmd)) add('http-download', L, 'Downloads over plain HTTP', { fix: 'Use HTTPS and verify a checksum.' });
      if (/\bchmod\s+(-R\s+)?(0?777|a\+w|o\+w|666)\b/.test(cmd)) add('chmod-777', L, 'World-writable permissions', { fix: 'Grant only what is needed (e.g. 755 / 644) and chown to the app user.' });
      if (/(^|[;&|]\s*|\s)sudo\s/.test(cmd) || /(apt-get|apt|apk|yum|dnf|microdnf)\s+(-\S+\s+)*(install|add)\b[^;&|]*\bsudo\b/.test(cmd)) add('sudo-usage', L, 'sudo in the image', { fix: 'Builds already run as root; drop sudo and use USER for runtime.' });
      if (/(apt-get|apt|apk|yum|dnf)\s+(-\S+\s+)*(install|add)\b[^;&|]*\bopenssh-server\b/.test(cmd)) add('ssh-server', L, 'Installs an SSH server');
      if (/apt(-get)?\s+(-\S+\s+)*(upgrade|dist-upgrade)\b/.test(cmd)) add('apt-upgrade', L, 'apt-get upgrade makes builds non-reproducible', { fix: 'Use a newer base image instead.' });
      if (/apt-get\s+(-\S+\s+)*install/.test(cmd) && !/rm\s+-rf\s+\/var\/lib\/apt\/lists|--mount=type=cache/.test(cmd)) add('pkg-cache-not-cleaned', L, 'apt lists not removed (rm -rf /var/lib/apt/lists/*)');
      if (/apk\s+(-\S+\s+)*add/.test(cmd) && !/--no-cache|rm\s+-rf\s+\/var\/cache\/apk/.test(cmd)) add('pkg-cache-not-cleaned', L, 'apk add without --no-cache');
    }
  }
  return raw;
}
