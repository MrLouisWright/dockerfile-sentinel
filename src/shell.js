// ShellCheck/hadolint-style checks for RUN commands (and RUN heredocs).
/** Split a shell command into simple commands on && || ; | (quote-aware, rough). */
export function splitCommands(cmd) {
  const out = []; let cur = ''; let q = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    const two = cmd.slice(i, i + 2);
    if (two === '&&' || two === '||') { out.push({ text: cur.trim(), sep: two }); cur = ''; i++; continue; }
    if (c === ';' || c === '|' || c === '\n') { out.push({ text: cur.trim(), sep: c }); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push({ text: cur.trim(), sep: null });
  return out.filter((x) => x.text);
}

/**
 * Check one RUN body. Returns [{ rule, message, fix }].
 * ctx: { shell: 'sh'|'bash'|'pwsh', heredoc: boolean, pipefail: boolean }
 */
export function shellChecks(cmd, ctx = {}) {
  const out = []; const add = (rule, message, fix) => out.push({ rule, message, fix });
  if (/^(pwsh|powershell|cmd)/i.test(ctx.shell || '')) return out;
  const parts = splitCommands(cmd.replace(/^--mount=\S+\s+|^--network=\S+\s+|^--security=\S+\s+/g, ''));
  const words = (t) => t.split(/\s+/);
  const hasPipe = parts.some((p) => p.sep === '|');
  if (hasPipe && !ctx.pipefail && !/set\s+-[a-z]*o\s+pipefail|set\s+-o\s+pipefail/.test(cmd)) add('missing-pipefail', 'RUN uses a pipe without "set -o pipefail": a failing first command is ignored', 'Add SHELL ["/bin/bash", "-o", "pipefail", "-c"] before it, or start the RUN with set -o pipefail &&.');
  if (parts.some((p) => p.sep === ';') && !ctx.heredoc && !/set\s+-e/.test(cmd)) add('semicolon-chain', 'Commands chained with ";" keep going after a failure', 'Chain with && (or set -e) so the build stops on the first error.');
  for (const p of parts) {
    const w = words(p.text); const [c0, c1] = w;
    if (c0 === 'cd' && !ctx.heredoc) add('cd-instead-of-workdir', `"${p.text}" in RUN: use WORKDIR to change directory`, 'Use WORKDIR /path (it also documents the image layout).');
    if (/^(apt-get|apt)$/.test(c0) && w.includes('install')) {
      if (!w.some((x) => /^-(y|qq?y|yq+)$|^--yes$|^--assume-yes$/.test(x))) add('apt-missing-yes', `${c0} install without -y waits for input and fails the build`, 'Use apt-get install -y.');
      if (!w.includes('--no-install-recommends')) add('apt-no-install-recommends', `${c0} install without --no-install-recommends pulls in extra packages`, 'Add --no-install-recommends.');
      const pkgs = w.slice(w.indexOf('install') + 1).filter((x) => !x.startsWith('-') && !x.startsWith('$'));
      if (pkgs.length && pkgs.every((x) => !x.includes('='))) add('apt-unpinned', `${c0} install of unpinned packages (${pkgs.slice(0, 3).join(', ')}${pkgs.length > 3 ? ', …' : ''})`, 'Pin versions (pkg=1.2.3-1) for reproducible builds, or accept the drift and allowlist it.');
    }
    if (c0 === 'apt') add('apt-cli', '"apt" is meant for interactive use; its CLI is not stable in scripts', 'Use apt-get / apt-cache.');
    if (/^pip3?$/.test(c0) && c1 === 'install' && !w.includes('--no-cache-dir') && !/--mount=type=cache/.test(cmd)) add('pip-no-cache-dir', `${c0} install without --no-cache-dir leaves the wheel cache in the layer`, 'Add --no-cache-dir (or use RUN --mount=type=cache,target=/root/.cache/pip).');
    if (/^pip3?$/.test(c0) && c1 === 'install' && w.slice(2).some((x) => /^[A-Za-z][\w.-]*$/.test(x)) && !w.some((x) => x === '-r' || x.startsWith('--requirement') || x === '.' || /[=<>~]/.test(x))) add('pip-unpinned', `${c0} install of unpinned packages`, 'Pin versions (pkg==1.2.3) or install from a lock/requirements file.');
    if (c0 === 'npm' && (c1 === 'install' || c1 === 'i') && w.length === 2) add('npm-install-not-ci', 'npm install in an image build can change the lockfile', 'Use npm ci (with --omit=dev for production images).');
    if (c0 === 'rm' && w.some((x) => /^-[a-z]*r[a-z]*f|^-[a-z]*f[a-z]*r/i.test(x)) && w.some((x) => /^\$\{?\w+\}?(\/|$)/.test(x))) add('unquoted-variable', `"${p.text}": unquoted variable in rm -rf; if it is empty this deletes from /`, 'Quote it and guard it: rm -rf "${DIR:?}"/…');
    if (c0 === 'sudo') continue;
    if (/^(useradd)$/.test(c0) && !w.includes('-l') && !w.includes('--no-log-init') && w.some((x) => /^\d{6,}$/.test(x))) add('useradd-no-log-init', 'useradd with a large UID and without -l can create a huge /var/log/lastlog', 'Add -l (--no-log-init).');
  }
  if (/\bwget\b/.test(cmd) && /\bcurl\b/.test(cmd)) add('wget-and-curl', 'Both wget and curl are used; pick one', 'Use one download tool to keep the image small.');
  const upd = parts.findIndex((p) => /^(apt-get|apt)\s+update\b/.test(p.text));
  if (upd !== -1 && !parts.some((p, i) => i > upd && /^(apt-get|apt)\s.*\binstall\b/.test(p.text))) add('apt-update-alone', 'apt-get update in a RUN without install: the cached layer goes stale', 'Run apt-get update && apt-get install -y … in the same RUN.');
  return out;
}
