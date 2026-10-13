import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { exitCode, lint, lintDockerfile, lintCompose, parseDockerfile } from '../src/index.js';
const F = new URL('./fixtures/', import.meta.url).pathname;
const rules = (fs) => new Set(fs.map((f) => f.rule));

test('parser handles continuations, comments and JSON form', () => {
  const ins = parseDockerfile('FROM a\n# c\nRUN echo 1 \\\n  && echo 2\nCMD ["x"]\n');
  assert.deepEqual(ins.map((i) => i.instruction), ['FROM', 'RUN', 'CMD']);
  assert.equal(ins[1].line, 3);
});
test('bad Dockerfile triggers core rules', () => {
  const r = lint([F + 'bad/Dockerfile']);
  const s = rules(r.findings);
  for (const k of ['hardcoded-secret', 'curl-pipe-shell', 'insecure-tls', 'run-as-root', 'secret-in-env', 'add-remote-url', 'chmod-777', 'eol-base-image', 'missing-dockerignore', 'copy-sensitive-file', 'base-image-unpinned']) assert.ok(s.has(k), k);
  assert.equal(exitCode(r, 'high'), 1);
});
test('good Dockerfile is clean', () => { const r = lint([F + 'good/Dockerfile']); assert.equal(r.findings.length, 0); assert.equal(exitCode(r, 'high'), 0); });
test('secrets are masked', () => { const r = lint([F + 'bad']); assert.ok(!JSON.stringify(r).includes('AKIAIOSFODNN7EXAMPLE')); assert.ok(!JSON.stringify(r).includes('ghp_abcdefghijklmnopqrstuvwxyz0123456789AB')); });
test('compose rules', () => {
  const s = rules(lintCompose(require_('bad/docker-compose.yml'), 'c.yml'));
  for (const k of ['compose-privileged', 'compose-docker-socket', 'compose-host-namespace', 'compose-dangerous-cap', 'compose-security-opt', 'compose-sensitive-mount', 'compose-secret-env', 'compose-exposed-port', 'compose-image-latest']) assert.ok(s.has(k), k);
});
test('compose: localhost ports, interpolated env and NET_BIND_SERVICE are fine', () => {
  const f = lintCompose('services:\n  a:\n    image: x:1\n    cap_add: [NET_BIND_SERVICE]\n    ports: ["127.0.0.1:5432:5432", "8080:80"]\n    environment:\n      PASSWORD: ${PASSWORD}\n', 'c.yml');
  assert.deepEqual(f, []);
});
test('USER root at end flagged; USER app fine', () => {
  assert.ok(rules(lintDockerfile('FROM a@sha256:' + '0'.repeat(64) + '\nUSER root\n', 'D', { dockerignore: '' })).has('run-as-root'));
  assert.ok(!rules(lintDockerfile('FROM a@sha256:' + '0'.repeat(64) + '\nUSER app\n', 'D', { dockerignore: '' })).has('run-as-root'));
});
test('allowlist and severity override', () => {
  const r = lint([F + 'bad/Dockerfile'], { allow: [{ rule: 'run-as-root', reason: 'test' }], severity: { 'curl-pipe-shell': 'off' } });
  const s = rules(r.findings); assert.ok(!s.has('run-as-root')); assert.ok(!s.has('curl-pipe-shell'));
});
test('in-memory input', () => { const r = lint([{ name: 'Dockerfile', text: 'FROM scratch\nUSER 1\nHEALTHCHECK NONE\n', dockerignore: '' }]); assert.ok(Array.isArray(r.findings)); });
test('CLI formats and exit codes', () => {
  const bin = new URL('../bin/dockerfile-sentinel.js', import.meta.url).pathname;
  for (const fmt of ['json', 'sarif', 'markdown', 'text']) { const p = spawnSync('node', [bin, F + 'bad', '--format', fmt]); assert.equal(p.status, 1, fmt); assert.ok(p.stdout.length > 0); }
  JSON.parse(execFileSync('node', [bin, F + 'bad', '--format', 'sarif', '--fail-on', 'none']));
  assert.equal(spawnSync('node', [bin, F + 'good']).status, 0);
  assert.equal(spawnSync('node', [bin, '--bogus']).status, 2);
  assert.equal(spawnSync('node', [bin, '/nonexistent/x']).status, 2);
});
import { readFileSync } from 'node:fs';
function require_(p) { return readFileSync(F + p, 'utf8'); }
