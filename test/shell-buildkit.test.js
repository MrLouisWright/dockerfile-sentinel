import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TOOL, lintDockerfile, findSecret, SECRET_PATTERNS, RULES, formatSarif, lint as check } from '../src/index.js';
import { shellChecks, splitCommands } from '../src/shell.js';
import { inlineIgnores } from '../src/dockerfile.js';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const rules = (text) => lintDockerfile(text, 'Dockerfile', { dockerignore: '.git\n.env\n' }).map((f) => f.rule);
const base = 'FROM node:22.1.0@sha256:abc\nUSER node\nHEALTHCHECK CMD true\n';

test('secret patterns are the shared bundle-secret-guard set', () => {
  assert.ok(SECRET_PATTERNS.some(([, , r]) => r?.id === 'npm-token'));
  assert.equal(findSecret('ENV T=npm_' + 'a'.repeat(36)).id, 'npm-token');
  assert.equal(findSecret('postgres://u:${PASS}@db/x'), null);
});
test('splitCommands is quote-aware', () => {
  assert.deepEqual(splitCommands('a && b "x && y" | c; d').map((x) => x.text), ['a', 'b "x && y"', 'c', 'd']);
});
test('shell checks: apt, pip, npm, cd, pipefail, rm', () => {
  const r = shellChecks('cd /app && apt-get update && apt-get install curl wget | tee log; pip install requests && npm install && rm -rf $DIR/').map((x) => x.rule);
  for (const x of ['cd-instead-of-workdir', 'apt-missing-yes', 'apt-no-install-recommends', 'apt-unpinned', 'missing-pipefail', 'semicolon-chain', 'pip-no-cache-dir', 'pip-unpinned', 'npm-install-not-ci', 'unquoted-variable']) assert.ok(r.includes(x), x);
  assert.deepEqual(shellChecks('apt-get update && apt-get install -y --no-install-recommends curl=8.0 && rm -rf "${DIR:?}"/x').map((x) => x.rule), []);
  assert.ok(shellChecks('apt-get update').some((x) => x.rule === 'apt-update-alone'));
});
test('SHELL with pipefail satisfies missing-pipefail', () => {
  assert.ok(rules(base + 'RUN curl -fsSL https://x/a | tar x\n').includes('missing-pipefail'));
  assert.ok(!rules(base + 'SHELL ["/bin/bash", "-o", "pipefail", "-c"]\nRUN curl -fsSL https://x/a | tar x\n').includes('missing-pipefail'));
});
test('BuildKit: secret mounts persisted, syntax directive, heredoc bodies checked', () => {
  const r = rules(base + 'RUN --mount=type=secret,id=npmrc cp /run/secrets/npmrc /root/.npmrc && npm ci\n');
  assert.ok(r.includes('secret-mount-persisted')); assert.ok(r.includes('buildkit-syntax-missing'));
  assert.ok(!rules('# syntax=docker/dockerfile:1\n' + base + 'RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci\n').some((x) => x === 'secret-mount-persisted' || x === 'buildkit-syntax-missing'));
  assert.ok(rules('# syntax=docker/dockerfile:1\n' + base + 'RUN <<EOF\napt-get install curl\nEOF\n').includes('apt-missing-yes'));
});
test('hadolint and dockerfile-sentinel inline ignores', () => {
  const t = base + '# hadolint ignore=DL3008,DL3015\nRUN apt-get update && apt-get install -y curl\n';
  const r = rules(t);
  assert.ok(!r.includes('apt-unpinned') && !r.includes('apt-no-install-recommends'));
  assert.ok(!rules(base + '# dockerfile-sentinel ignore=npm-install-not-ci\nRUN npm install\n').includes('npm-install-not-ci'));
  assert.ok(!rules('# hadolint global ignore=DL3006\nFROM node\nUSER node\n').includes('base-image-latest'));
  assert.equal(inlineIgnores('# hadolint ignore=DL3008\n\nRUN x').byLine.get(3)[0], 'DL3008');
});
test('CIS Docker Benchmark mapping in findings and SARIF tags', () => {
  assert.equal(RULES['run-as-root'].cis, '4.1'); assert.deepEqual(RULES['apt-unpinned'].hadolint, ['DL3008']);
  const f = lintDockerfile('FROM node:22\n', 'Dockerfile', {}).find((x) => x.rule === 'run-as-root');
  assert.equal(f.cis, '4.1');
  const d = mkdtempSync(join(tmpdir(), 'dk-')); writeFileSync(join(d, 'Dockerfile'), 'FROM node:22\n');
  const sarif = JSON.parse(formatSarif(check([d]), TOOL));
  const rule = sarif.runs[0].tool.driver.rules.find((x) => x.id === 'run-as-root');
  assert.ok(rule.properties.tags.includes('CIS-Docker-4.1')); assert.ok(rule.properties.tags.includes('DL3002'));
});
