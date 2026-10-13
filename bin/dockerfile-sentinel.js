#!/usr/bin/env node
import { runCli, UsageError } from '../src/cli-core.js';
import { lint, TOOL } from '../src/index.js';

const HELP = `dockerfile-sentinel {VERSION} — security linter for Dockerfiles and Docker Compose files

Usage: dockerfile-sentinel [Dockerfile|compose.yml|dir...] [options]

Directories (default: .) are searched for Dockerfile, *.Dockerfile, Dockerfile.*, Containerfile,
docker-compose*.yml and compose*.yaml. A .dockerignore next to each Dockerfile is checked.

      --context <dir>        Build context to look for .dockerignore (default: the Dockerfile's directory)
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { context: { type: 'string' } },
  run(o, pos, cfg) {
    const paths = pos.length ? pos : cfg.paths || ['.'];
    if (!paths.length) throw new UsageError('Nothing to lint');
    return lint(paths, { context: o.context || cfg.context, allow: cfg.allow, severity: cfg.severity });
  },
});
