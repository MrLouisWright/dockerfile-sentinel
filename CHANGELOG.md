# Changelog

## 1.1.0 - 2026-10-17

Re-release: these changes were committed after 1.0.0 was published but never reached npm. 1.0.0 on npm is the original first release.

### Added

- ShellCheck/hadolint-style checks on `RUN` commands and RUN heredocs: `missing-pipefail` (DL4006, `SHELL [... "-o", "pipefail" ...]` is honoured), `semicolon-chain`, `cd-instead-of-workdir` (DL3003), `apt-missing-yes` (DL3014), `apt-no-install-recommends` (DL3015), `apt-unpinned` (DL3008), `apt-cli` (DL3027), `apt-update-alone`, `pip-no-cache-dir` (DL3042), `pip-unpinned` (DL3013), `npm-install-not-ci`, `unquoted-variable` in `rm -rf` (SC2086/SC2115), `useradd-no-log-init` (DL3046), `wget-and-curl` (DL4001).
- BuildKit: `secret-mount-persisted` (a `--mount=type=secret` copied into the layer) and `buildkit-syntax-missing` (`--mount` or heredocs without `# syntax=`).
- CIS Docker Benchmark IDs on rules (`RULES[id].cis`, a `cis` field on findings, `CIS-Docker-x.y` SARIF tags) and hadolint codes (`RULES[id].hadolint`).
- Inline ignores: `# hadolint ignore=DL3008,SC2086` (mapped to the matching rules), `# dockerfile-sentinel ignore=<rule>` and the `global ignore=` forms.
- Hardcoded-credential detection now uses the shared provider patterns from `bundle-secret-guard/patterns` instead of a private list.
- Kubernetes/Helm manifests are deliberately out of scope, since they would fit better in a separate package.

### Packaging

- Dual ESM + CommonJS: `import` loads `src/`, `require` loads a bundled `dist/index.cjs`, via package.json `exports`.
- TypeScript declarations are generated from the source (`dist/types`) instead of hand-written.
- CI runs build, tests and a require+import check on Node 18/20/22; releases use `npm publish --provenance`.

## 1.0.0 - 2026-10-14

- First release: Dockerfile and Docker Compose security linter with 32 rules (root user, secrets, curl | sh, TLS bypass, remote ADD, EOL and unpinned base images, .dockerignore checks, privileged services, socket mounts, host namespaces, dangerous capabilities, exposed databases).
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
