# Changelog

## 1.0.0 - 2026-10-14

- First release: Dockerfile and Docker Compose security linter with 32 rules (root user, secrets, curl | sh, TLS bypass, remote ADD, EOL and unpinned base images, .dockerignore checks, privileged services, socket mounts, host namespaces, dangerous capabilities, exposed databases).
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
