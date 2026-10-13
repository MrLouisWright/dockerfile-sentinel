# dockerfile-sentinel

> Security linter for Dockerfiles and Docker Compose files: root containers, baked-in secrets, curl | sh, unpinned and end-of-life base images, privileged services, Docker socket mounts and exposed databases.

`dockerfile-sentinel` reads Dockerfiles, Containerfiles and Compose files and reports security problems with a line number and a fix. CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**. Nothing is built or pulled; files are only parsed. Secrets are masked in every output.

## What it checks

- **Dockerfiles**: final stage running as root, secrets in `ENV`/`ARG`/`RUN` (AWS, GitHub, Slack, Stripe, private keys and more), `curl … | sh`, disabled TLS verification, `ADD` of remote URLs without `--checksum`, HTTP downloads, `chmod 777`, base images that are end-of-life (Node, Python, Debian, Ubuntu, Alpine, CentOS…) or not pinned by digest, `COPY .` with no `.dockerignore`, copying `.env`/keys/`.git` into the image, SSH servers, sudo, `apt-get upgrade`, uncleaned package caches, missing `HEALTHCHECK`, deprecated `MAINTAINER`.
- **Compose**: `privileged`, Docker/containerd socket mounts, host network/PID/IPC namespaces, dangerous capabilities (`SYS_ADMIN`, `ALL`…), `seccomp/apparmor:unconfined`, sensitive host paths (`/`, `/etc`, `/proc`…), literal secrets in `environment`, databases and admin APIs published on all interfaces, `:latest`/untagged images.

Directories are searched for `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile`, `docker-compose*.yml` and `compose*.yaml` (skipping `.git` and `node_modules`). A `.dockerignore` next to each Dockerfile, or in `--context`, is taken into account.

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `hardcoded-secret` | critical | Hardcoded credential or private key |
| `secret-in-env` | high | Secret-looking ENV value baked into the image |
| `secret-in-arg` | medium | Secret passed as a build ARG (visible in image history) |
| `copy-sensitive-file` | high | COPY/ADD of keys, .env, cloud credentials or .git |
| `missing-dockerignore` | medium | Build context copied without a .dockerignore (or it misses .git/.env) |
| `run-as-root` | high | Final stage runs as root |
| `sudo-usage` | medium | sudo installed or used |
| `base-image-latest` | medium | Base image uses :latest or no tag |
| `base-image-unpinned` | low | Base image not pinned by digest |
| `eol-base-image` | medium | End-of-life base image |
| `curl-pipe-shell` | high | Remote script piped into a shell |
| `insecure-tls` | high | TLS certificate verification disabled |
| `gpg-check-disabled` | high | Package signature checks disabled |
| `add-remote-url` | medium | ADD from a URL without --checksum |
| `add-instead-of-copy` | low | ADD used for local files (use COPY) |
| `http-download` | medium | Plain-HTTP download during build |
| `chmod-777` | medium | World-writable permissions (chmod 777 / a+w) |
| `ssh-server` | medium | SSH server installed or port 22 exposed |
| `apt-upgrade` | low | apt-get upgrade / dist-upgrade in image build |
| `pkg-cache-not-cleaned` | info | Package manager cache left in the layer |
| `no-healthcheck` | info | No HEALTHCHECK in final stage |
| `maintainer-deprecated` | info | MAINTAINER is deprecated (use LABEL) |
| `parse-error` | medium | File could not be parsed |
| `compose-privileged` | critical | Compose service runs privileged |
| `compose-docker-socket` | critical | Docker socket mounted into a container |
| `compose-host-namespace` | high | Host network/PID/IPC/UTS/userns namespace shared |
| `compose-dangerous-cap` | high | Dangerous Linux capability added |
| `compose-security-opt` | high | seccomp/AppArmor/SELinux disabled |
| `compose-sensitive-mount` | high | Sensitive host path mounted |
| `compose-secret-env` | high | Literal secret in service environment |
| `compose-exposed-port` | medium | Database/admin port published on all interfaces |
| `compose-image-latest` | low | Service image uses :latest or no tag |

## Install and run

```bash
npx dockerfile-sentinel                      # scan the current directory
npx dockerfile-sentinel Dockerfile docker-compose.yml --fail-on medium
npx dockerfile-sentinel services/ --format sarif > docker.sarif
```

## Library

```js
import { lint, exitCode } from 'dockerfile-sentinel';
const report = lint(['.'], { severity: { 'no-healthcheck': 'off' } });
process.exitCode = exitCode(report, 'high');
```

## Configuration

Put a `.dockerfile-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "run-as-root": "high" },
  "allow": [
    { "rule": "run-as-root", "match": "docker/debug.Dockerfile*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `run-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/dockerfile-sentinel@v1
    with:
      targets: '.'
      fail-on: high
      sarif: dockerfile-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: dockerfile-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags). Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## License

MIT © Louis Wright
