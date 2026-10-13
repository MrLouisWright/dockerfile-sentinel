import { parseYaml } from './yaml.js';
import { findSecret, isSecretAssignment, mask } from './secrets.js';

const DANGEROUS_CAPS = { ALL: 'critical', SYS_ADMIN: 'critical', SYS_PTRACE: 'high', SYS_MODULE: 'critical', DAC_READ_SEARCH: 'high', NET_ADMIN: 'high', SYS_RAWIO: 'high', BPF: 'high', PERFMON: 'medium', NET_RAW: 'medium', SYS_BOOT: 'high', MKNOD: 'medium', SETFCAP: 'medium' };
const SENSITIVE_HOST = /^(\/|\/etc(\/.*)?|\/proc(\/.*)?|\/sys(\/.*)?|\/root(\/.*)?|\/boot|\/dev(\/.*)?|\/var\/run|\/run|\/var\/lib\/docker(\/.*)?|\/var\/lib\/kubelet|\/home|\/lib\/modules|~\/\.ssh|\/usr)$/;
const DB_PORTS = { 22: 'SSH', 2375: 'Docker API (unauthenticated)', 2376: 'Docker API', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 9300: 'Elasticsearch', 11211: 'Memcached', 5984: 'CouchDB', 8086: 'InfluxDB', 9042: 'Cassandra', 1433: 'SQL Server', 1521: 'Oracle', 5672: 'RabbitMQ', 15672: 'RabbitMQ admin', 6443: 'Kubernetes API', 10250: 'kubelet', 2379: 'etcd', 8500: 'Consul', 4444: 'Selenium/WebDriver' };

export function lintCompose(text, file) {
  const raw = []; const lines = String(text).split(/\r?\n/);
  let doc; try { doc = parseYaml(text); } catch (e) { return [{ rule: 'parse-error', file, line: 1, location: `${file}:1`, message: `YAML parse error: ${e.message}` }]; }
  const services = doc?.services && typeof doc.services === 'object' ? doc.services : null;
  if (!services) return raw;
  // line lookup: first line after the service header containing the needle
  const svcLine = (name) => { const i = lines.findIndex((l) => new RegExp(`^\\s+["']?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?\\s*:`).test(l)); return i + 1 || 1; };
  const lineOf = (svc, needle) => { const s = svcLine(svc); for (let i = s; i < lines.length; i++) { if (i > s && /^\s{0,2}[\w"'-]+\s*:/.test(lines[i]) && !/^\s{3,}/.test(lines[i]) && lines[i].search(/\S/) <= (lines[s - 1].search(/\S/))) break; if (lines[i].includes(needle)) return i + 1; } return s; };
  for (const [name, svc0] of Object.entries(services)) {
    const svc = svc0 || {}; const add = (rule, needle, message, extra = {}) => { const line = lineOf(name, needle); raw.push({ rule, file, line, location: `${file}:${line} (${name})`, message: `${name}: ${message}`, ...extra }); };
    if (svc.privileged === true || svc.privileged === 'true') add('compose-privileged', 'privileged', 'privileged: true gives the container full access to the host', { fix: 'Remove privileged and add only the capabilities/devices you need.' });
    for (const ns of ['network_mode', 'pid', 'ipc', 'uts', 'userns_mode']) if (svc[ns] === 'host') add('compose-host-namespace', ns, `${ns}: host shares the host ${ns.replace(/_mode$/, '')} namespace`, { severity: ns === 'pid' ? 'critical' : undefined });
    for (const c of [].concat(svc.cap_add || [])) { const cap = String(c).toUpperCase().replace(/^CAP_/, ''); if (DANGEROUS_CAPS[cap]) add('compose-dangerous-cap', String(c), `cap_add ${cap}`, { severity: DANGEROUS_CAPS[cap], evidence: cap, fix: 'Drop the capability; use cap_drop: [ALL] and add back only what is required.' }); }
    for (const o of [].concat(svc.security_opt || [])) if (/(seccomp|apparmor)[:=]unconfined|label[:=]disable|no-new-privileges[:=]false/i.test(String(o))) add('compose-security-opt', String(o).split(/[:=]/)[0], `security_opt ${o}`, { evidence: String(o) });
    for (const v of [].concat(svc.volumes || [])) {
      const src = typeof v === 'string' ? v.split(':')[0] : v?.source; const ro = typeof v === 'string' ? /:ro(,|$)|:ro$/.test(v) : v?.read_only === true;
      if (!src) continue;
      if (/docker\.sock|podman\.sock|containerd\.sock|crio\.sock/.test(src)) add('compose-docker-socket', src, `mounts ${src}${ro ? ' (read-only still allows full API control)' : ''}: root on the host`, { fix: 'Use a socket proxy with an allowlist (e.g. tecnativa/docker-socket-proxy) or avoid it.' });
      else if (SENSITIVE_HOST.test(src.replace(/\/$/, '') || '/')) add('compose-sensitive-mount', src, `mounts host path ${src}${ro ? ' read-only' : ' read-write'}`, { severity: ro ? 'medium' : undefined });
    }
    for (const d of [].concat(svc.devices || [])) if (/^\/dev\/(mem|kmem|sd[a-z]|nvme|disk)/.test(String(d))) add('compose-sensitive-mount', String(d).split(':')[0], `device ${d} passed through`);
    const env = Array.isArray(svc.environment) ? svc.environment.map((e) => { const s = String(e); const i = s.indexOf('='); return i < 0 ? [s, undefined] : [s.slice(0, i), s.slice(i + 1)]; }) : Object.entries(svc.environment || {});
    for (const [k, v] of env) {
      if (v === undefined || v === null) continue;
      const sec = findSecret(String(v));
      if (sec) add('compose-secret-env', k, `${k} contains a ${sec.name} (${mask(sec.value)})`, { severity: 'critical', evidence: k, fix: 'Rotate it and use Compose secrets or an env_file kept out of version control.' });
      else if (isSecretAssignment(k, v)) add('compose-secret-env', k, `${k} has a literal value (${mask(v)})`, { evidence: k, fix: 'Use ${VAR} interpolation from an untracked .env, or Compose secrets.' });
    }
    for (const p of [].concat(svc.ports || [])) {
      let host, target, ip;
      if (typeof p === 'object' && p) { target = p.target; host = p.published; ip = p.host_ip; }
      else { const s = String(p).replace(/\/(tcp|udp)$/, ''); const parts = s.split(':'); target = parts.pop(); host = parts.pop() ?? target; ip = parts.join(':') || undefined; }
      const port = Number(String(target).split('-')[0]);
      if (DB_PORTS[port] && (!ip || ip === '0.0.0.0' || ip === '::')) add('compose-exposed-port', String(typeof p === 'object' ? target : p), `publishes ${DB_PORTS[port]} port ${port} on all interfaces`, { severity: [2375, 10250, 2379].includes(port) ? 'critical' : undefined, fix: `Bind to localhost ("127.0.0.1:${host}:${target}") or keep it on an internal network.` });
    }
    if (svc.image && typeof svc.image === 'string' && !svc.image.includes('@sha256:') && !/\$/.test(svc.image)) { const tag = svc.image.split('/').pop().split(':')[1]; if (!tag || tag === 'latest') add('compose-image-latest', svc.image, `image ${svc.image} ${tag ? 'uses :latest' : 'has no tag'}`, { evidence: svc.image }); }
  }
  return raw;
}
