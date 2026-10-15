// Provider credential patterns come from bundle-secret-guard's shared rule set; this file only
// adds Dockerfile/Compose-specific heuristics (secret-looking variable names, placeholders).
import { RULES as SHARED_RULES } from 'bundle-secret-guard/patterns';

const SKIP_SHARED = new Set(['generic-secret', 'stripe-publishable-key', 'stripe-test-secret-key']);
/** [name, RegExp, rule] for every shared provider pattern. */
export const SECRET_PATTERNS = [
  ...SHARED_RULES.filter((r) => !SKIP_SHARED.has(r.id)).map((r) => [r.id === 'database-url' ? 'password in URL' : r.title, r.re, r]),
  ['password in URL', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s/@$]{3,}@[^\s]+/i, null],
];
export const SECRET_NAME = /(^|_)(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH|CLIENT_SECRET|DB_PASS|SIGNING_KEY|ENCRYPTION_KEY|SAS)($|_)/i;
const PLACEHOLDER = /^(|changeme|change_me|example|dummy|test|placeholder|xxx+|<.*>|\$\{?[A-Za-z_][\w]*\}?.*|\*+|none|null|false|true|0|1|yes|no|\/run\/secrets\/.*|\/.*_file|.*_FILE)$/i;
export function findSecret(text) {
  const v = String(text);
  for (const [name, re, rule] of SECRET_PATTERNS) {
    const m = new RegExp(re.source, re.flags.replace('g', '')).exec(v); if (!m) continue;
    if (rule?.check && !rule.check(m)) continue;
    if (name === 'password in URL' && /:\$\{?\w+\}?@/.test(m[0])) continue; // ${VAR} placeholder
    return { name, value: rule?.id === 'aws-secret-access-key' ? m[1] : m[0], id: rule?.id || 'url-credentials' };
  }
  return null;
}
export function isSecretAssignment(key, value) { return SECRET_NAME.test(key) && !/_FILE$|_PATH$|_URL$|_HOST$|_USER(NAME)?$|_NAME$|_ID$|_ENABLED$|_LENGTH$/i.test(key) && !PLACEHOLDER.test(String(value ?? '').trim().replace(/^["']|["']$/g, '')); }
export const mask = (v) => { const s = String(v); return s.length <= 6 ? '***' : `${s.slice(0, 3)}…${s.slice(-2)} (${s.length} chars)`; };
