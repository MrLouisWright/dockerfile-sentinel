// Minimal YAML subset reader for lockfiles (pnpm-lock.yaml, yarn berry yarn.lock).
// Supports block maps, block sequences, quoted/plain scalars and simple flow maps/sequences.

function unquote(s) {
  s = s.trim();
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) { try { return JSON.parse(s); } catch { return s.slice(1, -1); } }
  if (s.startsWith("'") && s.endsWith("'") && s.length >= 2) return s.slice(1, -1).replace(/''/g, "'");
  return s;
}
function splitFlow(s) {
  const out = []; let depth = 0, q = null, cur = '';
  for (const ch of s) {
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === '{' || ch === '[') depth++;
    if (ch === '}' || ch === ']') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}
function keyColon(s) {
  // index of the ':' that ends the key (outside quotes, followed by space or EOL)
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === q) q = null; continue; }
    if ((ch === '"' || ch === "'") && i === 0) { q = ch; continue; }
    if (ch === ':' && (i === s.length - 1 || s[i + 1] === ' ')) return i;
  }
  return -1;
}
function scalar(s) {
  s = s.trim();
  if (s.startsWith('{') && s.endsWith('}')) {
    const o = {};
    for (const part of splitFlow(s.slice(1, -1))) { const i = keyColon(part.trim()); if (i > 0) o[unquote(part.trim().slice(0, i))] = scalar(part.trim().slice(i + 1)); }
    return o;
  }
  if (s.startsWith('[') && s.endsWith(']')) return splitFlow(s.slice(1, -1)).map(scalar);
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~' || s === '') return s === '' ? '' : null;
  return unquote(s);
}

export function parseYaml(text) {
  const lines = [];
  for (const raw of text.split(/\r?\n/)) {
    if (/^\s*(#.*)?$/.test(raw)) continue;
    const indent = raw.match(/^ */)[0].length;
    let content = raw.slice(indent);
    if (!/^["']/.test(content)) content = content.replace(/\s+#.*$/, '');
    lines.push({ indent, content });
  }
  let i = 0;
  function block(indent) {
    if (i >= lines.length) return null;
    if (lines[i].content.startsWith('- ') || lines[i].content === '-') {
      const arr = [];
      while (i < lines.length && lines[i].indent === indent && (lines[i].content.startsWith('- ') || lines[i].content === '-')) {
        const rest = lines[i].content.slice(2);
        i++;
        if (!rest.trim()) arr.push(i < lines.length && lines[i].indent > indent ? block(lines[i].indent) : null);
        else if (keyColon(rest) > 0) { // "- key: value" mapping item
          lines.splice(i, 0, { indent: indent + 2, content: rest });
          arr.push(block(indent + 2));
        } else arr.push(scalar(rest));
      }
      return arr;
    }
    const obj = {};
    while (i < lines.length && lines[i].indent === indent) {
      const { content } = lines[i];
      const c = keyColon(content);
      if (c === -1) { i++; continue; }
      const key = unquote(content.slice(0, c));
      const rest = content.slice(c + 1).trim();
      i++;
      if (rest === '' || rest === '|' || rest === '>' || rest === '|-' || rest === '>-') {
        if (i < lines.length && lines[i].indent > indent) {
          if (rest) { const ind = lines[i].indent; const buf = []; while (i < lines.length && lines[i].indent >= ind) buf.push(lines[i++].content); obj[key] = buf.join(rest.startsWith('|') ? '\n' : ' '); }
          else obj[key] = block(lines[i].indent);
        } else if (i < lines.length && lines[i].indent === indent && lines[i].content.startsWith('- ')) obj[key] = block(indent);
        else obj[key] = rest ? '' : null;
      } else obj[key] = scalar(rest);
    }
    return obj;
  }
  return lines.length ? block(lines[0].indent) : {};
}
