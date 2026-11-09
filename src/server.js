// DELIBERATELY VULNERABLE. Group A (A1-A10): direct, easy to reach and exploit.
// Group B (B7, B8 here; B1-B6, B10 in src/dead/): vulnerable code with no path from any route.
// Group C lives in src/admin.js and src/internal.js and needs a group A step first.
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cfg = require('./config');
const { db, md5, audit } = require('./db');
const jwt = require('./jwt');

const app = express();
app.use(express.json());
app.use(express.raw({ type: 'application/octet-stream', limit: '1mb' }));
app.use('/uploads', express.static(cfg.UPLOADS)); // A9 target: uploaded files are served as-is

app.get('/', (req, res) => res.json({ app: 'vuln-benchmark-app', endpoints: ENDPOINTS() }));

// A1 (CWE-89) SQL injection in login: username "admin'--" returns an admin token.
app.post('/api/login', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  audit(`login attempt: ${username}`);
  try {
    const row = db
      .prepare(`SELECT id,username,role FROM users WHERE username='${username}' AND password='${md5(password)}'`)
      .get();
    if (!row) return res.status(401).json({ error: 'bad credentials' });
    res.json({ token: jwt.sign({ sub: row.username, role: row.role }) });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// A2 (CWE-89) UNION-based SQL injection in product search.
app.get('/api/products', (req, res) => {
  try {
    res.json(db.prepare(`SELECT id,name,price FROM products WHERE name LIKE '%${req.query.q || ''}%'`).all());
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// A3 (CWE-78) OS command injection in host lookup.
app.get('/api/lookup', (req, res) => {
  exec(`getent hosts ${req.query.host || 'localhost'}; true`, (err, out) => res.type('text/plain').send(out));
});

// A4 (CWE-22) Path traversal: name=../secrets.env leaks the JWT secret and internal key.
app.get('/api/files', (req, res) => {
  try {
    res.type('text/plain').send(fs.readFileSync(path.join(cfg.DOCS, String(req.query.name || 'welcome.txt')), 'utf8'));
  } catch (e) {
    res.status(404).json({ error: 'not found' });
  }
});

// A5 (CWE-918) SSRF: the server fetches any URL, including 127.0.0.1:9091 (feeds C8, C9).
app.get('/api/fetch', async (req, res) => {
  try {
    const r = await fetch(String(req.query.url));
    res.type('text/plain').send(await r.text());
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// A6 (CWE-95) Code injection: eval of a user expression.
app.get('/api/calc', (req, res) => {
  try {
    res.json({ result: eval(String(req.query.expr || '1+1')) });
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

// A7 (CWE-798) Hardcoded debug credentials debug:debug expose the JWT secret and internal key.
app.get('/api/debug/env', (req, res) => {
  const auth = Buffer.from((req.headers.authorization || '').replace('Basic ', ''), 'base64').toString();
  if (auth !== 'debug:debug') return res.status(401).set('WWW-Authenticate', 'Basic').end();
  res.json({ NODE_ENV: process.env.NODE_ENV || 'dev', JWT_SECRET: cfg.JWT_SECRET, INTERNAL_KEY: cfg.INTERNAL_KEY });
});

// A8 (CWE-306/200) Missing authentication: system info leaks the internal service key.
app.get('/api/system/info', (req, res) =>
  res.json({ version: '1.0.0', node: process.version, internalPort: cfg.INTERNAL_PORT, internalKey: cfg.INTERNAL_KEY })
);

// A9 (CWE-434) Unrestricted upload: any file type, served back from /uploads (feeds C4).
app.post('/api/upload', (req, res) => {
  const name = path.basename(String(req.query.name || 'file.bin'));
  fs.writeFileSync(path.join(cfg.UPLOADS, name), req.body);
  res.json({ url: `/uploads/${name}` });
});

// A10 (CWE-347) JWT verify accepts alg "none": see src/jwt.js. This middleware relies on it.
function requireAdmin(req, res, next) {
  const claims = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''));
  if (!claims || claims.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  req.user = claims;
  next();
}
app.get('/api/me', (req, res) => {
  const claims = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''));
  claims ? res.json(claims) : res.status(401).json({ error: 'no token' });
});

app.use('/api/admin', requireAdmin, require('./admin'));

// B8 (CWE-78) Command injection, but nothing calls runDiagnostics().
function runDiagnostics(cmd) {
  return new Promise((resolve) => exec(cmd, (e, out) => resolve(out)));
}

function ENDPOINTS() {
  return [
    'POST /api/login', 'GET /api/products?q=', 'GET /api/lookup?host=', 'GET /api/files?name=',
    'GET /api/fetch?url=', 'GET /api/calc?expr=', 'GET /api/debug/env', 'GET /api/system/info',
    'POST /api/upload?name=', 'GET /api/me', 'ALL /api/admin/* (admin token)',
  ];
}

app.listen(cfg.PORT, () => console.log(`vuln-benchmark-app on :${cfg.PORT}`));
require('./internal');
