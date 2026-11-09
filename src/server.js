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
app.use('/uploads', express.static(cfg.UPLOADS));

app.get('/', (req, res) => res.json({ app: 'vuln-benchmark-app', endpoints: ENDPOINTS() }));

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

app.get('/api/products', (req, res) => {
  try {
    res.json(db.prepare(`SELECT id,name,price FROM products WHERE name LIKE '%${req.query.q || ''}%'`).all());
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/lookup', (req, res) => {
  exec(`getent hosts ${req.query.host || 'localhost'}; true`, (err, out) => res.type('text/plain').send(out));
});

app.get('/api/files', (req, res) => {
  try {
    res.type('text/plain').send(fs.readFileSync(path.join(cfg.DOCS, String(req.query.name || 'welcome.txt')), 'utf8'));
  } catch (e) {
    res.status(404).json({ error: 'not found' });
  }
});

app.get('/api/fetch', async (req, res) => {
  try {
    const r = await fetch(String(req.query.url));
    res.type('text/plain').send(await r.text());
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

app.get('/api/calc', (req, res) => {
  try {
    res.json({ result: eval(String(req.query.expr || '1+1')) });
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

app.get('/api/debug/env', (req, res) => {
  const auth = Buffer.from((req.headers.authorization || '').replace('Basic ', ''), 'base64').toString();
  if (auth !== 'debug:debug') return res.status(401).set('WWW-Authenticate', 'Basic').end();
  res.json({ NODE_ENV: process.env.NODE_ENV || 'dev', JWT_SECRET: cfg.JWT_SECRET, INTERNAL_KEY: cfg.INTERNAL_KEY });
});

app.get('/api/system/info', (req, res) =>
  res.json({ version: '1.0.0', node: process.version, internalPort: cfg.INTERNAL_PORT, internalKey: cfg.INTERNAL_KEY })
);

app.post('/api/upload', (req, res) => {
  const name = path.basename(String(req.query.name || 'file.bin'));
  fs.writeFileSync(path.join(cfg.UPLOADS, name), req.body);
  res.json({ url: `/uploads/${name}` });
});

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
