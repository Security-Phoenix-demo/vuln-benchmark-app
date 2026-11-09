// Group C (C1-C7, C10): every route here needs an admin token.
// You only get one through group A (A1 SQLi login, A10 alg none, or A4/A7 leaked secret).
const express = require('express');
const fs = require('fs');
const path = require('path');
const { db } = require('./db');
const cfg = require('./config');

const router = express.Router();
const settings = {};

// C1 (CWE-89) SQL injection in the table name.
router.get('/export', (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM ' + req.query.table).all());
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// C2 (CWE-22) Path traversal in log viewer.
router.get('/logs', (req, res) => {
  try {
    res.type('text/plain').send(fs.readFileSync(path.join(cfg.LOGS, String(req.query.file || 'app.log')), 'utf8'));
  } catch (e) {
    res.status(404).json({ error: 'not found' });
  }
});

// C3 (CWE-94) Server-side template injection: the template is compiled as a JS template literal.
router.post('/report', (req, res) => {
  try {
    const fn = new Function('name', 'return `' + String((req.body || {}).template || 'Hi ${name}') + '`');
    res.type('text/plain').send(fn('admin'));
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

// C4 (CWE-94/829) Plugin loader runs any uploaded .js file (upload it with A9).
router.post('/plugins/load', (req, res) => {
  try {
    const mod = require(path.join(cfg.UPLOADS, path.basename(String(req.query.name))));
    res.json({ loaded: true, exports: Object.keys(mod || {}) });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// C5 (CWE-79) Stored XSS: audit messages (which hold raw login usernames from A1) are rendered unescaped.
router.get('/audit', (req, res) => {
  const rows = db.prepare('SELECT msg FROM audit ORDER BY id DESC LIMIT 50').all();
  res.type('html').send(`<h1>Audit</h1><ul>${rows.map((r) => `<li>${r.msg}</li>`).join('')}</ul>`);
});

// C6 (CWE-73) Arbitrary file write: dest is not restricted.
router.post('/backup', (req, res) => {
  try {
    fs.writeFileSync(String(req.query.dest), JSON.stringify(db.prepare('SELECT * FROM products').all()));
    res.json({ written: req.query.dest });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// C7 (CWE-918) Second SSRF, through the webhook tester.
router.post('/webhook', async (req, res) => {
  try {
    const r = await fetch(String(req.query.url), { method: 'POST' });
    res.json({ status: r.status, body: (await r.text()).slice(0, 2000) });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// C10 (CWE-1321) Prototype pollution: recursive merge without a __proto__ guard.
function merge(target, src) {
  for (const k of Object.keys(src)) {
    if (src[k] && typeof src[k] === 'object') {
      if (!target[k]) target[k] = {};
      merge(target[k], src[k]);
    } else target[k] = src[k];
  }
  return target;
}
router.post('/settings', (req, res) => {
  merge(settings, JSON.parse(JSON.stringify(req.body || {})));
  res.json({ settings, polluted: ({}).isAdminEverywhere === true });
});

module.exports = router;
