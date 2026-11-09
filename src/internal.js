// Internal service on 127.0.0.1 only. Not reachable from outside.
// The only way in is SSRF from A5 (and C7) with the key leaked by A8, A7 or A4. Group C: C8, C9.
const http = require('http');
const { exec } = require('child_process');
const cfg = require('./config');
const { db } = require('./db');

http
  .createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.searchParams.get('key') !== cfg.INTERNAL_KEY) return res.writeHead(403).end('bad key');
    // C8 (CWE-78) Command injection in the internal run endpoint.
    if (u.pathname === '/internal/run') {
      return exec(u.searchParams.get('cmd') || 'true', (e, out) => res.end(out || String(e)));
    }
    // C9 (CWE-200/328) Internal dump returns users with unsalted MD5 password hashes.
    if (u.pathname === '/internal/users') {
      return res.end(JSON.stringify(db.prepare('SELECT username,password,role FROM users').all()));
    }
    res.writeHead(404).end();
  })
  .listen(cfg.INTERNAL_PORT, '127.0.0.1');
