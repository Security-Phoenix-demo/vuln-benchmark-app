const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const DATA = process.env.DATA_DIR || path.join(ROOT, 'data');
const SECRETS_FILE = path.join(DATA, 'secrets.env');

fs.mkdirSync(path.join(DATA, 'docs'), { recursive: true });
fs.mkdirSync(path.join(DATA, 'logs'), { recursive: true });
fs.mkdirSync(process.env.UPLOAD_DIR || path.join(ROOT, 'uploads'), { recursive: true });

if (!fs.existsSync(SECRETS_FILE)) {
  fs.writeFileSync(
    SECRETS_FILE,
    `JWT_SECRET=${crypto.randomBytes(16).toString('hex')}\nINTERNAL_KEY=${crypto.randomBytes(8).toString('hex')}\n`
  );
}
const secrets = Object.fromEntries(
  fs.readFileSync(SECRETS_FILE, 'utf8').split('\n').filter(Boolean).map((l) => l.split('='))
);
const docs = path.join(DATA, 'docs');
if (!fs.existsSync(path.join(docs, 'welcome.txt'))) fs.writeFileSync(path.join(docs, 'welcome.txt'), 'Welcome to the shop.\n');
const logf = path.join(DATA, 'logs', 'app.log');
if (!fs.existsSync(logf)) fs.writeFileSync(logf, 'app started\n');

module.exports = {
  PORT: Number(process.env.PORT || 8080),
  INTERNAL_PORT: 9091,
  DATA,
  DOCS: docs,
  LOGS: path.join(DATA, 'logs'),
  UPLOADS: process.env.UPLOAD_DIR || path.join(ROOT, 'uploads'),
  JWT_SECRET: secrets.JWT_SECRET,
  INTERNAL_KEY: secrets.INTERNAL_KEY,
};
