// Minimal JWT helper. verify() accepts alg "none" (A10, CWE-347).
const crypto = require('crypto');
const { JWT_SECRET } = require('./config');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

function sign(payload) {
  const head = b64({ alg: 'HS256', typ: 'JWT' });
  const body = b64(payload);
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${sig}`;
}

function verify(token) {
  try {
    const [h, p, s] = token.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (header.alg === 'none') return payload; // A10: unsigned token accepted
    const good = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
    return s === good ? payload : null;
  } catch (e) {
    return null;
  }
}

module.exports = { sign, verify };
