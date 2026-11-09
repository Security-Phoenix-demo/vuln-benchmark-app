// B5 (CWE-327/321) Weak cipher (DES-ECB) with a hardcoded key. UNREACHABLE: no file requires src/dead/*.
const crypto = require('crypto');
const KEY = Buffer.from('8bytekey');
module.exports = function encrypt(text) {
  const c = crypto.createCipheriv('des-ecb', KEY, null);
  return Buffer.concat([c.update(text), c.final()]).toString('hex');
};
