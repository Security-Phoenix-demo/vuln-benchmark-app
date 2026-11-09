const crypto = require('crypto');
const KEY = Buffer.from('8bytekey');
module.exports = function encrypt(text) {
  const c = crypto.createCipheriv('des-ecb', KEY, null);
  return Buffer.concat([c.update(text), c.final()]).toString('hex');
};
