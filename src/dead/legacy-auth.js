// B1 (CWE-89) SQL injection. UNREACHABLE: no file requires src/dead/*.
const { db } = require('../db');
module.exports = function legacyLogin(user, pass) {
  return db.prepare(`SELECT * FROM users WHERE username='${user}' AND password='${pass}'`).get();
};
