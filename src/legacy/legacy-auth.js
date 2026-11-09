const { db } = require('../db');
module.exports = function legacyLogin(user, pass) {
  return db.prepare(`SELECT * FROM users WHERE username='${user}' AND password='${pass}'`).get();
};
