const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

const db = new DatabaseSync(':memory:');
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

db.exec(`
  CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
  CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL);
  CREATE TABLE audit(id INTEGER PRIMARY KEY, msg TEXT);
`);
const addUser = db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)');
addUser.run('admin', md5('Adm1n!2026'), 'admin');
addUser.run('alice', md5('alice123'), 'user');
addUser.run('bob', md5('bob456'), 'user');
const addProduct = db.prepare('INSERT INTO products(name,price) VALUES(?,?)');
['Blue Widget', 'Red Widget', 'Green Gadget', 'Steel Bolt'].forEach((n, i) => addProduct.run(n, 9.99 + i));

const audit = (msg) => db.prepare('INSERT INTO audit(msg) VALUES(?)').run(msg);

function legacySearch(term) {
  return db.prepare(`SELECT * FROM products WHERE name = '${term}'`).all();
}

module.exports = { db, md5, audit, legacySearch };
