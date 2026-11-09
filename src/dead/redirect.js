// B6 (CWE-601) Open redirect. UNREACHABLE: no route mounts this handler.
module.exports = function redirect(req, res) {
  res.redirect(req.query.next);
};
