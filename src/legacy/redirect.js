module.exports = function redirect(req, res) {
  res.redirect(req.query.next);
};
