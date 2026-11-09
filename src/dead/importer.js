// B3 (CWE-94) Code injection through new Function. UNREACHABLE: no file requires src/dead/*.
module.exports = function importRule(ruleSource) {
  return new Function('row', `return ${ruleSource}`);
};
