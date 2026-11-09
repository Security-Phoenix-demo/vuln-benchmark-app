module.exports = function importRule(ruleSource) {
  return new Function('row', `return ${ruleSource}`);
};
