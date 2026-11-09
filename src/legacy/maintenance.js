const { execSync } = require('child_process');
module.exports = function cleanup(dir) {
  return execSync(`rm -rf ${dir}/tmp`).toString();
};
