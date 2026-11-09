// B2 (CWE-78) OS command injection. UNREACHABLE: no file requires src/dead/*.
const { execSync } = require('child_process');
module.exports = function cleanup(dir) {
  return execSync(`rm -rf ${dir}/tmp`).toString();
};
