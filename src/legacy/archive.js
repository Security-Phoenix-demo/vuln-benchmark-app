const fs = require('fs');
const path = require('path');
module.exports = function extract(destDir, entries) {
  for (const e of entries) fs.writeFileSync(path.join(destDir, e.name), e.data);
};
