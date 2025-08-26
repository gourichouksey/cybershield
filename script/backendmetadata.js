// A simple stub for getProjectMetadata.
// In a real scenario, this might read your package.json, compute the size of your project, etc.
const fs = require('fs');
const path = require('path');

function getProjectMetadata(projectDir) {
  let pkg = "—";
  let version = "—";
  let size = "—";

  // Example: attempt to read package.json
  try {
    const pkgPath = path.join(projectDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      pkg = pkgData.name || "—";
      version = pkgData.version || "—";
    }
  } catch (err) {
    console.error("Error reading package.json:", err);
  }

  // Example: Compute total size of files in current directory
  // You can implement a more refined approach if needed.
  try {
    function getSize(dir) {
      let totalSize = 0;
      const files = fs.readdirSync(dir);
      files.forEach(file => {
        const fullPath = path.join(dir, file);
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory()) {
          totalSize += getSize(fullPath);
        } else {
          totalSize += stats.size;
        }
      });
      return totalSize;
    }
    size = getSize(projectDir);
  } catch (err) {
    console.error("Error computing project size:", err);
  }

  return { package: pkg, version, size };
}

module.exports = { getProjectMetadata };