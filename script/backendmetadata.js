// Helper Module for Project Metadata
//
// In this stub, we try to read package information from package.json
// and compute the total size of all files within the project. For now,
// if package.json is not present or an error occurs, placeholder values ("—") are returned.

const fs = require('fs');
const path = require('path');

function getProjectMetadata(projectDir) {
  let pkg = "—";
  let version = "—";
  let size = "—";

  // Attempt to read package.json for package name and version
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

  // Compute total size of files in the directory
  try {
    function getSize(dir) {
      let totalSize = 0;
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        try {
          const stats = fs.statSync(fullPath);
          if (stats.isDirectory()) {
            totalSize += getSize(fullPath);
          } else {
            totalSize += stats.size;
          }
        } catch (e) {
          console.error(`Error getting size for ${fullPath}:`, e);
        }
      }
      return totalSize;
    }
    size = getSize(projectDir);
  } catch (err) {
    console.error("Error computing project size:", err);
  }

  return { package: pkg, version, size };
}

module.exports = { getProjectMetadata };