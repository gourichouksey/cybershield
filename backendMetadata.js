// Node.js Backend Script to Read Project Metadata
// This script reads the project folder recursively, retrieves package metadata from package.json (if it exists), and computes the total size of all files.

const fs = require('fs');
const path = require('path');

// Function to retrieve package metadata if package.json exists
function getPackageMetadata(projectDir) {
  let packageName = 'N/A';
  let version = 'N/A';
  const packagePath = path.join(projectDir, 'package.json');
  if (fs.existsSync(packagePath)) {
    try {
      const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
      packageName = packageData.name || packageName;
      version = packageData.version || version;
    } catch (err) {
      console.error('Error reading package.json:', err);
    }
  }
  return { packageName, version };
}

// Function to calculate the total size of all files in the directory recursively
function getDirectorySize(dir) {
  let totalSize = 0;
  function traverse(currentPath) {
    const files = fs.readdirSync(currentPath);
    for (const file of files) {
      const fullPath = path.join(currentPath, file);
      const stats = fs.statSync(fullPath);
      if (stats.isDirectory()) {
        traverse(fullPath);
      } else {
        totalSize += stats.size;
      }
    }
  }
  traverse(dir);
  return totalSize;
}

// Function to gather project metadata
function getProjectMetadata(projectDir) {
  const { packageName, version } = getPackageMetadata(projectDir);
  const size = getDirectorySize(projectDir);
  return { package: packageName, version, size };
}

// Example usage: Run this script from the project folder root
const projectDir = process.cwd();
const metadata = getProjectMetadata(projectDir);
console.log('Project Metadata:', metadata);

// Export the function for use in other modules if needed
module.exports = { getProjectMetadata };