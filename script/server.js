// Express Server Setup to Serve Project Metadata

const express = require('express');
const path = require('path');
const { getProjectMetadata } = require('.cybershield/script/backendMetadata.js');

const app = express();
const port = process.env.PORT || 3000;

// API endpoint to retrieve project metadata
app.get('/api/metadata', (req, res) => {
  // Using process.cwd() to get the project root directory
  const projectDir = process.cwd();
  const metadata = getProjectMetadata(projectDir);
  res.json(metadata);
});

// Serve static files (for frontend)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});