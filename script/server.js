// Express Server Setup for Cryptera APK Detector
// -------------------------------------------------
// This server sets up an endpoint (/api/details) that returns a JSON object
// with the following structure:
//   RESULTS: A quick message (e.g., "No scan yet")
//   Metadata: Information such as Package, Version, and Size (computed via getProjectMetadata)
//   Permission Analysis: Placeholder (for future scan analysis)
//   Certificate & Signature: Placeholder
//   ML Prediction: Placeholder for malicious and legit probabilities
//
// Make sure you already have a backendMetadata.js file with the function getProjectMetadata.
// This function should accept a directory path (process.cwd()) and return an object
// with properties like "package", "version", and "size".
//

const express = require('express');
const path = require('path');
const { getProjectMetadata } = require('c:/cybershield/script/backendmetadata');

const app = express();
const port = process.env.PORT || 3000;

app.get('/api/details', (req, res) => {
  // Get project metadata from the backendMetadata module based on the current working directory
  const metadata = getProjectMetadata(process.cwd());

  // Return the full details object with placeholders where applicable
  const response = {
    results: "No scan yet",
    metadata: {
      package: metadata.package || "—",
      version: metadata.version || "—",
      size: metadata.size || "—"
    },
    permissionAnalysis: "—",
    certificateSignature: "—",
    mlPrediction: {
      malicious: "—",
      legit: "—"
    }
  };

  res.json(response);
});

// Serve the frontend static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});