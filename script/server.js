// Express Server Setup for Cryptera APK Detector
//
// This server sets up an endpoint (/api/details) that returns a JSON object 
// containing the following details:
//   • RESULTS: A message ("No scan yet")
//   • Metadata: Package name, version, and size (from backendMetadata.js)
//   • Permission Analysis: Placeholder ("—")
//   • Certificate & Signature: Placeholder ("—")
//   • ML Prediction: Placeholder for malicious and legit values ("—")
//
// The server also serves static files from the "public" folder,
// so that the frontend (cryptera_frontend.html) can be loaded in the browser.

const express = require('express');
const path = require('path');
const { getProjectMetadata } = require('c:/cybershield/script/backendmetadata');

const app = express();
const port = process.env.PORT || 3000;

app.get('/api/details', (req, res) => {
  const metadata = getProjectMetadata(process.cwd());

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

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});