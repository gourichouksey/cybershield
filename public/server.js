// Express Server Setup for Cryptera APK Detector
//
// This server uses multer to handle file upload. It exposes an API endpoint (/api/scan)
// that accepts an APK file upload, then (for now) returns placeholder scan results.
// The returned JSON includes:
//   • results: Scan message
//   • metadata: { package, version, size }
//   • permissionAnalysis: Analysis results for permissions
//   • certificateSignature: Certificate details
//   • mlPrediction: { malicious, legit }
// The server also serves static files from the "public" folder.

const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Set up multer with memory storage, limiting file size to 50MB.
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50 MB
});

// API endpoint for scanning the APK file.
app.post('/api/scan', upload.single('apkFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded!" });
  }
  
  // For demonstration: Retrieve file information.
  const fileInfo = {
    originalname: req.file.originalname,
    mimetype: req.file.mimetype,
    // Convert the file size from bytes to MB (with 2 decimals)
    size: (req.file.size / (1024 * 1024)).toFixed(2) + " MB"
  };

  // Placeholder logic for file analysis.
  // Replace the below details with your actual scanning logic.
  const response = {
    results: "No scan yet",
    metadata: {
      package: "com.example.app",     // Placeholder package name.
      version: "1.0.0",               // Placeholder version.
      size: fileInfo.size             // File size calculated above.
    },
    permissionAnalysis: "✅ INTERNET, ❌ READ_SMS, ❌ RECEIVE_BOOT_COMPLETED",
    certificateSignature: "❌ Not signed by official cert",
    mlPrediction: {
      malicious: "87%",
      legit: "13%"
    }
  };

  res.json(response);
});

// Serve static files from the public folder.
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});