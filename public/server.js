const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const { analyzeApk } = require('./utils/apkAnalyzer');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files from /public
app.use('/', express.static(path.join(__dirname, 'public')));

// Ensure uploads directory exists
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    if (!file.originalname.toLowerCase().endsWith('.apk')) {
      cb(new Error('Only .apk files are allowed'));
    } else {
      cb(null, true);
    }
  }
});

app.post('/api/scan', upload.single('apk'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No APK uploaded (field name: apk)' });

  const apkPath = req.file.path;
  try {
    const analysis = await analyzeApk(apkPath);

    // delete uploaded file (best-effort)
    fs.unlink(apkPath, (err) => {
      if (err) console.warn('Failed to remove upload:', apkPath, err.message);
    });

    res.json(analysis);
  } catch (err) {
    console.error('Scan error:', err);
    // cleanup
    fs.unlink(apkPath, () => {});
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// Fallback: serve frontend file
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cryptera-frontend.html'));
});

app.listen(PORT, () => {
  console.log(`Cryptera backend listening on http://localhost:${PORT}`);
});