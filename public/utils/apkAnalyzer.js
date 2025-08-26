const ApkReader = require('adbkit-apkreader');
const AdmZip = require('adm-zip');
const fs = require('fs');
const crypto = require('crypto');

let mlModel = null;
try { mlModel = require('./mlModel'); } catch (err) { mlModel = null; }

// minimal official mapping (extend with real fingerprints)
const officialApps = {
  "com.sbi.mobilebanking": { certs: [] }
};

function sha256hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function extractCertificateFingerprint(apkPath) {
  const zip = new AdmZip(apkPath);
  const entries = zip.getEntries();
  for (const entry of entries) {
    const name = entry.entryName;
    if (/^META-INF\/.*\.(RSA|DSA|EC)$/i.test(name)) {
      const data = entry.getData();
      const fingerprint = sha256hex(data);
      return { found: true, file: name, fingerprint };
    }
  }
  return { found: false };
}

async function extractManifest(apkPath) {
  const reader = await ApkReader.open(apkPath);
  const manifest = await reader.readManifest();
  const metadata = {
    package: manifest.package || manifest.packageName || 'unknown',
    versionName: manifest.versionName || manifest['android:versionName'] || '',
    versionCode: manifest.versionCode || manifest['android:versionCode'] || ''
  };

  let permissions = [];
  if (Array.isArray(manifest.usesPermissions)) {
    permissions = manifest.usesPermissions.map(p => (p.name || p['@android:name'] || p));
  } else if (manifest.usesPermissions && Array.isArray(manifest.uses_permissions)) {
    permissions = manifest.uses_permissions;
  } else if (manifest.usesPermissions && typeof manifest.usesPermissions === 'object') {
    permissions = Object.keys(manifest.usesPermissions);
  } else if (manifest.uses_permission) {
    permissions = manifest.uses_permission;
  } else if (manifest.permissions && Array.isArray(manifest.permissions)) {
    permissions = manifest.permissions.map(p => p.name || p);
  }

  permissions = permissions.filter(Boolean).map(p => p.replace(/^android\.permission\./, ''));
  return { metadata, permissions };
}

function buildFeatures(metadata, permissions, certInfo, apkSizeBytes) {
  const suspiciousPermissions = [
    'READ_SMS','RECEIVE_SMS','SEND_SMS','RECEIVE_BOOT_COMPLETED',
    'READ_CONTACTS','READ_CALL_LOG','PROCESS_OUTGOING_CALLS','SYSTEM_ALERT_WINDOW'
  ];
  const foundSuspicious = permissions.filter(p => suspiciousPermissions.includes(p.toUpperCase()));
  const suspiciousCount = foundSuspicious.length;
  const hasCert = certInfo && certInfo.found ? 1 : 0;

  const commonBankPackages = ['com.sbi.mobilebanking','com.hdfc.mobilebanking','com.icici.mobilebanking'];
  const pkgLower = (metadata.package || '').toLowerCase();
  let bestScore = 0;
  for (const official of commonBankPackages) {
    if (pkgLower === official) { bestScore = 1; break; }
    if (pkgLower.includes(official)) bestScore = Math.max(bestScore, 0.85);
    else {
      const setA = new Set(pkgLower);
      const setB = new Set(official);
      let common = 0;
      for (const ch of setA) if (setB.has(ch)) common++;
      const overlap = common / Math.max(setA.size, setB.size, 1);
      bestScore = Math.max(bestScore, overlap * 0.6);
    }
  }
  const packageSimilarity = Math.max(0, Math.min(1, bestScore));
  const sizeMB = apkSizeBytes / (1024 * 1024);
  const sizeMBNormalized = Math.min(10, sizeMB / 100);
  return [suspiciousCount, hasCert, packageSimilarity, sizeMBNormalized];
}

function heuristicScore(metadata, permissions, certInfo, apkSizeBytes) {
  let score = 0;
  const reasons = [];
  const suspiciousPermissions = [
    'READ_SMS','RECEIVE_SMS','SEND_SMS','RECEIVE_BOOT_COMPLETED',
    'READ_CONTACTS','READ_CALL_LOG','PROCESS_OUTGOING_CALLS','SYSTEM_ALERT_WINDOW'
  ];

  const foundSuspicious = permissions.filter(p => suspiciousPermissions.includes(p.toUpperCase()));
  if (foundSuspicious.length) {
    score += Math.min(0.4, foundSuspicious.length * 0.12);
    reasons.push(`Suspicious permissions: ${foundSuspicious.join(', ')}`);
  }

  if (!certInfo.found) {
    score += 0.25;
    reasons.push('No signing certificate found in APK');
  } else {
    const pkg = metadata.package;
    if (officialApps[pkg] && officialApps[pkg].certs && officialApps[pkg].certs.length) {
      const matches = officialApps[pkg].certs.includes(certInfo.fingerprint);
      if (!matches) {
        score += 0.25;
        reasons.push('Certificate fingerprint does not match official certificate for package');
      }
    } else {
      score += 0.12;
      reasons.push('Unknown signer (no official fingerprint available)');
    }
  }

  const commonBankPackages = ['com.sbi.mobilebanking','com.hdfc.mobilebanking','com.icici.mobilebanking'];
  const pkgLower = (metadata.package || '').toLowerCase();
  for (const official of commonBankPackages) {
    if (pkgLower.includes(official) && pkgLower !== official) {
      score += 0.15;
      reasons.push(`Package name similar to official ${official} but not exact`);
      break;
    }
  }

  const sizeMB = apkSizeBytes / (1024 * 1024);
  if (sizeMB < 1.0) { score += 0.08; reasons.push('APK size unusually small (<1MB)'); }
  else if (sizeMB > 200) { score += 0.05; reasons.push('APK size unusually large (>200MB)'); }

  score = Math.max(0, Math.min(1, score));
  const classification = score >= 0.5 ? 'suspicious' : 'safe';
  return { maliciousProbability: Math.round(score * 100), score, classification, reasons };
}

async function analyzeApk(apkPath) {
  const stat = fs.statSync(apkPath);
  const apkSizeBytes = stat.size;

  let manifestResult = { metadata: { package: 'unknown' }, permissions: [] };
  try { manifestResult = await extractManifest(apkPath); } catch (err) { console.warn('Manifest parse failed:', err.message); }

  let certInfo = { found: false };
  try { certInfo = await extractCertificateFingerprint(apkPath); } catch (err) { console.warn('Cert extract failed:', err.message); }

  const features = buildFeatures(manifestResult.metadata, manifestResult.permissions, certInfo, apkSizeBytes);

  // Try ML model, fallback to heuristic on any failure
  let mlPrediction = null;
  if (mlModel && typeof mlModel.predict === 'function') {
    try {
      const out = await mlModel.predict(features);
      const prob = Math.round(out.probability * 100);
      mlPrediction = { malicious: `${prob}%`, legit: `${100 - prob}%`, classification: out.probability >= 0.5 ? 'suspicious' : 'safe', reasons: ['Model-based prediction'], rawScore: out.probability };
    } catch (err) {
      console.warn('ML predict failed (fall back to heuristic):', err.message);
    }
  }

  if (!mlPrediction) {
    const heur = heuristicScore(manifestResult.metadata, manifestResult.permissions, certInfo, apkSizeBytes);
    mlPrediction = { malicious: `${heur.maliciousProbability}%`, legit: `${100 - heur.maliciousProbability}%`, classification: heur.classification, reasons: heur.reasons, rawScore: heur.score };
  }

  return {
    metadata: { packageName: manifestResult.metadata.package || 'unknown', version: manifestResult.metadata.versionName || manifestResult.metadata.versionCode || '', size: `${(apkSizeBytes / (1024 * 1024)).toFixed(2)} MB` },
    permissions: manifestResult.permissions || [],
    permissionAnalysis: { suspicious: manifestResult.permissions.filter(p => ['READ_SMS','RECEIVE_SMS','SEND_SMS','RECEIVE_BOOT_COMPLETED','READ_CONTACTS','READ_CALL_LOG','PROCESS_OUTGOING_CALLS','SYSTEM_ALERT_WINDOW'].includes(p.toUpperCase())) },
    certificate: { found: certInfo.found || false, file: certInfo.file || '', fingerprint: certInfo.fingerprint || '' },
    mlPrediction
  };
}

module.exports = { analyzeApk };