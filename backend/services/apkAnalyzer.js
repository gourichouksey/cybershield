const yauzl = require('yauzl');
const xml2js = require('xml2js');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Try to import APK parser, fallback if not available
let ApkReader = null;
try {
  ApkReader = require('node-apk-parser');
} catch (err) {
  console.warn('node-apk-parser not available, falling back to basic parsing');
}

class APKAnalyzer {
  constructor() {
    this.knownBankingApps = new Set([
      'com.bankofamerica.bmobilebank',
      'com.chase.mobile',
      'com.wellsfargo.mobile',
      'com.citibank.mobile',
      'com.usbank.mobile',
      // Add more legitimate banking package names
    ]);
    
    this.suspiciousStrings = [
      'banking', 'password', 'pin', 'account', 'balance', 'transfer',
      'login', 'authenticate', 'security', 'credential', 'token',
      'keylogger', 'screen_record', 'accessibility_service',
      'device_admin', 'phone_state', 'sms', 'contacts'
    ];
    
    this.bankingKeywords = [
      'bank', 'credit', 'debit', 'account', 'balance', 'transaction',
      'transfer', 'payment', 'wallet', 'finance', 'money', 'card'
    ];
  }
  
  async analyzeAPK(apkPath) {
    try {
      console.log('Starting APK analysis for:', apkPath);
      
      const basicInfo = await this.extractBasicInfo(apkPath);
      const manifest = await this.parseManifest(apkPath);
      const certificates = await this.extractCertificates(apkPath);
      const fileHashes = await this.calculateFileHashes(apkPath);
      const dexAnalysis = await this.analyzeDexFiles(apkPath);
      
      return {
        ...basicInfo,
        manifest,
        certificates,
        fileHashes,
        dexAnalysis,
        extractedAt: new Date()
      };
      
    } catch (error) {
      console.error('APK analysis failed:', error);
      throw new Error(`APK analysis failed: ${error.message}`);
    }
  }
  
  async extractBasicInfo(apkPath) {
    return new Promise((resolve, reject) => {
      const stats = require('fs').statSync(apkPath);
      console.info("Using yauzl for APK analysis");
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          
          console.error("Yauzl error:", err);
          return reject(err);
        };
        
        const info = {
          fileSize: stats.size,
          fileCount: 0,
          hasNativeCode: false,
          hasResources: false,
          hasDexFiles: false,
          isDebuggable: false,
          allowBackup: true,
          directories: new Set(),
          extensions: new Set()
        };
        
        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          info.fileCount++;
          
          const fileName = entry.fileName.toLowerCase();
          const ext = path.extname(fileName);
          if (ext) info.extensions.add(ext);
          
          const dir = path.dirname(entry.fileName);
          if (dir !== '.') info.directories.add(dir);
          
          // Check for native code
          if (fileName.includes('lib/') && (fileName.endsWith('.so') || fileName.endsWith('.dll'))) {
            info.hasNativeCode = true;
          }
          
          // Check for DEX files
          if (fileName.endsWith('.dex')) {
            info.hasDexFiles = true;
          }
          
          // Check for resources
          if (fileName.includes('res/') || fileName.includes('assets/')) {
            info.hasResources = true;
          }
          
          zipfile.readEntry();
        });
        
        zipfile.on('end', () => {
          console.info("Extracted basic info successfully through yauzl");
          resolve(info);
        });
        
        zipfile.on('error', reject);
      });
    });
  }
  
  async parseManifest(apkPath) {
    // Use aapt to parse the AndroidManifest.xml directly from the APK file
    try {
      console.info("Parsing manifest")
      const manifest = await this.parseAndroidManifest(apkPath);
      console.info("Parsed manifest successfully");

      return manifest;
    } catch (error) {
      console.error('Manifest parsing error:', error);
      return { error: `Manifest parsing failed: ${error.message}` };
    }
  }

  async parseAndroidManifest(apkPath) {
    // Try JavaScript APK parser first, then fallback to aapt
    if (ApkReader) {
      try {
        const reader = await ApkReader.readFile(apkPath);
        const manifest = await reader.readManifestSync();
        // return manifest
        return {
          package: manifest.package || '',
          versionCode: manifest.versionCode || '',
          versionName: manifest.versionName || '',
          permissions: manifest.usesPermissions || [], // [{name: "PERMISSION", maxSdkVersion: "VERSION"}],
          features: manifest.usesFeatures || [], // [{name: "FEATURE", required: TRUE | FALSE}]
          activities: manifest.application.activities || [],
          launcherActivities: manifest.application.launcherActivities || [],
          services: manifest.application.services || [],
          receivers: manifest.application.receivers || [],
          metadatas: manifest.application.metaDatas || [],
          minSdkVersion: manifest.usesSdk.minSdkVersion || '',
          targetSdkVersion: manifest.usesSdk.targetSdkVersion || '',
          compileSdkVersion: manifest.compileSdkVersion || '',
          isDebuggable: manifest.application?.debuggable || false,
          allowBackup: manifest.application?.allowBackup !== false,
          networkSecurityConfig: manifest.application?.networkSecurityConfig || '',
          usesCleartextTraffic: manifest.application?.usesCleartextTraffic !== false
        };
      } catch (jsError) {
        console.warn('JavaScript APK parser failed:', jsError.message);
        // Fall through to aapt method
      }
    }

    // Fallback to aapt method
    try {
      const { stdout } = await execPromise(`aapt dump badging "${apkPath}" 2>/dev/null || echo "aapt_failed"`);
      
      if (stdout.includes('aapt_failed')) {
        return { 
          error: 'Could not parse manifest - neither JavaScript parser nor aapt available',
          suggestion: 'Install Android SDK Build Tools or run: npm install node-apk-parser'
        };
      }
      
      const lines = stdout.split('\n');
      const manifest = {
        package: '',
        versionCode: '',
        versionName: '',
        permissions: [],
        activities: [],
        services: [],
        receivers: [],
        minSdkVersion: '',
        targetSdkVersion: ''
      };
      
      lines.forEach(line => {
        if (line.startsWith('package:')) {
          const match = line.match(/name='([^']+)'/);
          if (match) manifest.package = match[1];
          
          const versionCode = line.match(/versionCode='([^']+)'/);
          if (versionCode) manifest.versionCode = versionCode[1];
          
          const versionName = line.match(/versionName='([^']+)'/);
          if (versionName) manifest.versionName = versionName[1];
        }
        
        if (line.startsWith('uses-permission:')) {
          const match = line.match(/name='([^']+)'/);
          if (match) manifest.permissions.push(match[1]);
        }
        
        if (line.startsWith('sdkVersion:')) {
          const match = line.match(/'(\d+)'/);
          if (match) manifest.minSdkVersion = match[1];
        }
        
        if (line.startsWith('targetSdkVersion:')) {
          const match = line.match(/'(\d+)'/);
          if (match) manifest.targetSdkVersion = match[1];
        }
      });
      
      return manifest;
      
    } catch (error) {
      console.error('Manifest parsing error:', error);
      return { error: 'Failed to parse manifest' };
    }
  }
  
  async extractCertificates(apkPath) {
    return new Promise((resolve, reject) => {
      console.log("Starting Certificates Extraction using Yauzl")
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          console.error("Yauzl error:", err);
          return reject(err);
        }

        const certificates = [];
        
        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          if (entry.fileName.startsWith('META-INF/') && 
              (entry.fileName.endsWith('.RSA') || entry.fileName.endsWith('.DSA'))) {
            
            zipfile.openReadStream(entry, (err, readStream) => {
              if (err) {
                zipfile.readEntry();
                return;
              }
              
              const chunks = [];
              readStream.on('data', chunk => chunks.push(chunk));
              readStream.on('end', () => {
                const buffer = Buffer.concat(chunks);
                certificates.push({
                  file: entry.fileName,
                  size: buffer.length,
                  hash: crypto.createHash('sha256').update(buffer).digest('hex')
                });
                zipfile.readEntry();
              });
            });
          } else {
            zipfile.readEntry();
          }
        });
        
        zipfile.on('end', () => {
          console.log("Certificates Extraction completed", certificates);
          resolve(certificates);
        });
      });
    });
  }
  
  async calculateFileHashes(apkPath) {
    const buffer = await fs.readFile(apkPath);
    console.info("Calculating file hashes");
    const hashes = {
      md5: crypto.createHash('md5').update(buffer).digest('hex'),
      sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      size: buffer.length
    }
    console.log("Hashes Calculation Completed")
    return hashes;
  }
  
  async analyzeDexFiles(apkPath) {
    console.log("Starting DEX Files Extraction using Yauzl");
    return new Promise((resolve, reject) => {
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          console.error("Yauzl error:", err);
          return reject(err);
        }

        const dexFiles = [];
        let processedFiles = 0;
        let totalDexFiles = 0;
        
        // First pass: count DEX files
        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          if (entry.fileName.endsWith('.dex')) {
            totalDexFiles++;
          }
          zipfile.readEntry();
        });
        
        zipfile.on('end', () => {
          if (totalDexFiles === 0) {
            return resolve([]);
          }

          console.log(`Found ${totalDexFiles} DEX files, starting analysis...`);
          
          // Second pass: analyze DEX files
          yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile2) => {
            if (err) {
              console.error("Yauzl error:", err);
              return reject(err);
            }

            console.log("Starting Analysis of DEX Files...  ")
            zipfile2.readEntry();
            zipfile2.on('entry', (entry) => {
              if (entry.fileName.endsWith('.dex')) {
                zipfile2.openReadStream(entry, (err, readStream) => {
                  console.log("Opened read stream for:", entry.fileName);
                  if (err) {
                    processedFiles++;
                    console.error("Read stream error:", err);

                    if (processedFiles === totalDexFiles) {
                      console.log("DEX Files Extraction completed", dexFiles);
                      resolve(dexFiles);
                    } else {
                      zipfile2.readEntry(); // Continue to next entry even on error
                    }
                    return;
                  }
                  
                  const chunks = [];
                  const analyzedFilename = entry.fileName;
                  console.log("Reading DEX file:", analyzedFilename);
                  readStream.on('data', chunk => {
                    return chunks.push(chunk);
                  });
                  readStream.on('end', () => {
                    const buffer = Buffer.concat(chunks);
                    dexFiles.push({
                      name: entry.fileName,
                      size: buffer.length,
                      hash: crypto.createHash('sha256').update(buffer).digest('hex'),
                      stringAnalysis: this.analyzeDexStrings(buffer)
                    });
                    
                    processedFiles++;
                    console.log(`Analyzed ${processedFiles}/${totalDexFiles} DEX files`);
                    if (processedFiles === totalDexFiles) {
                      console.log("DEX Files Extraction completed", dexFiles);
                      resolve(dexFiles);
                    } else {
                      zipfile2.readEntry(); // Continue to next entry
                    }
                  });
                });
              } else {
                zipfile2.readEntry();
              }
            });
            
            zipfile2.on('end', () => {
              console.log("0 DEX Files found");
              if (processedFiles === 0) resolve([]);
            });
          });
        });
      });
    });
  }
  
  analyzeDexStrings(buffer) {
    const strings = [];
    const suspiciousCount = { total: 0, banking: 0, malicious: 0 };
    
    try {
      // Simple string extraction from DEX (this is simplified)
      const text = buffer.toString('utf8', 0, Math.min(buffer.length, 100000));
      const matches = text.match(/[\x20-\x7E]{4,}/g) || [];
      
      matches.forEach(str => {
        const lowerStr = str.toLowerCase();
        
        // Check for suspicious strings
        if (this.suspiciousStrings.some(sus => lowerStr.includes(sus))) {
          suspiciousCount.total++;
          strings.push({ text: str, type: 'suspicious' });
        }
        
        // Check for banking-related strings
        if (this.bankingKeywords.some(keyword => lowerStr.includes(keyword))) {
          suspiciousCount.banking++;
          strings.push({ text: str, type: 'banking' });
        }
        
        // Check for explicitly malicious strings
        if (lowerStr.includes('malware') || lowerStr.includes('trojan') || 
            lowerStr.includes('keylog') || lowerStr.includes('steal') || lowerStr.includes('fraud')) {
          suspiciousCount.malicious++;
          strings.push({ text: str, type: 'malicious' });
        }
      });
      
    } catch (error) {
      console.error('String analysis error:', error);
    }
    
    return {
      suspiciousCount,
      samples: strings.slice(0, 20) // Limit to first 20 findings
    };
  }
  
  async analyzeBankingCharacteristics(apkPath, apkInfo) {
    const analysis = {
      imitatesBankingApp: false,
      hasPhishingIndicators: false,
      suspiciousPermissions: [],
      suspiciousNetworking: false,
      uiSimilarity: 0,
      confidence: 0
    };
    
    try {
      // Check package name similarity to known banking apps
      if (apkInfo.manifest && apkInfo.manifest.package) {
        const packageName = apkInfo.manifest.package.toLowerCase();
        
        // Check for banking keywords in package name
        const hasBankingKeywords = this.bankingKeywords.some(keyword => 
          packageName.includes(keyword)
        );
        
        // Check for legitimate banking app mimicking
        const mimicsLegitimate = Array.from(this.knownBankingApps).some(legit => {
          const legitLower = legit.toLowerCase();
          // Check for similar package names with slight variations
          const similarity = this.calculateStringSimilarity(packageName, legitLower);
          return similarity > 0.7 && packageName !== legitLower;
        });
        
        if (mimicsLegitimate || (hasBankingKeywords && !this.knownBankingApps.has(apkInfo.manifest.package))) {
          analysis.imitatesBankingApp = true;
        }
      }
      
      // Check permissions for banking-related suspicious activities
      if (apkInfo.manifest && apkInfo.manifest.permissions) {
        const permissions = apkInfo.manifest.permissions;
        const suspiciousPerms = [
          'android.permission.CALL_PHONE',
          'android.permission.SEND_SMS',
          // Banking app needs to read sms for OTP for autocompletion
          // 'android.permission.READ_SMS',
          'android.permission.RECEIVE_SMS',
          'android.permission.READ_PHONE_STATE',
          'android.permission.PROCESS_OUTGOING_CALLS',
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.BIND_DEVICE_ADMIN',
          'android.permission.SYSTEM_ALERT_WINDOW',
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.READ_CONTACTS',
          'android.permission.RECORD_AUDIO',
          'android.permission.CAMERA'
        ];
        
        analysis.suspiciousPermissions = permissions.filter(perm => 
          suspiciousPerms.includes(perm)
        );
        
        // Banking apps shouldn't need all these permissions
        if (analysis.suspiciousPermissions.length > 5) {
          analysis.hasPhishingIndicators = true;
        }
      }
      
      // Check for suspicious networking patterns in DEX files
      if (apkInfo.dexAnalysis && apkInfo.dexAnalysis.length > 0) {
        const networkingIndicators = [
          'http://',
          'socket',
          'tcp',
          'udp',
          'ssl',
          'certificate',
          'keystore',
          'encrypt',
          'decrypt',
          'base64',
          'json',
          'xml',
          'api',
          'server',
          'client'
        ];
        
        let networkingScore = 0;
        apkInfo.dexAnalysis.forEach(dex => {
          if (dex.stringAnalysis && dex.stringAnalysis.samples) {
            dex.stringAnalysis.samples.forEach(sample => {
              const text = sample.text.toLowerCase();
              networkingIndicators.forEach(indicator => {
                if (text.includes(indicator)) {
                  networkingScore++;
                }
              });
            });
          }
        });
        
        // High networking activity combined with banking mimicking is suspicious
        if (networkingScore > 15 && analysis.imitatesBankingApp) {
          analysis.suspiciousNetworking = true;
        }
      }
      
      // Calculate overall confidence
      let confidence = 0;
      if (analysis.imitatesBankingApp) confidence += 40;
      if (analysis.hasPhishingIndicators) confidence += 30;
      if (analysis.suspiciousNetworking) confidence += 20;
      if (analysis.suspiciousPermissions.length > 3) confidence += 10;
      
      analysis.confidence = Math.min(confidence, 100);
      
      return analysis;
      
    } catch (error) {
      console.error('Banking characteristics analysis failed:', error);
      return {
        ...analysis,
        error: error.message
      };
    }
  }
  
  calculateStringSimilarity(str1, str2) {
    // Simple Levenshtein distance based similarity
    const matrix = [];
    const len1 = str1.length;
    const len2 = str2.length;
    
    if (len1 === 0) return len2 === 0 ? 1 : 0;
    if (len2 === 0) return 0;
    
    // Initialize matrix
    for (let i = 0; i <= len1; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= len2; j++) {
      matrix[0][j] = j;
    }
    
    // Fill matrix
    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        if (str1[i - 1] === str2[j - 1]) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j] + 1,     // deletion
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j - 1] + 1  // substitution
          );
        }
      }
    }
    
    const distance = matrix[len1][len2];
    const maxLen = Math.max(len1, len2);
    return maxLen === 0 ? 1 : (maxLen - distance) / maxLen;
  }
}

module.exports = APKAnalyzer;