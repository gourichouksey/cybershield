// ./services/threatIntelligence.js
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class ThreatIntelligence {
  constructor() {
    this.virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
    this.malwareBazaarApiKey = process.env.MALWAREBAZAAR_API_KEY;
    this.abuseIPDBApiKey = process.env.ABUSEIPDB_API_KEY;

    // Cache for threat intelligence results
    this.threatCache = new Map();
    this.cacheTimeout = 24 * 60 * 60 * 1000; // 24 hours

    // Known malicious hashes database
    this.knownMalwareHashes = new Set();
    this.maliciousDomains = new Set();
    this.suspiciousPackages = new Set();

    // Banking trojans and their variants
    this.bankingTrojans = new Map([
      ['Anubis', ['com.anubis.', 'anubis.banking', 'banking.anubis']],
      ['Cerberus', ['com.cerberus.', 'cerberus.bank', 'banking.cerberus']],
      ['Eventbot', ['com.eventbot.', 'eventbot.banking']],
      ['Ginp', ['com.ginp.', 'ginp.banking']],
      ['Gustuff', ['com.gustuff.', 'gustuff.banking']],
      ['Hydra', ['com.hydra.', 'hydra.banking']],
      ['Marcher', ['com.marcher.', 'marcher.banking']],
      ['Red Alert', ['com.redalert.', 'redalert.banking']],
      ['TeaBot', ['com.teabot.', 'teabot.banking']],
      ['Xenomorph', ['com.xenomorph.', 'xenomorph.banking']]
    ]);

    this.phishingDomains = new Set([
      'bit.ly',
      'tinyurl.com',
      'short.link',
      't.co'
    ]);
  }

  async initialize() {
    try {
      console.log('Initializing Threat Intelligence service...');

      // Load threat intelligence databases
      await this.loadMalwareHashes();
      await this.loadMaliciousDomains();
      await this.loadSuspiciousPackages();

      // Initialize API connections
      if (this.virusTotalApiKey) {
        console.log('VirusTotal API enabled');
      }

      if (this.malwareBazaarApiKey) {
        console.log('MalwareBazaar API enabled');
      }

      console.log('Threat Intelligence service initialized successfully');

    } catch (error) {
      console.error('Failed to initialize Threat Intelligence service:', error);
      throw error;
    }
  }

  async loadMalwareHashes() {
    try {
      const hashesFile = path.join(__dirname, '../data/malware_hashes.txt');

      try {
        const content = await fs.readFile(hashesFile, 'utf8');
        const hashes = content.split('\n').filter(line => line.trim());
        hashes.forEach(hash => this.knownMalwareHashes.add(hash.toLowerCase()));
        console.log(`Loaded ${hashes.length} known malware hashes`);
      } catch (fileError) {
        console.log('No local malware hashes file found, using defaults');
        this.loadDefaultMalwareHashes();
      }

    } catch (error) {
      console.error('Failed to load malware hashes:', error);
      this.loadDefaultMalwareHashes();
    }
  }

  loadDefaultMalwareHashes() {
    const defaultHashes = [
      'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
      'b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456a1',
      'c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456a1b2'
    ];

    defaultHashes.forEach(hash => this.knownMalwareHashes.add(hash));
  }

  async loadMaliciousDomains() {
    try {
      const domainsFile = path.join(__dirname, '../data/malicious_domains.txt');

      try {
        const content = await fs.readFile(domainsFile, 'utf8');
        const domains = content.split('\n').filter(line => line.trim());
        domains.forEach(domain => this.maliciousDomains.add(domain.toLowerCase()));
        console.log(`Loaded ${domains.length} malicious domains`);
      } catch (fileError) {
        console.log('No local malicious domains file found, using defaults');
        this.loadDefaultMaliciousDomains();
      }

    } catch (error) {
      console.error('Failed to load malicious domains:', error);
      this.loadDefaultMaliciousDomains();
    }
  }

  loadDefaultMaliciousDomains() {
    const defaultDomains = [
      'malicious-banking-site.com',
      'fake-bank-login.net',
      'phishing-bank.org',
      'steal-credentials.info',
      'banking-trojan-c2.xyz'
    ];

    defaultDomains.forEach(domain => this.maliciousDomains.add(domain));
  }

  async loadSuspiciousPackages() {
    try {
      const packagesFile = path.join(__dirname, '../data/suspicious_packages.txt');

      try {
        const content = await fs.readFile(packagesFile, 'utf8');
        const packages = content.split('\n').filter(line => line.trim());
        packages.forEach(pkg => this.suspiciousPackages.add(pkg.toLowerCase()));
        console.log(`Loaded ${packages.length} suspicious packages`);
      } catch (fileError) {
        console.log('No local suspicious packages file found, using defaults');
      }

    } catch (error) {
      console.error('Failed to load suspicious packages:', error);
    }
  }

  async checkAPK(apkInfo) {
    try {
      const results = {
        knownMalware: false,
        suspiciousDomains: 0,
        blacklistedHashes: [],
        reputationScore: 100,
        threatDetails: [],
        bankingTrojanMatch: null,
        virusTotalResults: null,
        malwareBazaarResults: null
      };

      // Check file hashes against known malware
      if (apkInfo.fileHashes) {
        const hashes = [
          apkInfo.fileHashes.md5,
          apkInfo.fileHashes.sha1,
          apkInfo.fileHashes.sha256
        ];

        for (const hash of hashes) {
          if (hash && this.knownMalwareHashes.has(hash.toLowerCase())) {
            results.knownMalware = true;
            results.blacklistedHashes.push(hash);
            results.reputationScore -= 50;
            results.threatDetails.push(`Known malware hash detected: ${hash}`);
            break;
          }
        }
      }

      // Check for banking trojan characteristics
      if (apkInfo.manifest && apkInfo.manifest.package) {
        const trojanMatch = this.checkBankingTrojanSignatures(apkInfo.manifest.package);
        if (trojanMatch) {
          results.bankingTrojanMatch = trojanMatch;
          results.reputationScore -= 40;
          results.threatDetails.push(`Banking trojan signature detected: ${trojanMatch}`);
        }
      }

      // Check suspicious package names
      if (apkInfo.manifest && apkInfo.manifest.package) {
        if (this.suspiciousPackages.has(apkInfo.manifest.package.toLowerCase())) {
          results.reputationScore -= 30;
          results.threatDetails.push('Package name matches known suspicious pattern');
        }
      }

      // Check domains in DEX files
      if (apkInfo.dexAnalysis) {
        results.suspiciousDomains = this.checkSuspiciousDomains(apkInfo.dexAnalysis);
        if (results.suspiciousDomains > 0) {
          results.reputationScore -= Math.min(results.suspiciousDomains * 10, 30);
        }
      }

      // Query external threat intelligence services
      if (apkInfo.fileHashes) {
        // VirusTotal check
        if (this.virusTotalApiKey) {
          results.virusTotalResults = await this.queryVirusTotal(apkInfo.fileHashes.sha256);
          if (results.virusTotalResults && results.virusTotalResults.malicious > 0) {
            results.reputationScore -= results.virusTotalResults.malicious * 5;
            results.threatDetails.push(`VirusTotal detections: ${results.virusTotalResults.malicious}`);
          }
        }

        // MalwareBazaar check
        if (this.malwareBazaarApiKey) {
          results.malwareBazaarResults = await this.queryMalwareBazaar(apkInfo.fileHashes.sha256);
          if (results.malwareBazaarResults && results.malwareBazaarResults.found) {
            results.reputationScore -= 40;
            results.threatDetails.push('Sample found in MalwareBazaar database');
          }
        }
      }

      // Ensure reputation score doesn't go below 0
      results.reputationScore = Math.max(results.reputationScore, 0);

      return results;

    } catch (error) {
      console.error('Threat intelligence check failed:', error);
      return {
        knownMalware: false,
        suspiciousDomains: 0,
        blacklistedHashes: [],
        reputationScore: 50,
        threatDetails: [`Threat intelligence check failed: ${error.message}`],
        error: error.message
      };
    }
  }

  checkBankingTrojanSignatures(packageName) {
    const lowerPackage = packageName.toLowerCase();

    for (const [trojanName, signatures] of this.bankingTrojans) {
      for (const signature of signatures) {
        if (lowerPackage.includes(signature.toLowerCase())) {
          return trojanName;
        }
      }
    }

    return null;
  }

  checkSuspiciousDomains(dexAnalysis) {
    let suspiciousCount = 0;

    try {
      dexAnalysis.forEach(dex => {
        if (dex.stringAnalysis && dex.stringAnalysis.samples) {
          dex.stringAnalysis.samples.forEach(sample => {
            const text = (sample.text || '').toLowerCase();

            // Extract domains from URLs
            const urlRegex = /https?:\/\/([^\/\s]+)/gi;
            let match;

            while ((match = urlRegex.exec(text)) !== null) {
              const domain = match[1].toLowerCase();

              // Normalize domain (strip port/path)
              const host = domain.split(':')[0];

              // Check against known malicious domains
              if (this.maliciousDomains.has(host)) {
                suspiciousCount++;
                continue;
              }

              // Check against phishing domain patterns
              if (this.phishingDomains.has(host)) {
                suspiciousCount++;
                continue;
              }

              // Check for suspicious domain characteristics
              if (this.isDomainSuspicious(host)) {
                suspiciousCount++;
              }
            }
          });
        }
      });

    } catch (error) {
      console.error('Domain analysis failed:', error);
    }

    return suspiciousCount;
  }

  isDomainSuspicious(domain) {
    const suspiciousPatterns = [
      /bank.*login/i,
      /secure.*bank/i,
      /banking.*app/i,
      /mobile.*bank/i,
      /bank.*mobile/i,
      /financial.*secure/i,
      /account.*verify/i,
      /update.*bank/i,
      /\d+\.\d+\.\d+\.\d+/, // IP addresses
      /[a-z0-9]{10,}\.com/i, // Long random domain names
      /[a-z0-9]{5,}\.(tk|ml|ga|cf)$/i // Suspicious TLDs
    ];

    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  async queryVirusTotal(sha256Hash) {
    try {
      if (!this.virusTotalApiKey) {
        return null;
      }

      const cacheKey = `vt_${sha256Hash}`;
      if (this.threatCache.has(cacheKey)) {
        const cached = this.threatCache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return cached.data;
        }
      }

      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${sha256Hash}`,
        {
          headers: {
            'x-apikey': this.virusTotalApiKey
          },
          timeout: 10000
        }
      );

      const data = response.data;
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const result = {
        found: true,
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        engines: (stats.malicious || 0) + (stats.suspicious || 0),
        scanDate: data?.data?.attributes?.last_analysis_date || null,
        reputation: data?.data?.attributes?.reputation || 0
      };

      this.threatCache.set(cacheKey, { data: result, timestamp: Date.now() });

      return result;

    } catch (error) {
      if (error.response && error.response.status === 404) {
        return { found: false, error: 'File not found in VirusTotal' };
      }

      console.error('VirusTotal query failed:', error.message);
      return { found: false, error: error.message };
    }
  }

  async queryMalwareBazaar(sha256Hash) {
    try {
      if (!this.malwareBazaarApiKey) {
        return null;
      }

      const cacheKey = `mb_${sha256Hash}`;
      if (this.threatCache.has(cacheKey)) {
        const cached = this.threatCache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return cached.data;
        }
      }

      // Malwarebazaar expects form-encoded; axios will send JSON by default for objects,
      // so we encode as application/x-www-form-urlencoded:
      const params = new URLSearchParams();
      params.append('query', 'get_info');
      params.append('hash', sha256Hash);

      const response = await axios.post(
        'https://mb-api.abuse.ch/api/v1/',
        params.toString(),
        {
          headers: {
            'API-KEY': this.malwareBazaarApiKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 10000
        }
      );

      const data = response.data || {};
      const found = data.query_status === 'ok' && Array.isArray(data.data) && data.data.length > 0;
      const entry = found ? data.data[0] : null;

      const result = {
        found,
        signature: entry?.signature || null,
        family: entry?.malware || null,
        tags: entry?.tags || [],
        firstSeen: entry?.first_seen || null,
        lastSeen: entry?.last_seen || null
      };

      this.threatCache.set(cacheKey, { data: result, timestamp: Date.now() });

      return result;

    } catch (error) {
      console.error('MalwareBazaar query failed:', error.message);
      return { found: false, error: error.message };
    }
  }
}

// Export the class
module.exports = ThreatIntelligence;
