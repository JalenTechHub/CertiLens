/**
 * CertiLens Pro - Background Service Worker
 * 
 * Orchestrates all security analysis engines:
 * - Certificate Transparency log queries (crt.sh)
 * - Security header auditing
 * - RDAP/WHOIS domain age lookups
 * - DNS record analysis (Cloudflare DoH)
 * - URLScan.io threat intel
 * - Risk score computation
 * 
 * @module background
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

const STORAGE_KEYS = {
  SCAN_HISTORY: 'scanHistory',
  SETTINGS: 'settings',
  CACHE: 'analysisCache',
};

const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.pw', '.cc', '.su', '.ws', '.click', '.link', '.gdn',
  '.review', '.accountant', '.science', '.date', '.faith',
  '.racing', '.win', '.webcam', '.loans', '.stream',
]);

const BRAND_PATTERNS = [
  { brand: 'PayPal',    keywords: ['paypal'],           domains: ['paypal.com', 'paypal.me'] },
  { brand: 'Google',    keywords: ['google', 'gmail'],  domains: ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'] },
  { brand: 'Microsoft', keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'azure'],
                                                         domains: ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com', 'microsoftonline.com'] },
  { brand: 'Apple',     keywords: ['apple', 'icloud'],  domains: ['apple.com', 'icloud.com'] },
  { brand: 'Amazon',    keywords: ['amazon', 'aws'],    domains: ['amazon.com', 'aws.amazon.com'] },
  { brand: 'Netflix',   keywords: ['netflix'],          domains: ['netflix.com'] },
  { brand: 'Chase',     keywords: ['chase', 'jpmorgan'],domains: ['chase.com', 'jpmorganchase.com'] },
  { brand: 'Wells Fargo', keywords: ['wellsfargo'],     domains: ['wellsfargo.com'] },
  { brand: 'Facebook',  keywords: ['facebook', 'fb', 'instagram', 'whatsapp'],
                                                         domains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com'] },
];

const OBFUSCATION_PATTERNS = [
  { pattern: /\beval\s*\(/gi,                    label: 'eval() call',           weight: 15 },
  { pattern: /\batob\s*\(/gi,                    label: 'Base64 decode (atob)',   weight: 12 },
  { pattern: /String\.fromCharCode\s*\(/gi,      label: 'fromCharCode encoding', weight: 12 },
  { pattern: /unescape\s*\(/gi,                  label: 'unescape() call',       weight: 8  },
  { pattern: /document\.write\s*\(/gi,           label: 'document.write',        weight: 10 },
  { pattern: /\\x[0-9a-f]{2}/gi,                label: 'Hex escapes',           weight: 8  },
  { pattern: /\\u[0-9a-f]{4}/gi,                label: 'Unicode escapes',       weight: 5  },
];

const PHISHING_KEYWORDS = [
  'verify your account', 'confirm your identity', 'unusual activity',
  'suspended account', 'urgent action required', 'click here to verify',
  'your password will expire', 'update billing information', 'you have won',
  'claim your prize', 'limited time offer', 'act now', 'account locked',
  'security alert', 'unauthorized access', 'login attempt', 'reset password',
  'bank account', 'credit card number', 'social security', 'ssn',
];

// ─── Utility ──────────────────────────────────────────────────────────────────

/**
 * Extracts the registrable domain (eTLD+1) from a hostname.
 * Simple heuristic - handles most cases without a full PSL.
 * @param {string} hostname
 * @returns {string}
 */
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  // Handle common second-level TLDs (co.uk, com.au, etc.)
  const secondLevel = parts.slice(-2).join('.');
  const knownSLD = ['co.uk', 'co.nz', 'co.jp', 'com.au', 'com.br', 'org.uk', 'net.au'];
  if (knownSLD.includes(secondLevel)) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

/**
 * Detects homograph/punycode spoofing attacks.
 * @param {string} hostname
 * @returns {{ detected: boolean, decoded: string|null, confusables: string[] }}
 */
function analyzeHomograph(hostname) {
  const confusableMap = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'ο': 'o', 'ρ': 'p', 'ν': 'v', 'α': 'a', 'ε': 'e',
    '0': 'o', '1': 'l', '5': 's', '6': 'g', '8': 'b',
    'rn': 'm', 'cl': 'd', 'vv': 'w',
  };

  const confusables = [];
  let normalized = hostname;

  // Check for Punycode (xn--)
  const isPunycode = hostname.includes('xn--');

  // Check for mixed scripts (Latin + Cyrillic, etc.)
  const hasCyrillic = /[\u0400-\u04FF]/.test(hostname);
  const hasGreek    = /[\u0370-\u03FF]/.test(hostname);
  const hasLatin    = /[a-zA-Z]/.test(hostname);

  const mixedScript = (hasCyrillic || hasGreek) && hasLatin;

  // Check digit substitutions
  for (const [look, real] of Object.entries(confusableMap)) {
    if (hostname.includes(look) && look.length === 1) {
      confusables.push(`'${look}' looks like '${real}'`);
      normalized = normalized.split(look).join(real);
    }
  }

  return {
    detected: isPunycode || mixedScript || confusables.length > 0,
    isPunycode,
    mixedScript,
    confusables,
    normalizedHostname: normalized !== hostname ? normalized : null,
  };
}

/**
 * Fetch with timeout and retry support.
 * @param {string} url
 * @param {RequestInit} options
 * @param {number} timeoutMs
 * @param {number} retries
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = 8000, retries = 1) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(id);
      return response;
    } catch (err) {
      clearTimeout(id);
      if (attempt === retries) throw err;
      await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
    }
  }
}

// ─── Cache ────────────────────────────────────────────────────────────────────

/** Simple in-memory + storage cache for API responses */
const memCache = new Map();

async function getCached(key) {
  if (memCache.has(key)) {
    const { data, ts } = memCache.get(key);
    if (Date.now() - ts < CACHE_TTL_MS) return data;
    memCache.delete(key);
  }
  return null;
}

function setCache(key, data) {
  memCache.set(key, { data, ts: Date.now() });
}

// ─── Analysis Engines ─────────────────────────────────────────────────────────

/**
 * Queries crt.sh Certificate Transparency logs.
 * Returns the age of the oldest cert for the domain (days).
 * @param {string} domain
 * @returns {Promise<CTResult>}
 */
async function analyzeCertificateTransparency(domain) {
  const cacheKey = `ct:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const result = {
    available: false,
    oldestCertDays: null,
    newestCertDays: null,
    totalCerts: 0,
    issuers: [],
    riskContribution: 0,
    error: null,
  };

  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const res = await fetchWithTimeout(url, {}, 10000, 2);

    if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);

    const certs = await res.json();
    if (!Array.isArray(certs) || certs.length === 0) {
      result.available = true;
      result.riskContribution = 20; // No CT entries = suspicious
      return result;
    }

    const now = Date.now();
    const dates = certs
      .map(c => new Date(c.not_before).getTime())
      .filter(d => !isNaN(d))
      .sort((a, b) => a - b);

    result.available = true;
    result.totalCerts = certs.length;
    result.oldestCertDays = Math.floor((now - dates[0]) / 86400000);
    result.newestCertDays = Math.floor((now - dates[dates.length - 1]) / 86400000);

    const issuers = [...new Set(certs.map(c => c.issuer_name).filter(Boolean))];
    result.issuers = issuers.slice(0, 3);

    // Risk: cert < 7 days old is very suspicious
    if (result.newestCertDays < 7)   result.riskContribution = 30;
    else if (result.newestCertDays < 30)  result.riskContribution = 15;
    else if (result.newestCertDays < 90)  result.riskContribution = 5;
    else result.riskContribution = 0;

  } catch (err) {
    result.error = err.message;
    // Don't penalize for API failure
  }

  setCache(cacheKey, result);
  return result;
}

/**
 * Checks security response headers.
 * @param {string} url
 * @returns {Promise<HeaderResult>}
 */
async function analyzeSecurityHeaders(url) {
  const cacheKey = `headers:${url}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const HEADERS = [
    { name: 'content-security-policy',          label: 'CSP',               weight: 20, critical: true  },
    { name: 'strict-transport-security',         label: 'HSTS',              weight: 15, critical: true  },
    { name: 'x-frame-options',                   label: 'X-Frame-Options',   weight: 10, critical: false },
    { name: 'x-content-type-options',            label: 'X-Content-Type',    weight: 10, critical: false },
    { name: 'referrer-policy',                   label: 'Referrer-Policy',   weight: 5,  critical: false },
    { name: 'permissions-policy',                label: 'Permissions-Policy',weight: 5,  critical: false },
    { name: 'cross-origin-opener-policy',        label: 'COOP',              weight: 5,  critical: false },
    { name: 'cross-origin-embedder-policy',      label: 'COEP',              weight: 5,  critical: false },
  ];

  const result = {
    available: false,
    present: [],
    missing: [],
    score: 0,
    maxScore: HEADERS.reduce((s, h) => s + h.weight, 0),
    riskContribution: 0,
    error: null,
  };

  try {
    const res = await fetchWithTimeout(url, { method: 'HEAD' }, 8000, 1);
    result.available = true;

    let earned = 0;
    for (const hdr of HEADERS) {
      const val = res.headers.get(hdr.name);
      if (val) {
        result.present.push({ ...hdr, value: val });
        earned += hdr.weight;
      } else {
        result.missing.push(hdr);
      }
    }

    result.score = earned;
    const pct = earned / result.maxScore;
    // Missing critical headers raises risk
    const missedCritical = result.missing.filter(h => h.critical).length;
    result.riskContribution = Math.round((1 - pct) * 25) + (missedCritical * 5);

  } catch (err) {
    result.error = err.message;
  }

  setCache(cacheKey, result);
  return result;
}

/**
 * RDAP domain age lookup.
 * @param {string} domain
 * @returns {Promise<WhoisResult>}
 */
async function analyzeDomainAge(domain) {
  const cacheKey = `rdap:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const result = {
    available: false,
    registrationDate: null,
    ageInDays: null,
    registrar: null,
    expiryDate: null,
    riskContribution: 0,
    error: null,
  };

  // Try IANA RDAP bootstrap
  const rdapBootstrap = [
    `https://rdap.org/domain/${domain}`,
    `https://rdap.iana.org/domain/${domain}`,
  ];

  for (const url of rdapBootstrap) {
    try {
      const res = await fetchWithTimeout(url, {}, 8000, 1);
      if (!res.ok) continue;

      const data = await res.json();
      result.available = true;

      // Parse events
      if (data.events) {
        for (const event of data.events) {
          if (event.eventAction === 'registration') {
            result.registrationDate = event.eventDate;
          }
          if (event.eventAction === 'expiration') {
            result.expiryDate = event.eventDate;
          }
        }
      }

      // Parse registrar
      if (data.entities) {
        const registrar = data.entities.find(e =>
          e.roles && e.roles.includes('registrar')
        );
        if (registrar?.vcardArray) {
          const fn = registrar.vcardArray[1]?.find(v => v[0] === 'fn');
          if (fn) result.registrar = fn[3];
        }
      }

      if (result.registrationDate) {
        const regTime = new Date(result.registrationDate).getTime();
        result.ageInDays = Math.floor((Date.now() - regTime) / 86400000);

        if (result.ageInDays < 30)       result.riskContribution = 35;
        else if (result.ageInDays < 90)  result.riskContribution = 20;
        else if (result.ageInDays < 365) result.riskContribution = 8;
        else                             result.riskContribution = 0;
      }

      break;
    } catch (err) {
      result.error = err.message;
    }
  }

  setCache(cacheKey, result);
  return result;
}

/**
 * DNS record analysis via Cloudflare DNS over HTTPS.
 * Checks MX, TXT (SPF/DMARC), and A records.
 * @param {string} domain
 * @returns {Promise<DNSResult>}
 */
async function analyzeDNS(domain) {
  const cacheKey = `dns:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const result = {
    available: false,
    hasMX: false,
    hasSPF: false,
    hasDMARC: false,
    dmarcPolicy: null,
    spfRecord: null,
    aRecords: [],
    riskContribution: 0,
    error: null,
  };

  const dohBase = 'https://cloudflare-dns.com/dns-query';

  try {
    const [mxRes, txtRes, dmarcRes] = await Promise.allSettled([
      fetchWithTimeout(`${dohBase}?name=${domain}&type=MX`, { headers: { Accept: 'application/dns-json' } }),
      fetchWithTimeout(`${dohBase}?name=${domain}&type=TXT`, { headers: { Accept: 'application/dns-json' } }),
      fetchWithTimeout(`${dohBase}?name=_dmarc.${domain}&type=TXT`, { headers: { Accept: 'application/dns-json' } }),
    ]);

    result.available = true;

    if (mxRes.status === 'fulfilled' && mxRes.value.ok) {
      const data = await mxRes.value.json();
      result.hasMX = !!(data.Answer && data.Answer.length > 0);
    }

    if (txtRes.status === 'fulfilled' && txtRes.value.ok) {
      const data = await txtRes.value.json();
      if (data.Answer) {
        const spfRecord = data.Answer.find(r =>
          r.data && r.data.includes('v=spf1')
        );
        if (spfRecord) {
          result.hasSPF = true;
          result.spfRecord = spfRecord.data;
        }
      }
    }

    if (dmarcRes.status === 'fulfilled' && dmarcRes.value.ok) {
      const data = await dmarcRes.value.json();
      if (data.Answer) {
        const dmarc = data.Answer.find(r => r.data && r.data.includes('v=DMARC1'));
        if (dmarc) {
          result.hasDMARC = true;
          const policyMatch = dmarc.data.match(/p=(\w+)/);
          result.dmarcPolicy = policyMatch ? policyMatch[1] : 'none';
        }
      }
    }

    // Risk scoring for email security
    if (!result.hasSPF)   result.riskContribution += 8;
    if (!result.hasDMARC) result.riskContribution += 8;
    if (result.dmarcPolicy === 'none') result.riskContribution += 4;

  } catch (err) {
    result.error = err.message;
  }

  setCache(cacheKey, result);
  return result;
}

/**
 * Checks URLScan.io for recent scan results.
 * @param {string} domain
 * @returns {Promise<ThreatIntelResult>}
 */
async function analyzeThreatIntel(domain) {
  const cacheKey = `ti:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const result = {
    available: false,
    malicious: false,
    verdicts: [],
    lastSeen: null,
    riskContribution: 0,
    error: null,
  };

  try {
    // URLScan.io search (no API key needed for reads)
    const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`;
    const res = await fetchWithTimeout(url, {
      headers: { 'Accept': 'application/json' }
    }, 8000, 1);

    if (!res.ok) throw new Error(`URLScan returned ${res.status}`);
    const data = await res.json();

    result.available = true;

    if (data.results && data.results.length > 0) {
      result.lastSeen = data.results[0].task?.time || null;

      const maliciousScans = data.results.filter(r =>
        r.verdicts?.overall?.malicious === true
      );

      if (maliciousScans.length > 0) {
        result.malicious = true;
        result.verdicts = maliciousScans.map(r => r.verdicts?.overall);
        result.riskContribution = 50;
      }
    }

  } catch (err) {
    result.error = err.message;
  }

  setCache(cacheKey, result);
  return result;
}

// ─── Risk Scoring ─────────────────────────────────────────────────────────────

/**
 * Computes the final risk score from all analysis results.
 * 
 * Scoring philosophy: additive penalties capped at 100.
 * Each engine contributes independently so failures degrade gracefully.
 * 
 * @param {object} results - All engine results
 * @param {URL} parsedUrl
 * @returns {{ score: number, level: string, reasons: string[] }}
 */
function computeRiskScore(results, parsedUrl) {
  const reasons = [];
  let score = 0;

  const { ct, headers, whois, dns, dom, homograph, threatIntel } = results;

  // ── Protocol ──
  if (parsedUrl.protocol === 'http:') {
    score += 20;
    reasons.push('No HTTPS encryption');
  }

  // ── TLD ──
  const tld = '.' + parsedUrl.hostname.split('.').pop().toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 15;
    reasons.push(`High-risk TLD: ${tld}`);
  }

  // ── Homograph ──
  if (homograph?.detected) {
    if (homograph.isPunycode) {
      score += 25;
      reasons.push('Punycode/IDN domain — possible homograph attack');
    }
    if (homograph.mixedScript) {
      score += 30;
      reasons.push('Mixed Unicode scripts detected (homograph attack)');
    }
    if (homograph.confusables?.length) {
      score += 20;
      reasons.push(`Confusable characters: ${homograph.confusables.slice(0, 2).join(', ')}`);
    }
  }

  // ── CT Logs ──
  if (ct?.available) {
    score += ct.riskContribution;
    if (ct.riskContribution >= 30) reasons.push(`Certificate only ${ct.newestCertDays} days old`);
    else if (ct.riskContribution >= 15) reasons.push(`Recently issued certificate (${ct.newestCertDays} days)`);
  }

  // ── Domain Age ──
  if (whois?.available && whois.ageInDays !== null) {
    score += whois.riskContribution;
    if (whois.ageInDays < 30)       reasons.push(`Domain registered ${whois.ageInDays} days ago — very new`);
    else if (whois.ageInDays < 90)  reasons.push(`Domain registered ${whois.ageInDays} days ago — recently created`);
  }

  // ── Security Headers ──
  if (headers?.available) {
    score += headers.riskContribution;
    const critMissing = headers.missing?.filter(h => h.critical).map(h => h.label);
    if (critMissing?.length) reasons.push(`Missing critical headers: ${critMissing.join(', ')}`);
  }

  // ── DNS ──
  if (dns?.available) {
    score += dns.riskContribution;
    if (!dns.hasSPF)   reasons.push('No SPF record — email spoofing possible');
    if (!dns.hasDMARC) reasons.push('No DMARC policy — phishing emails unprotected');
  }

  // ── DOM Analysis ──
  if (dom) {
    if (dom.httpPasswordFields > 0) {
      score += 35;
      reasons.push(`Password field on insecure HTTP page`);
    }
    if (dom.brandSpoofing?.length) {
      score += 30;
      reasons.push(`Brand impersonation: ${dom.brandSpoofing.join(', ')}`);
    }
    if (dom.hiddenIframes > 0) {
      score += 15;
      reasons.push(`${dom.hiddenIframes} hidden iframe(s) detected`);
    }
    if (dom.obfuscation?.length) {
      const totalWeight = dom.obfuscation.reduce((s, o) => s + o.weight, 0);
      score += Math.min(totalWeight, 25);
      reasons.push(`Obfuscated JS: ${dom.obfuscation.map(o => o.label).join(', ')}`);
    }
    if (dom.suspiciousFormActions?.length) {
      score += 20;
      reasons.push(`Form submits to external domain: ${dom.suspiciousFormActions[0]}`);
    }
    if (dom.phishingKeywords > 2) {
      score += Math.min(dom.phishingKeywords * 3, 15);
      reasons.push(`${dom.phishingKeywords} phishing keywords detected in page`);
    }
  }

  // ── Threat Intel ──
  if (threatIntel?.available && threatIntel.malicious) {
    score += 50;
    reasons.push('Domain flagged as malicious by threat intelligence');
  }

  score = Math.min(Math.round(score), 100);

  const level =
    score >= 75 ? 'CRITICAL' :
    score >= 50 ? 'HIGH'     :
    score >= 25 ? 'MEDIUM'   : 'LOW';

  return { score, level, reasons };
}

// ─── Main Analysis Orchestrator ───────────────────────────────────────────────

/**
 * Runs all analysis engines in parallel and assembles the full report.
 * @param {string} tabUrl
 * @param {object} domData - Data from the content script
 * @returns {Promise<AnalysisReport>}
 */
async function runFullAnalysis(tabUrl, domData = {}) {
  const startTime = Date.now();
  let parsedUrl;

  try {
    parsedUrl = new URL(tabUrl);
  } catch {
    return { error: 'Invalid URL', url: tabUrl };
  }

  const hostname = parsedUrl.hostname;
  const domain   = getBaseDomain(hostname);

  // Process homograph locally (synchronous)
  const homograph = analyzeHomograph(hostname);

  // Check brand spoofing in DOM data against correct domains
  let brandSpoofing = [];
  if (domData.pageText || domData.title) {
    const combined = `${domData.title || ''} ${domData.pageText || ''}`.toLowerCase();
    for (const b of BRAND_PATTERNS) {
      const matches = b.keywords.some(k => combined.includes(k));
      const onOfficialDomain = b.domains.some(d =>
        hostname === d || hostname.endsWith('.' + d)
      );
      if (matches && !onOfficialDomain) {
        brandSpoofing.push(b.brand);
      }
    }
  }

  // Detect obfuscation patterns in page scripts
  let obfuscation = [];
  if (domData.scripts) {
    const scriptContent = domData.scripts.join('\n');
    for (const p of OBFUSCATION_PATTERNS) {
      if (p.pattern.test(scriptContent)) {
        obfuscation.push({ label: p.label, weight: p.weight });
      }
      p.pattern.lastIndex = 0;
    }
  }

  // Count phishing keywords
  let phishingKeywords = 0;
  if (domData.pageText) {
    const lower = domData.pageText.toLowerCase();
    phishingKeywords = PHISHING_KEYWORDS.filter(k => lower.includes(k)).length;
  }

  const dom = {
    httpPasswordFields: domData.httpPasswordFields || 0,
    brandSpoofing,
    hiddenIframes: domData.hiddenIframes || 0,
    obfuscation,
    suspiciousFormActions: domData.suspiciousFormActions || [],
    externalLinks: domData.externalLinks || 0,
    phishingKeywords,
  };

  // Run API-dependent engines concurrently
  const [ct, headers, whois, dns, threatIntel] = await Promise.all([
    analyzeCertificateTransparency(domain),
    analyzeSecurityHeaders(tabUrl),
    analyzeDomainAge(domain),
    analyzeDNS(domain),
    analyzeThreatIntel(domain),
  ]);

  const allResults = { ct, headers, whois, dns, dom, homograph, threatIntel };
  const { score, level, reasons } = computeRiskScore(allResults, parsedUrl);

  const report = {
    url: tabUrl,
    hostname,
    domain,
    scanTime: new Date().toISOString(),
    scanDurationMs: Date.now() - startTime,
    riskScore: score,
    riskLevel: level,
    reasons,
    engines: {
      certificateTransparency: ct,
      securityHeaders: headers,
      domainAge: whois,
      dns,
      dom,
      homograph,
      threatIntel,
    },
  };

  // Persist to scan history
  await saveScanToHistory(report);

  return report;
}

// ─── Scan History ─────────────────────────────────────────────────────────────

async function getScanHistory() {
  const data = await chrome.storage.local.get(STORAGE_KEYS.SCAN_HISTORY);
  return data[STORAGE_KEYS.SCAN_HISTORY] || [];
}

async function saveScanToHistory(report) {
  const history = await getScanHistory();
  const trimmed = {
    url: report.url,
    hostname: report.hostname,
    scanTime: report.scanTime,
    riskScore: report.riskScore,
    riskLevel: report.riskLevel,
    reasons: report.reasons.slice(0, 3),
  };

  history.unshift(trimmed);
  if (history.length > 100) history.length = 100;

  await chrome.storage.local.set({ [STORAGE_KEYS.SCAN_HISTORY]: history });
}

async function clearScanHistory() {
  await chrome.storage.local.set({ [STORAGE_KEYS.SCAN_HISTORY]: [] });
}

// ─── Settings ─────────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  autoScan: true,
  showNotifications: true,
  highlightRiskElements: true,
  theme: 'dark',
  demoMode: false,
  enabledEngines: {
    ct: true,
    headers: true,
    whois: true,
    dns: true,
    threatIntel: true,
  },
};

async function getSettings() {
  const data = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
  return { ...DEFAULT_SETTINGS, ...(data[STORAGE_KEYS.SETTINGS] || {}) };
}

async function saveSettings(settings) {
  await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
}

// ─── Demo Mode ────────────────────────────────────────────────────────────────

function getDemoReport(url) {
  return {
    url,
    hostname: 'paypa1-secure-login.xyz',
    domain: 'paypa1-secure-login.xyz',
    scanTime: new Date().toISOString(),
    scanDurationMs: 1842,
    riskScore: 91,
    riskLevel: 'CRITICAL',
    reasons: [
      'Brand impersonation: PayPal',
      'Domain registered 4 days ago — very new',
      "Confusable characters: '1' looks like 'l'",
      'Missing critical headers: CSP, HSTS',
      'Password field on insecure HTTP page',
      'Certificate only 4 days old',
      'No DMARC policy — phishing emails unprotected',
    ],
    engines: {
      certificateTransparency: {
        available: true, totalCerts: 1, oldestCertDays: 4, newestCertDays: 4,
        issuers: ["Let's Encrypt"], riskContribution: 30, error: null,
      },
      securityHeaders: {
        available: true,
        present: [{ name: 'x-content-type-options', label: 'X-Content-Type', weight: 10 }],
        missing: [
          { name: 'content-security-policy', label: 'CSP', weight: 20, critical: true },
          { name: 'strict-transport-security', label: 'HSTS', weight: 15, critical: true },
          { name: 'x-frame-options', label: 'X-Frame-Options', weight: 10, critical: false },
        ],
        score: 10, maxScore: 75, riskContribution: 22, error: null,
      },
      domainAge: {
        available: true, registrationDate: new Date(Date.now() - 4 * 86400000).toISOString(),
        ageInDays: 4, registrar: 'NameCheap', riskContribution: 35, error: null,
      },
      dns: {
        available: true, hasMX: false, hasSPF: false, hasDMARC: false,
        dmarcPolicy: null, riskContribution: 16, error: null,
      },
      dom: {
        httpPasswordFields: 1, brandSpoofing: ['PayPal'], hiddenIframes: 2,
        obfuscation: [{ label: 'Base64 decode (atob)', weight: 12 }],
        suspiciousFormActions: ['https://collector.ru/steal.php'],
        externalLinks: 3, phishingKeywords: 7,
      },
      homograph: {
        detected: true, isPunycode: false, mixedScript: false,
        confusables: ["'1' looks like 'l'"],
        normalizedHostname: 'paypal-secure-login.xyz',
      },
      threatIntel: {
        available: false, malicious: false, riskContribution: 0,
        error: 'API timeout',
      },
    },
    _isDemo: true,
  };
}

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'RUN_ANALYSIS': {
          const settings = await getSettings();
          if (settings.demoMode) {
            sendResponse({ success: true, data: getDemoReport(msg.url) });
            break;
          }
          const data = await runFullAnalysis(msg.url, msg.domData || {});
          sendResponse({ success: true, data });
          break;
        }
        case 'GET_HISTORY': {
          const history = await getScanHistory();
          sendResponse({ success: true, data: history });
          break;
        }
        case 'CLEAR_HISTORY': {
          await clearScanHistory();
          sendResponse({ success: true });
          break;
        }
        case 'GET_SETTINGS': {
          const settings = await getSettings();
          sendResponse({ success: true, data: settings });
          break;
        }
        case 'SAVE_SETTINGS': {
          await saveSettings(msg.settings);
          sendResponse({ success: true });
          break;
        }
        case 'EXPORT_REPORT': {
          sendResponse({ success: true, data: msg.report });
          break;
        }
        default:
          sendResponse({ success: false, error: `Unknown message type: ${msg.type}` });
      }
    } catch (err) {
      console.error('[CertiLens] Background error:', err);
      sendResponse({ success: false, error: err.message });
    }
  })();
  return true; // Keep message channel open for async
});

// ─── Startup ──────────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  if (reason === 'install') {
    await saveSettings(DEFAULT_SETTINGS);
    console.log('[CertiLens Pro] Installed successfully.');
    chrome.tabs.create({ url: 'pages/dashboard.html#onboarding' });
  }
});
