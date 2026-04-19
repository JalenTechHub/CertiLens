/**
 * CertiLens Pro - Popup Controller
 * 
 * Manages the popup UI lifecycle:
 * 1. Gets active tab URL
 * 2. Requests DOM scan from content script
 * 3. Sends analysis request to background worker
 * 4. Renders results into the popup
 * 
 * @module popup
 */

'use strict';

// ─── DOM Refs ─────────────────────────────────────────────────────────────────

const $main    = document.getElementById('main-content');
const $footer  = document.getElementById('footer');
const $btnDemo = document.getElementById('btn-demo');
const $btnSettings = document.getElementById('btn-settings');

// ─── State ────────────────────────────────────────────────────────────────────

let currentReport = null;
let currentTab    = null;
let isLoading     = false;

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  // Wire up header buttons
  $btnSettings.addEventListener('click', () => {
    chrome.tabs.create({ url: 'pages/dashboard.html' });
    window.close();
  });

  $btnDemo.addEventListener('click', toggleDemoMode);

  document.getElementById('btn-export')?.addEventListener('click', exportReport);
  document.getElementById('btn-history')?.addEventListener('click', () => {
    chrome.tabs.create({ url: 'pages/dashboard.html#history' });
    window.close();
  });
  document.getElementById('btn-rescan')?.addEventListener('click', runScan);

  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;

  if (!tab || !tab.url || !tab.url.startsWith('http')) {
    renderUnsupportedPage(tab?.url);
    return;
  }

  // Run analysis
  await runScan();
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

async function runScan() {
  if (isLoading) return;
  isLoading = true;

  showLoading();

  let domData = {};
  try {
    const domResult = await chrome.tabs.sendMessage(currentTab.id, { type: 'SCAN_DOM' });
    if (domResult?.success) domData = domResult.data;
  } catch {
    // Content script not injected yet — that's ok
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'RUN_ANALYSIS',
      url: currentTab.url,
      domData,
    });

    if (response?.success) {
      currentReport = response.data;
      renderReport(currentReport);
    } else {
      renderError(response?.error || 'Analysis failed');
    }
  } catch (err) {
    renderError(err.message);
  } finally {
    isLoading = false;
  }
}

// ─── Render Helpers ───────────────────────────────────────────────────────────

function showLoading() {
  $footer.style.display = 'none';
  $main.innerHTML = `
    <div class="loading-state">
      <div class="loading-bars">
        <span></span><span></span><span></span><span></span><span></span>
      </div>
      <div class="loading-label">ANALYZING</div>
      <div class="loading-sublabel" id="loading-step">Querying Certificate Transparency logs…</div>
    </div>
  `;

  // Cycle through loading messages
  const steps = [
    'Querying Certificate Transparency logs…',
    'Checking security headers…',
    'Running RDAP domain lookup…',
    'Analyzing DNS records…',
    'Scanning DOM for heuristics…',
    'Computing risk score…',
  ];
  let i = 0;
  const stepEl = document.getElementById('loading-step');
  const interval = setInterval(() => {
    i = (i + 1) % steps.length;
    if (stepEl) stepEl.textContent = steps[i];
  }, 800);

  // Store interval ID to clear it when done
  window._loadingInterval = interval;
}

function renderReport(report) {
  clearInterval(window._loadingInterval);

  const { riskScore, riskLevel, engines, reasons, scanDurationMs, _isDemo } = report;
  const parsedUrl = tryParseUrl(report.url);

  const isHttps = parsedUrl?.protocol === 'https:';
  const hostname = report.hostname || parsedUrl?.hostname || '—';

  // Build HTML
  let html = '';

  // Demo banner
  if (_isDemo) {
    html += `<div class="demo-banner">⚡ DEMO MODE — Simulated phishing site data</div>`;
  }

  // URL bar
  html += `
    <div class="url-bar">
      <span class="protocol-badge ${isHttps ? 'https' : 'http'}">${isHttps ? 'HTTPS' : 'HTTP'}</span>
      <span class="url-label" title="${escHtml(report.url)}">${escHtml(hostname)}</span>
    </div>
  `;

  // Score ring
  const circumference = 245;
  const dashOffset = circumference - (riskScore / 100) * circumference;
  const ringColor = levelColor(riskLevel);
  const duration = scanDurationMs ? `${(scanDurationMs / 1000).toFixed(1)}s` : '—';

  html += `
    <div class="score-section">
      <div class="score-ring-wrap">
        <svg class="score-ring" viewBox="0 0 88 88" width="88" height="88">
          <circle class="score-ring-bg" cx="44" cy="44" r="39"/>
          <circle class="score-ring-fill" cx="44" cy="44" r="39"
            stroke="${ringColor}"
            style="stroke-dashoffset: ${dashOffset}"/>
        </svg>
        <div class="score-center">
          <span class="score-number" style="color:${ringColor}">${riskScore}</span>
          <span class="score-label">/ 100</span>
        </div>
      </div>
      <div class="score-meta">
        <div class="risk-level-badge ${riskLevel}">
          <span class="pulse"></span>
          ${riskLevel}
        </div>
        <div class="scan-duration">Scanned in ${duration}</div>
        <button class="scan-btn" id="btn-rescan-inline">↺ Re-analyze</button>
      </div>
    </div>
  `;

  // Engine cards
  html += `
    <div class="section-header">
      <span>Security Engines</span>
      <span style="color:var(--text-muted);font-size:10px">6 checks</span>
    </div>
    <div class="engines-grid">
      ${renderCTCard(engines.certificateTransparency)}
      ${renderHeadersCard(engines.securityHeaders)}
      ${renderWhoisCard(engines.domainAge)}
      ${renderDNSCard(engines.dns)}
      ${renderDOMCard(engines.dom)}
      ${renderHomographCard(engines.homograph)}
    </div>
  `;

  // Findings
  if (reasons && reasons.length > 0) {
    html += `
      <div class="section-header">
        <span>Findings</span>
        <span style="color:var(--text-muted);font-size:10px">${reasons.length} issues</span>
      </div>
      <div class="reasons-list">
        ${reasons.map(r => `
          <div class="reason-item">
            <span class="reason-icon">${reasonIcon(r)}</span>
            <span class="reason-text">${escHtml(r)}</span>
          </div>
        `).join('')}
      </div>
    `;
  } else {
    html += `
      <div class="section-header"><span>Findings</span></div>
      <div style="padding:16px;text-align:center;color:var(--text-dim);font-size:12px">
        ✓ No significant threats detected
      </div>
    `;
  }

  $main.innerHTML = html;
  $footer.style.display = 'flex';

  // Animate ring
  requestAnimationFrame(() => {
    const ring = $main.querySelector('.score-ring-fill');
    if (ring) ring.style.strokeDashoffset = dashOffset;
  });

  // Wire rescan button
  $main.querySelector('#btn-rescan-inline')?.addEventListener('click', runScan);
}

// ─── Engine Card Renderers ────────────────────────────────────────────────────

function renderCTCard(ct) {
  if (!ct?.available) {
    return engineCard('CT Logs', '—', 'crt.sh unavailable', 'na',
      'Certificate Transparency: checks how old the domain\'s SSL cert is');
  }
  const age = ct.newestCertDays !== null ? `${ct.newestCertDays}d old` : 'No certs';
  const risk = ct.riskContribution >= 25 ? 'critical' :
               ct.riskContribution >= 15 ? 'high' :
               ct.riskContribution >= 5  ? 'medium' : 'low';
  const detail = ct.totalCerts ? `${ct.totalCerts} cert${ct.totalCerts > 1 ? 's' : ''} found` : 'No CT entries';
  return engineCard('CT Logs', age, detail, risk,
    'Certificate Transparency logs: new certs (< 30 days) indicate potential phishing infrastructure');
}

function renderHeadersCard(h) {
  if (!h?.available) {
    return engineCard('Headers', '—', 'HEAD request failed', 'na',
      'HTTP security headers: CSP, HSTS, X-Frame-Options, etc.');
  }
  const pct = Math.round((h.score / h.maxScore) * 100);
  const risk = pct >= 75 ? 'low' : pct >= 50 ? 'medium' : pct >= 25 ? 'high' : 'critical';
  return engineCard('Headers', `${pct}%`, `${h.present?.length || 0}/${(h.present?.length || 0) + (h.missing?.length || 0)} present`, risk,
    'Security headers score: higher % = better configured server');
}

function renderWhoisCard(w) {
  if (!w?.available || w.ageInDays === null) {
    return engineCard('Domain Age', '—', w?.error ? 'RDAP unavailable' : 'Unknown age', 'na',
      'Domain registration age via RDAP protocol — new domains are high risk');
  }
  const age = w.ageInDays < 365
    ? `${w.ageInDays}d`
    : `${(w.ageInDays / 365).toFixed(1)}y`;
  const risk = w.riskContribution >= 30 ? 'critical' :
               w.riskContribution >= 20 ? 'high' :
               w.riskContribution >= 8  ? 'medium' : 'low';
  return engineCard('Domain Age', age, w.registrar ? w.registrar.slice(0, 20) : 'Unknown registrar', risk,
    'Domain age: domains registered < 90 days are commonly used for phishing');
}

function renderDNSCard(dns) {
  if (!dns?.available) {
    return engineCard('DNS / Email', '—', 'DNS unavailable', 'na',
      'DNS records: checks SPF and DMARC for email authentication');
  }
  const risk = dns.riskContribution >= 14 ? 'high' :
               dns.riskContribution >= 8  ? 'medium' : 'low';
  const detail = `SPF ${dns.hasSPF ? '✓' : '✗'} · DMARC ${dns.hasDMARC ? '✓' : '✗'}`;
  return engineCard('DNS / Email', dns.hasSPF && dns.hasDMARC ? 'Secure' : 'Weak', detail, risk,
    'Email security: missing SPF/DMARC enables phishing emails spoofing this domain');
}

function renderDOMCard(dom) {
  if (!dom) return engineCard('DOM Scan', '—', 'No data', 'na', 'DOM analysis: scans page structure for phishing signals');

  const issues = (dom.httpPasswordFields > 0 ? 1 : 0) +
                 (dom.brandSpoofing?.length > 0 ? 1 : 0) +
                 (dom.hiddenIframes > 0 ? 1 : 0) +
                 (dom.obfuscation?.length > 0 ? 1 : 0) +
                 (dom.suspiciousFormActions?.length > 0 ? 1 : 0);

  const risk = issues >= 3 ? 'critical' : issues >= 2 ? 'high' : issues >= 1 ? 'medium' : 'low';
  return engineCard('DOM Scan', `${issues} issue${issues !== 1 ? 's' : ''}`,
    issues === 0 ? 'Page looks clean' : buildDOMDetail(dom), risk,
    'DOM heuristics: detects password fields on HTTP, brand spoofing, hidden iframes, obfuscated JS');
}

function renderHomographCard(h) {
  if (!h) return engineCard('Homograph', '—', 'No data', 'na', 'Homograph detection: identifies lookalike Unicode domains');
  const risk = h.mixedScript ? 'critical' : h.isPunycode ? 'high' : h.detected ? 'medium' : 'low';
  const label = h.detected ? 'Detected' : 'Clean';
  const detail = h.mixedScript ? 'Mixed scripts!' :
                 h.isPunycode  ? 'Punycode IDN' :
                 h.confusables?.length ? h.confusables[0] : 'No lookalikes';
  return engineCard('Homograph', label, detail, risk,
    'Homograph attack detection: spots domains using lookalike Unicode characters (е vs e, 0 vs o)');
}

function engineCard(name, value, detail, riskClass, tooltip) {
  return `
    <div class="engine-card risk-${riskClass}" data-tooltip="${escHtml(tooltip)}">
      <div class="engine-name">${name}</div>
      <div class="engine-value">${value}</div>
      <div class="engine-detail">${detail}</div>
    </div>
  `;
}

function buildDOMDetail(dom) {
  const parts = [];
  if (dom.httpPasswordFields > 0) parts.push('HTTP pwd');
  if (dom.brandSpoofing?.length) parts.push('Brand spoof');
  if (dom.hiddenIframes > 0) parts.push('Hidden iframe');
  if (dom.obfuscation?.length) parts.push('Obfusc JS');
  if (dom.suspiciousFormActions?.length) parts.push('Bad form');
  return parts.join(' · ') || 'Various';
}

// ─── Misc Render States ───────────────────────────────────────────────────────

function renderUnsupportedPage(url) {
  $main.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">🔒</div>
      <div class="empty-title">Page Not Scannable</div>
      <div class="empty-desc">
        CertiLens Pro can only analyze HTTP and HTTPS web pages.
        Navigate to a website to run a security scan.
      </div>
    </div>
  `;
}

function renderError(msg) {
  $main.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">⚠</div>
      <div class="empty-title">Analysis Error</div>
      <div class="empty-desc">${escHtml(msg)}</div>
      <button class="scan-btn" id="btn-retry" style="margin-top:8px">↺ Retry</button>
    </div>
  `;
  $main.querySelector('#btn-retry')?.addEventListener('click', runScan);
}

// ─── Export ───────────────────────────────────────────────────────────────────

function exportReport() {
  if (!currentReport) return;

  const r = currentReport;
  const lines = [
    '═══════════════════════════════════════',
    '       CERTILENS PRO SECURITY REPORT   ',
    '═══════════════════════════════════════',
    '',
    `URL:         ${r.url}`,
    `Scanned:     ${new Date(r.scanTime).toLocaleString()}`,
    `Duration:    ${r.scanDurationMs}ms`,
    '',
    `RISK SCORE:  ${r.riskScore}/100  [${r.riskLevel}]`,
    '',
    '─── FINDINGS ───────────────────────────',
    ...(r.reasons?.length ? r.reasons.map(x => `  ▸ ${x}`) : ['  ✓ No significant threats detected']),
    '',
    '─── ENGINE RESULTS ─────────────────────',
    `  Certificate Transparency:`,
    `    Cert age:      ${r.engines?.certificateTransparency?.newestCertDays ?? '—'} days`,
    `    Total certs:   ${r.engines?.certificateTransparency?.totalCerts ?? '—'}`,
    `    Risk contrib:  ${r.engines?.certificateTransparency?.riskContribution ?? '—'}`,
    '',
    `  Security Headers:`,
    `    Score:         ${r.engines?.securityHeaders?.score ?? '—'}/${r.engines?.securityHeaders?.maxScore ?? '—'}`,
    `    Missing:       ${r.engines?.securityHeaders?.missing?.map(h => h.label).join(', ') || 'None'}`,
    '',
    `  Domain Age (RDAP):`,
    `    Registered:    ${r.engines?.domainAge?.registrationDate ?? '—'}`,
    `    Age (days):    ${r.engines?.domainAge?.ageInDays ?? '—'}`,
    `    Registrar:     ${r.engines?.domainAge?.registrar ?? '—'}`,
    '',
    `  DNS / Email Security:`,
    `    SPF:           ${r.engines?.dns?.hasSPF ? 'Present' : 'Missing'}`,
    `    DMARC:         ${r.engines?.dns?.hasDMARC ? `Present (${r.engines?.dns?.dmarcPolicy})` : 'Missing'}`,
    '',
    `  DOM Analysis:`,
    `    HTTP pwd fields:  ${r.engines?.dom?.httpPasswordFields ?? 0}`,
    `    Brand spoofing:   ${r.engines?.dom?.brandSpoofing?.join(', ') || 'None'}`,
    `    Hidden iframes:   ${r.engines?.dom?.hiddenIframes ?? 0}`,
    `    Obfuscated JS:    ${r.engines?.dom?.obfuscation?.map(o => o.label).join(', ') || 'None'}`,
    '',
    `  Homograph Detection:`,
    `    Status:        ${r.engines?.homograph?.detected ? 'DETECTED' : 'Clean'}`,
    `    Punycode:      ${r.engines?.homograph?.isPunycode ? 'Yes' : 'No'}`,
    '',
    '═══════════════════════════════════════',
    'Generated by CertiLens Pro',
    'A Chrome extension for web security analysis',
    '═══════════════════════════════════════',
  ].join('\n');

  const blob = new Blob([lines], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const hostname = r.hostname?.replace(/[^a-z0-9.-]/gi, '_') || 'unknown';
  const ts   = new Date().toISOString().slice(0, 10);
  chrome.downloads.download({
    url,
    filename: `certilens-report-${hostname}-${ts}.txt`,
    saveAs: false,
  }).catch(() => {
    // Fallback: open in new tab
    chrome.tabs.create({ url });
  });
}

// ─── Demo Mode Toggle ─────────────────────────────────────────────────────────

async function toggleDemoMode() {
  const res = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
  const settings = res.data;
  settings.demoMode = !settings.demoMode;
  await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings });

  $btnDemo.style.color = settings.demoMode ? 'var(--medium)' : '';
  $btnDemo.style.borderColor = settings.demoMode ? 'var(--medium)' : '';

  await runScan();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function levelColor(level) {
  return { LOW: '#22c55e', MEDIUM: '#f59e0b', HIGH: '#ef4444', CRITICAL: '#ff2266' }[level] || '#888';
}

function reasonIcon(reason) {
  const r = reason.toLowerCase();
  if (r.includes('cert'))     return '🔏';
  if (r.includes('domain'))   return '📅';
  if (r.includes('header'))   return '🛡';
  if (r.includes('spf') || r.includes('dmarc')) return '📧';
  if (r.includes('password')) return '🔑';
  if (r.includes('brand') || r.includes('impersonation')) return '🎭';
  if (r.includes('iframe'))   return '🖼';
  if (r.includes('obfusc') || r.includes('js')) return '⚡';
  if (r.includes('form'))     return '📝';
  if (r.includes('https') || r.includes('http')) return '🔓';
  if (r.includes('homograph') || r.includes('unicode') || r.includes('puny')) return '🔤';
  if (r.includes('malicious') || r.includes('threat')) return '☠';
  return '⚠';
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function tryParseUrl(url) {
  try { return new URL(url); } catch { return null; }
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', init);
