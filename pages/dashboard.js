/**
 * CertiLens - Dashboard Controller
 * 
 * Manages the full-page dashboard opened via Options UI.
 * Handles: scan history, analytics, settings, engine controls, demo mode.
 * 
 * @module dashboard
 */

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────

let history = [];
let settings = {};
let currentPage = 'dashboard';

const PAGE_META = {
  dashboard: { title: 'Dashboard',     sub: 'Security analysis overview' },
  history:   { title: 'Scan History',  sub: 'All sites analyzed by CertiLens' },
  settings:  { title: 'Settings',      sub: 'Customize extension behavior' },
  engines:   { title: 'Engines',       sub: 'Configure analysis modules' },
  about:     { title: 'About',         sub: 'Architecture and Security+ concepts' },
  demo:      { title: 'Demo Mode',     sub: 'Offline presentation data' },
};

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  // Wire nav
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(item.dataset.page);
    });
  });

  // Load data
  [history, settings] = await Promise.all([
    sendMessage({ type: 'GET_HISTORY' }).then(r => r.data || []),
    sendMessage({ type: 'GET_SETTINGS' }).then(r => r.data || {}),
  ]);

  applyTheme(settings.theme || 'dark');
  updateSidebarStats();
  renderPage(currentPage);

  // Handle hash navigation (e.g. from popup #history, #onboarding)
  const hash = location.hash.replace('#', '');
  if (hash && PAGE_META[hash]) navigateTo(hash);
  if (hash === 'onboarding') navigateTo('about');
}

// ─── Navigation ───────────────────────────────────────────────────────────────

function navigateTo(page) {
  currentPage = page;

  // Update nav active state
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
  });

  // Update topbar
  const meta = PAGE_META[page] || {};
  document.getElementById('topbar-title').textContent = meta.title || page;
  document.getElementById('topbar-sub').textContent   = meta.sub   || '';

  // Show/hide pages
  document.querySelectorAll('.page').forEach(p => {
    p.classList.toggle('active', p.id === `page-${page}`);
  });

  // Topbar actions
  renderTopbarActions(page);

  // Render page-specific content
  renderPage(page);
}

function renderTopbarActions(page) {
  const wrap = document.getElementById('topbar-actions');
  wrap.innerHTML = '';

  if (page === 'history') {
    const btn = makeBtn('Clear All', 'btn-danger');
    btn.addEventListener('click', clearHistory);
    wrap.appendChild(btn);
  }

  if (page === 'settings') {
    const btn = makeBtn('Save Settings', 'btn-primary');
    btn.addEventListener('click', saveSettings);
    wrap.appendChild(btn);
  }
}

function makeBtn(label, cls) {
  const btn = document.createElement('button');
  btn.className = `btn ${cls}`;
  btn.textContent = label;
  return btn;
}

// ─── Page Renderers ───────────────────────────────────────────────────────────

function renderPage(page) {
  switch (page) {
    case 'dashboard': renderDashboard(); break;
    case 'history':   renderHistory();   break;
    case 'settings':  renderSettings();  break;
    case 'engines':   renderEngines();   break;
    case 'demo':      renderDemo();      break;
    // 'about' is pure static HTML
  }
}

// ── Dashboard ──

function renderDashboard() {
  const total    = history.length;
  const threats  = history.filter(h => h.riskLevel === 'HIGH' || h.riskLevel === 'CRITICAL').length;
  const safe     = history.filter(h => h.riskScore < 25).length;
  const avg      = total ? Math.round(history.reduce((s, h) => s + h.riskScore, 0) / total) : 0;

  setEl('stat-total',   total);
  setEl('stat-threats', threats);
  setEl('stat-avg',     total ? avg : '—');
  setEl('stat-safe',    safe);

  renderSparkline(history.slice(0, 20));
  renderTable('recent-table', history.slice(0, 8));
}

function renderSparkline(items) {
  const wrap = document.getElementById('sparkline');
  if (!wrap) return;

  if (!items.length) {
    wrap.innerHTML = `<div style="width:100%;text-align:center;color:var(--text-muted);font-size:12px;padding:20px 0">No scan data yet</div>`;
    return;
  }

  wrap.innerHTML = items.map((item, i) => {
    const h = Math.round((item.riskScore / 100) * 60) + 4;
    const color = riskColor(item.riskLevel);
    return `<div class="sparkline-bar"
      title="${escHtml(item.hostname)} — ${item.riskScore}/100 (${item.riskLevel})"
      style="height:${h}px;background:${color};opacity:${0.5 + (i / items.length) * 0.5}">
    </div>`;
  }).join('');
}

// ── History ──

function renderHistory() {
  renderTable('history-table', history, true);
}

function renderTable(id, items, showAll = false) {
  const wrap = document.getElementById(id);
  if (!wrap) return;

  if (!items.length) {
    wrap.innerHTML = `
      <div class="empty-table">
        <div class="empty-table-icon">🕵️</div>
        <div class="empty-table-title">No scans yet</div>
        <div style="font-size:12px;color:var(--text-muted)">
          Visit a website with CertiLens active to start building your scan history.
        </div>
      </div>
    `;
    return;
  }

  wrap.innerHTML = `
    <div class="table-head">
      <div>Domain</div>
      <div>Score</div>
      <div>Risk Level</div>
      <div>Scanned</div>
    </div>
    <div class="table-body">
      ${items.map(item => {
        const time = formatTime(item.scanTime);
        const color = riskColor(item.riskLevel);
        return `
          <div class="table-row">
            <div class="row-url" title="${escHtml(item.url)}">${escHtml(item.hostname || item.url)}</div>
            <div class="row-score" style="color:${color}">${item.riskScore}</div>
            <div><span class="risk-chip ${item.riskLevel}">${item.riskLevel}</span></div>
            <div class="row-time">${time}</div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

// ── Settings ──

function renderSettings() {
  // Wire toggles
  [
    'autoScan', 'highlightRiskElements', 'showNotifications', 'demoMode'
  ].forEach(key => {
    const el = document.getElementById(`s-${key}`);
    if (el) el.checked = !!settings[key];
  });

  const themeEl = document.getElementById('s-theme');
  if (themeEl) themeEl.value = settings.theme || 'dark';

  // Wire clear history button
  const clearBtn = document.getElementById('btn-clear-history');
  if (clearBtn) {
    clearBtn.onclick = clearHistory;
  }
}

async function saveSettings() {
  const newSettings = { ...settings };

  ['autoScan', 'highlightRiskElements', 'showNotifications', 'demoMode'].forEach(key => {
    const el = document.getElementById(`s-${key}`);
    if (el) newSettings[key] = el.checked;
  });

  const themeEl = document.getElementById('s-theme');
  if (themeEl) newSettings.theme = themeEl.value;

  settings = newSettings;
  await sendMessage({ type: 'SAVE_SETTINGS', settings });
  applyTheme(settings.theme || 'dark');
  showToast('Settings saved ✓');
  updateSidebarStats();
}

// ── Engines ──

function renderEngines() {
  const wrap = document.getElementById('engine-controls');
  if (!wrap) return;

  const engines = [
    { key: 'ct',          label: 'Certificate Transparency', desc: 'Queries crt.sh for certificate age (new certs = phishing risk)' },
    { key: 'headers',     label: 'Security Headers',         desc: 'Audits CSP, HSTS, X-Frame-Options and 5 other headers' },
    { key: 'whois',       label: 'Domain Age (RDAP)',        desc: 'Checks domain registration date — new domains are high risk' },
    { key: 'dns',         label: 'DNS / Email Security',     desc: 'Verifies SPF and DMARC records via Cloudflare DoH' },
    { key: 'threatIntel', label: 'Threat Intelligence',      desc: 'Searches URLScan.io for known malicious verdicts' },
  ];

  wrap.innerHTML = engines.map(e => {
    const enabled = settings.enabledEngines?.[e.key] !== false;
    return `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;padding:14px 0;border-bottom:1px solid var(--border)">
        <div style="flex:1;padding-right:16px">
          <div style="font-weight:600;margin-bottom:3px">${e.label}</div>
          <div style="font-size:11px;color:var(--text-dim)">${e.desc}</div>
        </div>
        <label class="toggle" style="margin-top:2px">
          <input type="checkbox" data-engine="${e.key}" ${enabled ? 'checked' : ''}>
          <span class="toggle-track"></span>
        </label>
      </div>
    `;
  }).join('');

  // Auto-save on toggle
  wrap.addEventListener('change', async (e) => {
    const key = e.target.dataset.engine;
    if (!key) return;
    if (!settings.enabledEngines) settings.enabledEngines = {};
    settings.enabledEngines[key] = e.target.checked;
    await sendMessage({ type: 'SAVE_SETTINGS', settings });
    showToast(`${key} engine ${e.target.checked ? 'enabled' : 'disabled'}`);
  });
}

// ── Demo ──

function renderDemo() {
  const btn    = document.getElementById('btn-enable-demo');
  const status = document.getElementById('demo-status');
  if (!btn || !status) return;

  function updateDemoUI() {
    const on = !!settings.demoMode;
    btn.textContent = on ? 'Disable Demo Mode' : 'Enable Demo Mode';
    btn.className   = `btn ${on ? 'btn-danger' : 'btn-primary'}`;
    status.textContent = `Demo mode is currently ${on ? 'ON' : 'OFF'}`;
    status.style.color = on ? 'var(--medium)' : 'var(--text-muted)';
  }

  updateDemoUI();

  btn.onclick = async () => {
    settings.demoMode = !settings.demoMode;
    await sendMessage({ type: 'SAVE_SETTINGS', settings });
    updateDemoUI();
    showToast(`Demo mode ${settings.demoMode ? 'enabled' : 'disabled'}`);
  };
}

// ─── Sidebar Stats ────────────────────────────────────────────────────────────

function updateSidebarStats() {
  const total   = history.length;
  const threats = history.filter(h => h.riskLevel === 'HIGH' || h.riskLevel === 'CRITICAL').length;
  const avg     = total ? Math.round(history.reduce((s, h) => s + h.riskScore, 0) / total) : null;

  setEl('sb-total',   total);
  setEl('sb-threats', threats);
  setEl('sb-avg',     avg !== null ? avg : '—');
}

// ─── Actions ──────────────────────────────────────────────────────────────────

async function clearHistory() {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  await sendMessage({ type: 'CLEAR_HISTORY' });
  history = [];
  updateSidebarStats();
  renderPage(currentPage);
  showToast('Scan history cleared');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Applies light/dark theme by swapping CSS custom properties on :root.
 * The dashboard HTML uses var(--bg), var(--text), etc. throughout.
 * @param {'dark'|'light'} theme
 */
function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === 'light') {
    root.style.setProperty('--bg',           '#f0f4f8');
    root.style.setProperty('--bg-2',         '#ffffff');
    root.style.setProperty('--surface',      '#ffffff');
    root.style.setProperty('--surface-2',    '#f5f8fb');
    root.style.setProperty('--border',       '#d1dce8');
    root.style.setProperty('--border-2',     '#b8ccde');
    root.style.setProperty('--text',         '#1a2a3a');
    root.style.setProperty('--text-dim',     '#4a6a88');
    root.style.setProperty('--text-muted',   '#8aa8c0');
    root.style.setProperty('--accent',       '#0077cc');
    root.style.setProperty('--accent-2',     '#005fa3');
    root.style.setProperty('--accent-dim',   'rgba(0, 119, 204, 0.08)');
    root.style.setProperty('--accent-border','rgba(0, 119, 204, 0.25)');
    root.style.setProperty('--low-bg',       'rgba(21, 128, 61, 0.08)');
    root.style.setProperty('--medium-bg',    'rgba(180, 83, 9, 0.08)');
    root.style.setProperty('--high-bg',      'rgba(185, 28, 28, 0.08)');
    root.style.setProperty('--critical-bg',  'rgba(190, 18, 60, 0.08)');
  } else {
    // Restore dark theme defaults
    root.style.setProperty('--bg',           '#080c10');
    root.style.setProperty('--bg-2',         '#0d1117');
    root.style.setProperty('--surface',      '#111820');
    root.style.setProperty('--surface-2',    '#162030');
    root.style.setProperty('--border',       '#1a2535');
    root.style.setProperty('--border-2',     '#243348');
    root.style.setProperty('--text',         '#c8d8e8');
    root.style.setProperty('--text-dim',     '#5a7a94');
    root.style.setProperty('--text-muted',   '#2e4a5e');
    root.style.setProperty('--accent',       '#00d4ff');
    root.style.setProperty('--accent-2',     '#0088cc');
    root.style.setProperty('--accent-dim',   'rgba(0, 212, 255, 0.08)');
    root.style.setProperty('--accent-border','rgba(0, 212, 255, 0.2)');
    root.style.setProperty('--low-bg',       'rgba(34, 197, 94, 0.08)');
    root.style.setProperty('--medium-bg',    'rgba(245, 158, 11, 0.08)');
    root.style.setProperty('--high-bg',      'rgba(239, 68, 68, 0.08)');
    root.style.setProperty('--critical-bg',  'rgba(255, 34, 102, 0.08)');
  }
}

function sendMessage(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (response) => {
      resolve(response || {});
    });
  });
}

function riskColor(level) {
  return {
    LOW:      '#22c55e',
    MEDIUM:   '#f59e0b',
    HIGH:     '#ef4444',
    CRITICAL: '#ff2266',
  }[level] || '#5a7a94';
}

function formatTime(isoStr) {
  if (!isoStr) return '—';
  const d = new Date(isoStr);
  const now = new Date();
  const diffMs = now - d;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHr  = Math.floor(diffMs / 3600000);
  const diffDay = Math.floor(diffMs / 86400000);

  if (diffMin < 1)   return 'just now';
  if (diffMin < 60)  return `${diffMin}m ago`;
  if (diffHr  < 24)  return `${diffHr}h ago`;
  if (diffDay < 7)   return `${diffDay}d ago`;
  return d.toLocaleDateString();
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', init);
