/**
 * CertiLens - Content Script
 * 
 * Performs DOM-level security heuristics:
 * - HTTP password field detection
 * - Form action cross-origin analysis
 * - Hidden iframe detection
 * - JavaScript obfuscation signals
 * - Page text extraction for phishing keyword analysis
 * - External link analysis
 * 
 * Sends results to background.js when requested.
 * 
 * @module content
 */

'use strict';

(function () {
  // Prevent double-injection on SPA navigations
  if (window.__certilensInjected) return;
  window.__certilensInjected = true;

  /**
   * Scans the DOM and returns structured findings.
   * @returns {DOMScanResult}
   */
  function scanDOM() {
    const result = {
      httpPasswordFields: 0,
      hiddenIframes: 0,
      suspiciousFormActions: [],
      externalLinks: 0,
      scripts: [],
      pageText: '',
      title: document.title || '',
      // Identity signals for accurate brand spoofing detection
      headings: [],
      logoAlts: [],
      metaDescription: '',
    };

    const isHttp = location.protocol === 'http:';
    const currentHost = location.hostname;

    // ── Page identity signals (used for brand spoofing — NOT full body text) ──
    // Collect h1/h2 headings — these establish what brand the page claims to be
    document.querySelectorAll('h1, h2').forEach(h => {
      const t = (h.textContent || '').trim();
      if (t.length > 1 && t.length < 120) result.headings.push(t.toLowerCase());
    });

    // Logo image alt text — phishing pages often use brand logos
    document.querySelectorAll('img[alt]').forEach(img => {
      const src = (img.src || '').toLowerCase();
      const alt = (img.alt || '').trim().toLowerCase();
      if (alt.length > 1 && (src.includes('logo') || src.includes('brand') || img.closest('a[href="/"]'))) {
        result.logoAlts.push(alt);
      }
    });

    // Meta description
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) result.metaDescription = (metaDesc.getAttribute('content') || '').toLowerCase().slice(0, 200);

    // ── Password fields on HTTP ──
    if (isHttp) {
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      result.httpPasswordFields = passwordInputs.length;
    }

    // ── Hidden iframes ──
    const iframes = document.querySelectorAll('iframe');
    for (const frame of iframes) {
      const style = window.getComputedStyle(frame);
      const isHidden =
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        parseInt(style.width) === 0 ||
        parseInt(style.height) === 0 ||
        frame.getAttribute('width') === '0' ||
        frame.getAttribute('height') === '0' ||
        (frame.getAttribute('style') || '').includes('display:none');

      if (isHidden) result.hiddenIframes++;
    }

    // ── Suspicious form actions ──
    const forms = document.querySelectorAll('form[action]');
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (!action || action.startsWith('#') || action.startsWith('/') || action.startsWith('?')) continue;

      try {
        const actionUrl = new URL(action, location.href);
        if (actionUrl.hostname !== currentHost) {
          result.suspiciousFormActions.push(actionUrl.hostname);
        }
      } catch {
        // Malformed action URL
        result.suspiciousFormActions.push(action.slice(0, 60));
      }
    }

    // ── External links ──
    const links = document.querySelectorAll('a[href]');
    for (const link of links) {
      try {
        const linkUrl = new URL(link.href, location.href);
        if (linkUrl.hostname !== currentHost &&
            linkUrl.protocol.startsWith('http')) {
          result.externalLinks++;
        }
      } catch { /* ignore */ }
    }

    // ── Script content collection (inline only, first 5) ──
    const scripts = document.querySelectorAll('script:not([src])');
    let count = 0;
    for (const script of scripts) {
      if (count >= 5) break;
      const content = script.textContent || '';
      if (content.length > 20 && content.length < 100000) {
        result.scripts.push(content.slice(0, 5000));
        count++;
      }
    }

    // ── Page text (truncated, for keyword matching) ──
    try {
      const body = document.body;
      if (body) {
        // Skip scripts/styles from text extraction
        const clone = body.cloneNode(true);
        clone.querySelectorAll('script, style, noscript').forEach(el => el.remove());
        result.pageText = (clone.innerText || clone.textContent || '').slice(0, 8000);
      }
    } catch { /* ignore */ }

    return result;
  }

  // ── Message listener ──
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'SCAN_DOM') {
      try {
        const domData = scanDOM();
        sendResponse({ success: true, data: domData });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    }
    return false; // synchronous response
  });

  // ── Visual risk highlight (if enabled) ──
  chrome.storage.local.get('settings', ({ settings }) => {
    if (settings?.highlightRiskElements) {
      highlightRiskElements();
    }
  });

  function highlightRiskElements() {
    // Highlight password fields on HTTP
    if (location.protocol === 'http:') {
      document.querySelectorAll('input[type="password"]').forEach(el => {
        el.style.outline = '3px solid #ff4444';
        el.title = '⚠ CertiLens: Password field on insecure HTTP connection';
      });
    }
  }

  // ── SPA navigation detection ──
  // Re-scan on URL change (handles React/Vue/Angular SPAs)
  let lastUrl = location.href;
  const observer = new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      window.__certilensInjected = false;
    }
  });
  observer.observe(document.body || document.documentElement, {
    subtree: true,
    childList: true,
  });

})();
