# CertiLens

> Real-time phishing detection and web security analysis — a Chrome Manifest V3 extension that applies layered, enterprise-style detection logic to every site you visit.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Chrome Web Store](https://img.shields.io/badge/Chrome%20Web%20Store-Available-brightgreen)](https://chromewebstore.google.com/detail/certilens-pro/gfpmhgmpjefpkjgmiheafciplajjccbb)
[![Made by Jalen Joseph](https://img.shields.io/badge/Made%20by-Jalen%20Joseph-cyan)](https://github.com/JalenTechHub)

---

## What It Does

Most security extensions check a URL against a single blocklist. CertiLens runs **six independent analysis engines in parallel** and synthesizes them into a 0–100 risk score with per-finding rationale. Even if no blocklist has ever seen a brand-new phishing site, CertiLens can still flag it based on certificate age, domain registration recency, missing email authentication, and DOM-level indicators.

The core design philosophy is **defense-in-depth**: no single signal is authoritative, but six corroborating signals are hard to fake simultaneously.

---

## Installation

### From the Chrome Web Store (recommended)
**[Install CertiLens](https://chromewebstore.google.com/detail/certilens-pro/gfpmhgmpjefpkjgmiheafciplajjccbb)**

### Developer / Unpacked Install
```bash
git clone https://github.com/JalenTechHub/CertiLens
```
1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select the cloned folder
4. The CertiLens icon appears in your toolbar

---

## Architecture

```
certilens/
├── manifest.json          # MV3 — service worker, declarative APIs
├── background.js          # Service worker: API orchestration, caching, risk engine
├── content.js             # DOM scanner: injected into every page at document_idle
├── popup.html             # Popup shell
├── popup.js               # Popup controller: risk ring, engine cards, findings
├── pages/
│   ├── dashboard.html     # Full-tab dashboard (Settings, History, Engines, About)
│   └── dashboard.js       # Dashboard controller
└── icons/
    └── icon{16,32,48,128}.png
```

**Data flow:**
```
Active Tab URL
│
├──► content.js ──────────────────────► DOM scan result
│                                              │
└──► background.js ◄───────────────────────────┘
        │
        ├── crt.sh CT API        (certificate age)
        ├── HTTP HEAD request    (security headers)
        ├── RDAP API             (domain registration age)
        ├── Cloudflare DoH       (SPF / DMARC DNS records)
        ├── URLScan.io           (threat intelligence)
        └── Local heuristics    (homograph, brand spoofing)
               │
        Risk Score (0–100)
               │
        popup.js (UI render)
```

All six engines run via `Promise.all()` — total scan time is bounded by the slowest API (~2–4s), not the sum of all calls (~15–20s).

---

## Analysis Engines

| Engine | API / Technique | What It Catches |
|--------|----------------|-----------------|
| **Certificate Transparency** | crt.sh JSON API | Certs under 30 days old — phishing domains cannot have old certificates |
| **Security Header Audit** | HTTP HEAD request | Missing CSP, HSTS, X-Frame-Options, COEP, COOP, Referrer-Policy |
| **Domain Age** | RDAP (RFC 7480) | Newly registered domains — most phishing sites are under 90 days old |
| **DNS / Email Security** | Cloudflare DoH | Missing SPF/DMARC — enables spoofed phishing emails from the domain |
| **Threat Intelligence** | URLScan.io search | Known malicious verdicts from prior community scans |
| **Homograph Detection** | Local Unicode analysis | IDN/punycode domains, mixed Cyrillic/Latin scripts, digit substitution |
| **DOM Heuristics** | content.js | Password fields on HTTP, brand spoofing, hidden iframes, obfuscated JS, cross-origin form actions |

---

## Risk Scoring

Scoring is **additive with a hard cap at 100** — each engine contributes independently:

```
Protocol (HTTP, no TLS)            → +20
Suspicious TLD (.xyz, .tk, etc.)   → +15
Homograph detected                 → +20–30
CT cert under 7 days old           → +30
CT cert under 30 days old          → +15
Domain age under 30 days           → +35
Domain age under 90 days           → +20
Missing CSP + HSTS                 → +15–25
No SPF / DMARC                     → +8–16
Password field on HTTP             → +35
Brand impersonation detected       → +30
Hidden iframes                     → +15
Obfuscated JS (eval/atob/etc.)     → +8–15
Cross-origin form action           → +20
Malicious on URLScan.io            → +50
─────────────────────────────────────────
Total (capped at 100)              → Risk Score
```

| Score | Level | Color |
|-------|-------|-------|
| 0–24 | LOW | Green |
| 25–49 | MEDIUM | Amber |
| 50–74 | HIGH | Red |
| 75–100 | CRITICAL | Hot pink |

---

## Key Technical Decisions

**Why RDAP instead of WHOIS?**
WHOIS is an unstructured plaintext protocol — parsing it requires brittle per-registrar regex. RDAP (RFC 7480) returns structured JSON, is IANA-standardized, free, requires no API key, and is supported by all major registrars.

**Why Certificate Transparency for phishing detection?**
CT logs are public and immutable — every TLS certificate issued must be logged. A phishing domain registered today cannot have a cert issued last year. Checking cert age via crt.sh is a high-signal, low-false-positive indicator that complements blocklist approaches.

**Why run everything in parallel?**
`Promise.all()` over six async engines means total scan time is bounded by the slowest API (~2–4s), not the sum (~15–20s). Each engine has independent timeout and retry logic, so a single API failure degrades gracefully without blocking the result.

**Why local homograph detection instead of an API?**
Homograph analysis is deterministic — Unicode confusable character mappings do not change. Running it locally means no API cost, no latency, full offline support, and no user browsing data sent to a third party.

**Why check page identity signals instead of full body text for brand spoofing?**
An early version scanned the full page body, which caused false positives — google.com search results contain competitor brand names as links. The fix: only check the page title, h1/h2 headings, logo image alt text, and meta description. Those are the signals a spoofed page controls to impersonate a brand, and they will not randomly contain unrelated brand names.

---

## Demo Mode

For offline presentations, enable **Demo Mode** from the dashboard or popup. It replaces live API calls with a pre-built report of a simulated phishing site (paypa1-secure-login.xyz) demonstrating:

- Brand impersonation targeting PayPal
- 4-day-old domain and certificate
- Homograph attack (paypa1 vs paypal)
- Credential-stealing cross-origin form action
- Missing all security headers
- No SPF or DMARC records

---

## Security+ Concepts Demonstrated

| Sec+ Domain | Concept | Where in CertiLens |
|-------------|---------|-------------------|
| **1.0 — General Security Concepts** | PKI, TLS, CSP, HSTS, certificate validation | CT engine, headers engine |
| **2.0 — Threats, Vulnerabilities & Mitigations** | Phishing, brand impersonation, homograph attacks, obfuscated JS | Homograph engine, DOM heuristics |
| **3.0 — Security Architecture** | Defense-in-depth, multi-layer detection, graceful degradation | Overall engine design |
| **4.0 — Security Operations** | Threat intelligence, audit logging, automated scanning | URLScan.io engine, scan history |

---

## Tech Stack

- **Vanilla JavaScript** — no frameworks, no build step, no dependencies
- **Chrome Manifest V3** — service workers, declarative APIs
- **Free public APIs only** — crt.sh, rdap.org, Cloudflare DoH, URLScan.io
- **Offline-capable** — graceful degradation when APIs are unavailable; full demo mode for presentations

---

## Privacy

CertiLens does not collect, store, or transmit any personal information. All analysis runs locally or via public APIs using only the domain name being analyzed. See [PRIVACY.md](PRIVACY.md) for full details.

---

## Support the Project

CertiLens is free and open source, built solo by a high school student. If it has helped you stay safer online, consider [buying me a coffee](https://paypal.me/JalenTechHub).

---

## Links

- **Chrome Web Store:** [Install CertiLens](https://chromewebstore.google.com/detail/certilens-pro/gfpmhgmpjefpkjgmiheafciplajjccbb)
- **GitHub:** [github.com/JalenTechHub/CertiLens](https://github.com/JalenTechHub/CertiLens)
- **YouTube:** [@JalenTechHub](https://www.youtube.com/@JalenTechHub)
- **LinkedIn:** [Jalen Joseph](https://www.linkedin.com/in/jalen-joseph/)

---

## License

**GNU General Public License v3.0** — permissions are conditioned on making complete source code available under the same license. Copyright and license notices must be preserved. See [LICENSE](LICENSE) for full terms.

Built by [Jalen Joseph](https://github.com/JalenTechHub) as a portfolio project demonstrating applied web security engineering.
