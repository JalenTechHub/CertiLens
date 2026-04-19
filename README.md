# CertiLens Pro

> Real-time phishing detection and web security analysis — a Chrome Manifest V3 extension that replicates the core logic of enterprise EDR browser agents.

---

## What It Does

Most "security extensions" check a URL against a single blocklist. CertiLens Pro runs **six independent analysis engines in parallel** and synthesizes them into a 0–100 risk score with per-finding rationale. Even if no blocklist has seen a brand-new phishing site yet, CertiLens can still flag it based on certificate age, domain registration recency, missing email authentication, and DOM-level indicators.

---

## Installation

1. Clone this repository
2. Open Chrome → `chrome://extensions/`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** → select the extension folder
5. The CertiLens Pro icon will appear in your toolbar

**Chrome Web Store:** [CertiLens Pro](https://chromewebstore.google.com/detail/certilens-pro/gfpmhgmpjefpkjgmiheafciplajjccbb)

---

## Privacy

CertiLens Pro does not collect, store, or transmit any personal information. All security analysis occurs locally on your device. See our full [Privacy Policy](PRIVACY.md).

---

## Architecture
certilens-extension/
├── manifest.json # MV3 — declarative net request, service worker
├── background.js # Service worker: all API calls, caching, risk engine
├── content.js # DOM scanner: injected into every page
├── popup.html / popup.js # Popup UI: risk ring, engine cards, findings
├── pages/
│ ├── dashboard.html # Full-page dashboard (Settings, History, About)
│ └── dashboard.js # Dashboard controller
└── icons/
└── icon{16,32,48,128}.png

**Data flow:**
Active Tab URL
│
├──► content.js ──────────────────────► DOM scan result
│ │
└──► background.js ◄────────────────────────┘
│
├── crt.sh CT API (cert age)
├── HEAD request (security headers)
├── RDAP API (domain age)
├── Cloudflare DoH (SPF / DMARC)
├── URLScan.io (threat intel)
└── Local heuristics (homograph, brand spoofing)
│
Risk Score (0–100)
│
popup.js (UI render)


---

## Analysis Engines

| Engine | API / Technique | What It Catches |
|--------|----------------|-----------------|
| **Certificate Transparency** | crt.sh JSON API | Certs < 30 days old — phishing domains can't have old certs |
| **Security Headers** | HTTP HEAD request | Missing CSP, HSTS, X-Frame-Options, COEP, COOP |
| **Domain Age** | RDAP (rdap.org) | Newly registered domains — most phishing sites are < 90 days old |
| **DNS / Email Security** | Cloudflare DoH | Missing SPF/DMARC — enables phishing emails to spoof the domain |
| **Threat Intelligence** | URLScan.io search | Known malicious verdicts from previous scans |
| **Homograph Detection** | Local Unicode analysis | IDN/punycode domains, mixed Cyrillic/Latin scripts, digit substitution |
| **DOM Heuristics** | content.js | Password fields on HTTP, brand spoofing, hidden iframes, obfuscated JS, cross-origin form actions |

---

## Risk Scoring

Scoring is **additive with hard caps** — each engine contributes independently:
Protocol (HTTP, no TLS) → +20
Suspicious TLD (.xyz, .tk, etc) → +15
Homograph detected → +20–30
CT cert < 7 days old → +30
CT cert < 30 days old → +15
Domain age < 30 days → +35
Domain age < 90 days → +20
Missing CSP + HSTS → +15–25
No SPF/DMARC → +8–16
Password field on HTTP → +35
Brand impersonation detected → +30
Hidden iframes → +15
Obfuscated JS (eval/atob/etc) → +8–15
Cross-origin form action → +20
Malicious on URLScan.io → +50
─────────────────────────────────────
Total (capped at 100) → Risk Score


| Score | Level | Color |
|-------|-------|-------|
| 0–24  | LOW      | Green  |
| 25–49 | MEDIUM   | Amber  |
| 50–74 | HIGH     | Red    |
| 75–100| CRITICAL | Hot pink |

---

## Key Technical Decisions

**Why RDAP instead of WHOIS?**  
WHOIS is an unstructured plaintext protocol with no standardized format — parsing it requires brittle regex per registrar. RDAP (RFC 7480) returns structured JSON, is free, requires no API key, and is IANA-standardized. All major registrars support it.

**Why Certificate Transparency for phishing detection?**  
CT logs are public and immutable — every TLS cert issued must be logged. A phishing site registered today cannot have a cert issued last year. Checking cert age via crt.sh is a high-signal, low-false-positive indicator that complements blocklist approaches.

**Why run everything in parallel?**  
`Promise.all()` over 5 async engines means total scan time is bounded by the slowest API (~2–4s), not the sum (~15–20s). Each engine also has independent timeout/retry logic, so a single API failure degrades gracefully without blocking the result.

**Why local homograph detection instead of an API?**  
Homograph analysis is deterministic — Unicode confusable character mappings don't change. Running it locally means: no API cost, no latency, works completely offline, and avoids sending the user's browsing history to a third party.

---

## Demo Mode

For offline presentations, enable **Demo Mode** from the dashboard or popup. It replaces live API calls with a pre-built report of a simulated phishing site (`paypa1-secure-login.xyz`) that demonstrates:

- Brand impersonation (PayPal)
- 4-day-old domain
- Homograph attack (`paypa1` → `paypal`)
- Credential-stealing form action
- Missing security headers
- No SPF/DMARC

---

## CompTIA Security+ Concepts Demonstrated

| Sec+ Domain | Concept | Where |
|-------------|---------|-------|
| **1.0 — General Security Concepts** | PKI, TLS, CSP, HSTS, certificate validation | CT engine, headers engine |
| **2.0 — Threats, Vulnerabilities & Mitigations** | Phishing, brand impersonation, homograph attacks, obfuscated malicious JS | Homograph engine, DOM heuristics |
| **3.0 — Security Architecture** | Defense-in-depth, multi-layer detection, graceful degradation | Overall engine design |
| **4.0 — Security Operations** | Threat intelligence, audit logging, automated scanning | URLScan.io engine, scan history |

---

## Tech Stack

- **Vanilla JavaScript** — no frameworks, no build step
- **Chrome Manifest V3** — service workers, declarative APIs
- **Free APIs only** — crt.sh, rdap.org, Cloudflare DoH, URLScan.io
- **Offline-capable** — graceful degradation when APIs are unavailable; full demo mode

---

## License

MIT — built as a portfolio project demonstrating applied web security engineering.
