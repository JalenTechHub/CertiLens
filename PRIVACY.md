# Privacy Policy for CertiLens

**Last Updated: April 2026**

---

## Overview

CertiLens is designed with privacy as a core requirement, not an afterthought. The extension does not collect, store, or transmit any personal information. No account is required. No telemetry is sent. No browsing history ever leaves your device.

---

## What Happens When You Use CertiLens

When you click the CertiLens icon or a scan runs automatically, the extension:

1. **Reads the current tab's URL** to extract the domain name for analysis
2. **Scans the page's DOM** locally — reading the page title, headings, form fields, and scripts already loaded in your browser
3. **Queries public APIs using only the domain name** — never the full URL, never any page content, never any personal identifiers

The domain name (e.g., `example.com`) is the only piece of information that ever leaves your browser, and only to the public services listed below.

---

## Third-Party Services

CertiLens makes requests to the following public services. Each receives **only the domain name** being analyzed:

| Service | Purpose | Privacy Policy |
|---------|---------|----------------|
| [crt.sh](https://crt.sh) | Certificate Transparency log lookup | Public database, no account required |
| [rdap.org](https://rdap.org) | Domain registration date (RDAP protocol) | Public IANA-standard service |
| [cloudflare-dns.com](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/) | DNS-over-HTTPS for SPF/DMARC record checks | Cloudflare's public DNS resolver |
| [urlscan.io](https://urlscan.io/about/) | Threat intelligence lookup | Public scan database |

None of these services receive your IP address in a way that is tied to CertiLens specifically — requests are standard HTTPS calls indistinguishable from normal browser traffic.

---

## Local Data Storage

CertiLens stores the following data **locally on your device only**, using Chrome's `storage.local` API:

- **Scan history** — a log of domains you have analyzed, their risk scores, and findings
- **User preferences** — settings like auto-scan toggle, notification preferences, and theme

This data:
- Never leaves your browser
- Is not synced to any server
- Is not accessible to any website or third party
- Can be cleared at any time via the Settings page in the CertiLens dashboard

---

## What CertiLens Does NOT Do

- Does not collect your name, email, or any personal identifiers
- Does not track which websites you visit beyond what you explicitly scan
- Does not sell, share, or monetize any data
- Does not include any analytics or tracking SDKs
- Does not require an account or login
- Does not store full page URLs (only domain names in scan history)

---

## Permissions Explained

CertiLens requests the following Chrome permissions:

| Permission | Why It Is Needed |
|-----------|-----------------|
| `activeTab` | Read the URL and DOM of the tab you are currently viewing |
| `storage` | Save scan history and settings locally on your device |
| `tabs` | Open the full dashboard page in a new tab when you click Settings |
| `webRequest` | Inspect HTTP response headers for the security header audit engine |
| `alarms` | Schedule periodic cache cleanup so stored data does not grow indefinitely |
| `downloads` | Export your scan history as a JSON report |
| `notifications` | Alert you when a high-risk site is detected (requires opt-in in Settings) |
| `host_permissions: <all_urls>` | Allow the content script and header checks to run on any domain you visit |

---

## Open Source

CertiLens is fully open source under the GNU General Public License v3.0. You can read every line of code that handles your data at [github.com/JalenTechHub/CertiLens](https://github.com/JalenTechHub/CertiLens).

---

## Contact

For privacy questions or concerns, open an issue on the [GitHub repository](https://github.com/JalenTechHub/CertiLens/issues).

---

## Changes to This Policy

This policy may be updated as the extension evolves. The "Last Updated" date at the top of this document reflects the most recent revision. Continued use of CertiLens after an update constitutes acceptance of the revised policy.
