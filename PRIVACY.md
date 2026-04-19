# Privacy Policy for CertiLens Pro

**Last Updated: April 19, 2026**

## Overview

CertiLens Pro does not collect, store, or transmit any personal information. All security analysis occurs locally on your device.

## Data Processing

When you click the extension icon, CertiLens:
- Reads the current tab's URL and DOM structure to detect security indicators
- Queries public Certificate Transparency logs (crt.sh) for SSL certificate age
- Queries public RDAP servers for domain registration dates
- Makes a HEAD request to the current site to check security headers

## Data Retention

- User preferences and scan history are stored locally using Chrome's `storage.local` API
- This data never leaves your browser
- You can clear all stored data via the extension's Settings page

## Third-Party Services

CertiLens makes requests to:
- `crt.sh` - Public Certificate Transparency log database
- `rdap.org` - Public domain registration lookup service
- `cloudflare-dns.com` - DNS over HTTPS for SPF/DMARC checks

These services receive only the domain name being analyzed. No user identifiers, browsing history, or personal data are included.

## Contact

For questions, open an issue on this GitHub repository.

## Changes

This policy may be updated. Continued use of CertiLens Pro constitutes acceptance of any changes.
