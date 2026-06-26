# Cybersecurity Hub

![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python) ![stdlib only](https://img.shields.io/badge/dependencies-stdlib_only-green) ![HTML/CSS](https://img.shields.io/badge/Frontend-HTML%2FCSS-orange) ![Live Data](https://img.shields.io/badge/Data-Live_NVD_%2B_CISA-red)

Part of the **SPIRIT Labs** portfolio — AI-powered products by [Rishi Thangada](https://github.com/rishithangada).

---

## What It Does

Cybersecurity Hub is three tools in one: a live threat-intel dashboard pulling from NVD, CISA KEV, and Hacker News; a port scanner SaaS tool for quick security audits; and a 3-page education hub covering ethical hacking fundamentals.

No external Python dependencies — pure stdlib throughout.

---

## Features

- **Live threat feed** — CVEs from NVD, known exploited vulnerabilities from CISA KEV, and security news from HN; auto-refreshes every 60 seconds
- **Port scanner** — scans 20 common ports, performs SSL certificate check, audits HTTP security headers; outputs structured JSON + terminal summary
- **Education hub** — 3-page static site: ethical hacking intro, top security tools, and a 5-module beginner learning path

---

## Setup

Populate the live feed:
```bash
python3 fetch_feed.py
```

Open the hub:
```bash
open hub/index.html
```

Run the scanner:
```bash
python3 scanner.py example.com
```

---

## Cron (auto-refresh feed)

```
*/30 * * * * cd ~/cybersec-hub && python3 fetch_feed.py
```

---

## Status

Active development. Part of the SPIRIT Labs product portfolio.
