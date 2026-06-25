# Cybersecurity Hub

A lightweight security audit tool for small businesses, paired with a static education hub for learning ethical hacking fundamentals.

## Components

**Scanner** — input a domain or IP, receive a structured JSON report covering open ports, SSL certificate status, and common misconfigurations. Pure Python stdlib, no external dependencies.

**Education Hub** — static site covering ethical hacking basics, top security tools, and a structured beginner learning path. Functions as a lead magnet for the audit tool.

## Tech Stack

- **Scanner:** Python 3, stdlib only (`socket`, `ssl`, `urllib`)
- **Education site:** Static HTML/CSS
- **Output:** JSON report + human-readable terminal summary

## Project Structure

```
cybersec-hub/
├── scanner.py        # Port scan, SSL check, vuln probe
├── hub/
│   ├── index.html    # Ethical hacking intro
│   ├── tools.html    # Top 10 security tools
│   └── course.html   # 5-module learning path
└── reports/          # Scan output directory
```

## Usage

```bash
python scanner.py --target example.com
python scanner.py --target 192.168.1.1 --output reports/scan.json
```

## Status

Planning. Part of the SPIRIT OS project portfolio.
