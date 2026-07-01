#!/usr/bin/env python3
"""Fetch threat intel feeds and write ~/cybersec-hub/feed.json."""

import json
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).parent / "feed.json"
HEADERS = {"User-Agent": "cybersec-hub/1.0 (educational)"}


def fetch_json(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def get_cves():
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           "?resultsPerPage=20&startIndex=0")
    data = fetch_json(url)
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )
        score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            bucket = cve.get("metrics", {}).get(key)
            if bucket:
                m = bucket[0]["cvssData"]
                score = m.get("baseScore")
                severity = m.get("baseSeverity", "UNKNOWN")
                break
        out.append({
            "id": cve["id"],
            "description": desc[:300],
            "severity": severity,
            "published": cve.get("published", ""),
            "cvss_score": score,
        })
    return out


def get_kev():
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    data = fetch_json(url)
    vulns = data.get("vulnerabilities", [])
    return [
        {
            "cveID": v["cveID"],
            "vulnerabilityName": v.get("vulnerabilityName", ""),
            "dateAdded": v.get("dateAdded", ""),
            "shortDescription": v.get("shortDescription", "")[:300],
            "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", ""),
        }
        for v in vulns[-10:]
    ]


_ATOM_NS = "http://www.w3.org/2005/Atom"

def _fetch_rss(url, limit):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
    root = ET.fromstring(raw)
    items = root.findall(".//item")
    if items:
        return [
            {
                "title": (it.findtext("title") or "").strip(),
                "link": (it.findtext("link") or "").strip(),
                "published": (it.findtext("pubDate") or "").strip(),
                "description": (it.findtext("description") or "")[:250].strip(),
            }
            for it in items[:limit]
        ]
    # Atom fallback
    ns = f"{{{_ATOM_NS}}}"
    return [
        {
            "title": (e.findtext(f"{ns}title") or "").strip(),
            "link": (e.find(f"{ns}link") or {}).get("href", "") if e.find(f"{ns}link") is not None else "",
            "published": (e.findtext(f"{ns}published") or "").strip(),
            "description": (e.findtext(f"{ns}summary") or "")[:250].strip(),
        }
        for e in root.findall(f".//{ns}entry")[:limit]
    ]


def get_threat_news():
    return _fetch_rss("https://feeds.feedburner.com/TheHackersNews", 8)


def get_exploits():
    return _fetch_rss("https://www.exploit-db.com/rss.xml", 8)


def get_sans_diary():
    return _fetch_rss("https://isc.sans.edu/rssfeed.xml", 5)


def get_news():
    url = ("https://hn.algolia.com/api/v1/search"
           "?tags=story&query=hacking+security+vulnerability&hitsPerPage=10")
    data = fetch_json(url)
    return [
        {
            "title": h.get("title", ""),
            "url": h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}",
            "points": h.get("points", 0),
            "author": h.get("author", ""),
            "created_at": h.get("created_at", ""),
        }
        for h in data.get("hits", [])
        if h.get("title")
    ]


def main():
    feed = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "cves": [], "kev": [], "news": [],
        "threat_news": [], "exploits": [], "sans_diary": [],
    }
    for key, fn, label in [
        ("cves",         get_cves,        "CVEs"),
        ("kev",          get_kev,         "KEV"),
        ("news",         get_news,        "HN News"),
        ("threat_news",  get_threat_news, "Threat News (THN)"),
        ("exploits",     get_exploits,    "Exploit-DB"),
        ("sans_diary",   get_sans_diary,  "SANS ISC Diary"),
    ]:
        try:
            feed[key] = fn()
            print(f"[OK]   {label}: {len(feed[key])} items")
        except Exception as e:
            print(f"[SKIP] {label}: {e}")

    OUT.write_text(json.dumps(feed, indent=2))
    print(f"[DONE] Written: {OUT}")


if __name__ == "__main__":
    main()

# cron: */30 * * * * cd ~/cybersec-hub && python fetch_feed.py >> logs/feed.log 2>&1
