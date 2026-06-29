#!/usr/bin/env python3
"""Port scanner + basic vuln checker. Usage: python scanner.py <host>"""
import sys, os, socket, ssl, json, urllib.request, urllib.error
from datetime import datetime, timezone

PORTS = [21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,8888]
NAMES = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",
         443:"https",445:"smb",993:"imaps",995:"pop3s",1433:"mssql",3306:"mysql",
         3389:"rdp",5432:"postgres",6379:"redis",8080:"http-alt",8443:"https-alt",8888:"http-alt2"}
RISKY = {23:("HIGH","Telnet open — unencrypted"),21:("MEDIUM","FTP open — consider SFTP"),
         6379:("HIGH","Redis exposed — likely unauthenticated"),3389:("MEDIUM","RDP exposed")}
T = 1.5  # ponytail: single short timeout constant, tune per network

def scan_ports(host):
    open_ports = []
    for p in PORTS:
        try:
            s = socket.socket(); s.settimeout(T)
            if s.connect_ex((host, p)) == 0: open_ports.append(p)
            s.close()
        except OSError: pass
    return open_ports

def check_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, 443), T), server_hostname=host) as s:
            cert = s.getpeercert()
        exp = cert["notAfter"]
        days = (datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                - datetime.now(timezone.utc)).days
        return {"valid": True, "expires": exp, "days_remaining": days, "expiring_soon": days < 30}
    except ssl.SSLCertVerificationError as e: return {"valid": False, "error": str(e)}
    except Exception as e: return {"valid": None, "error": str(e)}

def _cert_issuer(cert):
    parts = []
    for group in cert.get("issuer", ()):
        for key, value in group:
            if key in ("organizationName", "commonName"):
                parts.append(value)
    return " / ".join(parts) if parts else "unknown"

def passive_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, 443), T), server_hostname=host) as s:
            cert = s.getpeercert()
        exp = cert["notAfter"]
        days = (datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                - datetime.now(timezone.utc)).days
        return {
            "valid": True,
            "expires": exp,
            "days_remaining": days,
            "expiring_soon": days < 30,
            "issuer": _cert_issuer(cert),
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": None, "error": str(e)}

def check_headers(host, port, tls):
    url = f"{'https' if tls else 'http'}://{host}{'/' if port in (80,443) else f':{port}/'}"
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent":"cybersec-scanner/1.0"}), timeout=3)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e: hdrs = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e: return {"error": str(e)}
    want = ["x-frame-options","x-content-type-options"]
    if tls: want.append("strict-transport-security")
    return {"server": hdrs.get("server","?"),
            "missing_headers": [h for h in want if h not in hdrs]}

def passive_headers(host):
    url = f"https://{host}/"
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent":"d2d-spirit-passive/1.0"}),
            timeout=5,
        )
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        return {"error": str(e)}

    wanted = [
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-xss-protection",
    ]
    cookies = hdrs.get("set-cookie", "")
    cookie_flags = {
        "secure": "secure" in cookies.lower() if cookies else None,
        "httponly": "httponly" in cookies.lower() if cookies else None,
        "samesite": "samesite" in cookies.lower() if cookies else None,
    }
    return {
        "server": hdrs.get("server", "?"),
        "missing_headers": [h for h in wanted if h not in hdrs],
        "headers": {h: hdrs.get(h) for h in wanted if h in hdrs},
        "set_cookie_flags": cookie_flags,
    }

def scan(host):
    try: ip = socket.gethostbyname(host)
    except socket.gaierror as e: return {"error": str(e)}

    r = {"host": host, "ip": ip, "scanned_at": datetime.utcnow().isoformat()+"Z",
         "open_ports": [], "ssl": None, "http_headers": None, "findings": []}

    open_ports = scan_ports(host)
    r["open_ports"] = [{"port": p, "service": NAMES.get(p,"unknown")} for p in open_ports]
    for p, (sev, msg) in RISKY.items():
        if p in open_ports: r["findings"].append({"severity": sev, "issue": msg})

    if 443 in open_ports:
        r["ssl"] = check_ssl(host)
        if r["ssl"].get("expiring_soon"):
            r["findings"].append({"severity":"MEDIUM","issue":f"SSL cert expires in {r['ssl']['days_remaining']} days"})
        if r["ssl"].get("valid") is False:
            r["findings"].append({"severity":"HIGH","issue":"SSL cert invalid/untrusted"})

    for port, tls in [(443,True),(80,False),(8443,True),(8080,False)]:
        if port in open_ports:
            r["http_headers"] = check_headers(host, port, tls)
            miss = r["http_headers"].get("missing_headers",[])
            if miss: r["findings"].append({"severity":"LOW","issue":f"Missing headers: {', '.join(miss)}"})
            break
    return r

active_scan = scan

def passive_scan(domain: str) -> dict:
    """Authorization-gated passive scan: DNS, SSL cert, one HTTPS GET for headers."""
    host = domain.strip().lower().removeprefix("https://").removeprefix("http://")
    host = host.split("/", 1)[0].split(":", 1)[0].strip(".")
    r = {
        "host": host,
        "scan_type": "passive",
        "ip": "?",
        "ips": [],
        "scanned_at": datetime.utcnow().isoformat()+"Z",
        "open_ports": [],
        "ssl": None,
        "http_headers": None,
        "findings": [],
    }
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in infos})
        r["ips"] = ips
        r["ip"] = ips[0] if ips else "?"
    except socket.gaierror as e:
        r["findings"].append({"severity":"HIGH","issue":f"DNS lookup failed: {e}"})
        return r

    r["ssl"] = passive_ssl(host)
    if r["ssl"].get("expiring_soon"):
        r["findings"].append({"severity":"MEDIUM","issue":f"SSL cert expires in {r['ssl']['days_remaining']} days"})
    if r["ssl"].get("valid") is False:
        r["findings"].append({"severity":"HIGH","issue":"SSL cert invalid/untrusted"})
    if r["ssl"].get("valid") is None:
        r["findings"].append({"severity":"LOW","issue":f"SSL check error: {r['ssl'].get('error','unknown')}"})

    r["http_headers"] = passive_headers(host)
    if r["http_headers"].get("error"):
        r["findings"].append({"severity":"LOW","issue":f"HTTPS header check error: {r['http_headers']['error']}"})
    else:
        missing = r["http_headers"].get("missing_headers", [])
        if missing:
            r["findings"].append({"severity":"LOW","issue":f"Missing headers: {', '.join(missing)}"})
        flags = r["http_headers"].get("set_cookie_flags") or {}
        if flags.get("secure") is False:
            r["findings"].append({"severity":"MEDIUM","issue":"Set-Cookie missing Secure flag"})
        if flags.get("httponly") is False:
            r["findings"].append({"severity":"LOW","issue":"Set-Cookie missing HttpOnly flag"})
        if flags.get("samesite") is False:
            r["findings"].append({"severity":"LOW","issue":"Set-Cookie missing SameSite flag"})

    # requires: paid_authorized_scan — injection probes, traversal requests, auth bypass checks.
    return r

def summary(r):
    if "error" in r: print(f"ERROR: {r['error']}"); return
    sep = "="*50
    print(f"\n{sep}\n  Scan: {r['host']} ({r['ip']})\n{sep}")
    ports = r["open_ports"]
    print(f"\nOpen ports ({len(ports)}):")
    for p in ports: print(f"  {p['port']:5d}  {p['service']}")
    if not ports: print("  none")
    if r["ssl"]:
        st = "VALID" if r["ssl"].get("valid") else ("INVALID" if r["ssl"].get("valid") is False else "ERROR")
        print(f"\nSSL (443): {st}", end="")
        if r["ssl"].get("expires"):
            flag = "  *** EXPIRING SOON ***" if r["ssl"].get("expiring_soon") else ""
            print(f"  |  expires {r['ssl']['expires']} ({r['ssl']['days_remaining']}d){flag}", end="")
        print()
    findings = r["findings"]
    print(f"\nFindings ({len(findings)}):")
    for f in findings: print(f"  [{f['severity']:6s}] {f['issue']}")
    if not findings: print("  none")
    print()

if __name__ == "__main__":
    if len(sys.argv) != 2: print("Usage: python scanner.py <host>", file=sys.stderr); sys.exit(1)
    import report_generator
    host = sys.argv[1]
    result = scan(host)
    summary(result)
    print(json.dumps(result, indent=2))
    os.makedirs("reports", exist_ok=True)
    date = datetime.utcnow().strftime("%Y-%m-%d")
    fname = f"reports/{host}_{date}.html"
    with open(fname, "w") as fh: fh.write(report_generator.generate(result))
    print(f"Report saved: {fname}")
