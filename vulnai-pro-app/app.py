#!/usr/bin/env python3
"""
VulnAI Pro - BEAST Edition v3.0  (Final)
Enterprise-Grade PASSIVE OSINT Intelligence Platform

LEGAL: Only scan systems you own or have explicit written permission to test.
"""

from flask import Flask, request, jsonify, render_template_string
import time, socket, ssl, json, re
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

app = Flask(__name__)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
UA         = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
CONNECT_TO = 1.2
API_TO     = 10
DOMAIN_RE  = re.compile(r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")

# ─── OPTIONAL API KEYS ────────────────────────────────────────────────────────
# These are used server-side only — users never see them.
# Add your keys here to unlock Shodan, Hunter.io, and VirusTotal modules.
# Get Shodan:     https://account.shodan.io/
# Get Hunter.io:  https://hunter.io/api-keys
# Get VirusTotal: https://www.virustotal.com/gui/my-apikey
SHODAN_KEY     = ""
HUNTER_KEY     = ""
VIRUSTOTAL_KEY = ""

def valid_domain(d: str) -> bool:
    return bool(DOMAIN_RE.match(d.strip()))

# ─── URL CLEANER ──────────────────────────────────────────────────────────────
def clean_urls(urls):
    """Remove junk: base64 blobs, tracking spam, overly long URLs."""
    junk_patterns = [
        "data:image", "%22", "base64,", "iVBORw0KGgo",
        "gclid=", "gclsrc=", "fbclid=", "msclkid=",
        "utm_source=", "utm_medium=", "irclickid=",
        "associateid=", "campaign_id=", "adgroupid=",
    ]
    result = []
    seen = set()
    for u in urls:
        if len(u) > 180:
            continue
        if any(p in u for p in junk_patterns):
            continue
        if u in seen:
            continue
        seen.add(u)
        result.append(u)
    return result[:12]

# ─── WHOIS ────────────────────────────────────────────────────────────────────
def get_whois(domain):
    if not WHOIS_OK:
        return {"note": "python-whois not installed"}
    try:
        w = whois_lib.whois(domain)
        def safe(v):
            if v is None: return "Not disclosed"
            if isinstance(v, list): v = v[0]
            try:   return str(v.date()) if hasattr(v, 'date') else str(v)
            except: return str(v)
        ns = list(getattr(w, 'name_servers', []) or [])
        return {
            "registrar":    safe(getattr(w, 'registrar', None)),
            "organization": safe(getattr(w, 'org', None)),
            "created":      safe(getattr(w, 'creation_date', None)),
            "expires":      safe(getattr(w, 'expiration_date', None)),
            "name_servers": [str(n).lower() for n in ns[:4]],
        }
    except Exception:
        return {"note": "WHOIS protected or rate-limited by registry"}

# ─── DNS ──────────────────────────────────────────────────────────────────────
def get_dns(domain):
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [r.to_text() for r in ans]
        except:
            records[rtype] = []
    txt = " ".join(records.get('TXT', []))
    records['_email_security'] = {
        "SPF":   "Found ✓" if "v=spf1"   in txt else "Not found",
        "DMARC": "Found ✓" if "v=DMARC1" in txt else "Not found",
        "DKIM":  "Found ✓" if "v=DKIM1"  in txt else "Not found",
    }
    return records

# ─── SUBDOMAINS ───────────────────────────────────────────────────────────────
def subs_crtsh(domain):
    found = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         headers={"User-Agent": UA}, timeout=API_TO)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value","").split('\n'):
                    name = name.strip().lower()
                    if name and '*' not in name and domain in name:
                        found.add(name)
    except: pass
    return list(found)

def subs_hackertarget(domain):
    found = []
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         headers={"User-Agent": UA}, timeout=API_TO)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split('\n'):
                if ',' in line and domain in line:
                    parts = line.split(',')
                    found.append({"subdomain": parts[0].strip(), "ip": parts[1].strip()})
    except: pass
    return found

def subs_rapiddns(domain):
    found = set()
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1#result",
                         headers={"User-Agent": UA}, timeout=API_TO)
        if r.status_code == 200:
            for m in re.findall(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', r.text):
                found.add(m.lower())
    except: pass
    return list(found)

def subs_bruteforce(domain):
    wordlist = [
        'www','mail','ftp','admin','api','dev','staging','test','beta','demo',
        'shop','store','blog','forum','wiki','docs','support','help','status',
        'cdn','static','assets','media','secure','portal','app','mobile',
        'vpn','remote','webmail','smtp','ns1','ns2','mx','auth','login',
        'dashboard','panel','cp','cpanel','autodiscover','chat','news','backup'
    ]
    found = []
    def chk(sub):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return {"subdomain": full, "ip": ip}
        except: return None
    with ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(chk, wordlist):
            if res: found.append(res)
    return found

# ─── CERTIFICATES ─────────────────────────────────────────────────────────────
def get_certs(domain):
    certs, seen = [], set()
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json",
                         headers={"User-Agent": UA}, timeout=API_TO)
        if r.status_code == 200:
            for c in r.json()[:40]:
                cid = c.get('id')
                if cid in seen: continue
                seen.add(cid)
                certs.append({
                    "id":          cid,
                    "issuer":      c.get('issuer_name','?')[:80],
                    "subject":     c.get('name_value','?')[:80],
                    "valid_from":  c.get('not_before','?'),
                    "valid_until": c.get('not_after','?'),
                })
    except: pass
    return certs

# ─── WAYBACK MACHINE ──────────────────────────────────────────────────────────
def get_wayback(domain):
    try:
        r = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&collapse=urlkey&output=json&limit=400&fl=original,timestamp",
            headers={"User-Agent": UA}, timeout=18)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:
                rows  = data[1:]
                raw   = [row[0] for row in rows]
                tss   = [row[1] for row in rows if len(row) > 1]
                # Strip all image/asset junk
                asset_ext = ('.jpg','.jpeg','.png','.gif','.css','.svg',
                             '.ico','.woff','.woff2','.ttf','.eot','.mp4',
                             '.mp3','.webp','.bmp','.tiff','.zip','.gz')
                clean = [u for u in raw if not any(u.lower().endswith(x) for x in asset_ext)]
                # Then apply URL cleaner to remove tracking/base64 noise
                clean = clean_urls(clean)
                admin_kw = ['admin','login','signin','dashboard','panel','auth','portal','cp/']
                api_kw   = ['/api/','/rest/','/graphql','/v1/','/v2/','/json','/xml']
                file_ext = ['.php','.asp','.aspx','.jsp','.sql','.env','.bak','.conf','.log','.xml','.json']
                def fmt(ts):
                    try: return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                    except: return ts
                admin_u = clean_urls([u for u in [row[0] for row in rows] if any(k in u.lower() for k in admin_kw)])
                api_u   = clean_urls([u for u in [row[0] for row in rows] if any(k in u.lower() for k in api_kw)])
                file_u  = clean_urls([u for u in [row[0] for row in rows] if any(u.lower().endswith(x) for x in file_ext)])
                return {
                    "total_snapshots": len(raw),
                    "unique_urls":     len(set(raw)),
                    "first_capture":   fmt(min(tss)) if tss else "Unknown",
                    "last_capture":    fmt(max(tss)) if tss else "Unknown",
                    "admin_urls":      admin_u[:8],
                    "api_urls":        api_u[:8],
                    "file_urls":       file_u[:8],
                    "sample_urls":     clean[:12],
                }
    except: pass
    return {
        "total_snapshots": 0,
        "unique_urls": 0,
        "note": "No archived data found — target may block Wayback crawlers or domain is new"
    }

# ─── TLS ──────────────────────────────────────────────────────────────────────
def get_tls(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                issuer  = dict(x[0] for x in cert.get("issuer",[])).get("commonName","?")
                subject = dict(x[0] for x in cert.get("subject",[])).get("commonName","?")
                return {
                    "tls_version": s.version(),
                    "cipher":      s.cipher()[0],
                    "issuer":      issuer,
                    "subject":     subject,
                    "valid_from":  cert.get("notBefore","?"),
                    "valid_until": cert.get("notAfter","?"),
                }
    except Exception as e:
        return {"error": str(e)}

# ─── WEB HEADERS + FINDINGS ───────────────────────────────────────────────────
def get_web(domain):
    findings, raw_headers = [], {}
    meta = {"status":0,"server":"Unknown","waf":"None detected",
            "scheme":"https","title":"—","technologies":[]}
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}",
                             headers={"User-Agent": UA}, timeout=8, allow_redirects=True)
            meta["status"] = r.status_code
            meta["server"] = r.headers.get("Server","Not disclosed")
            meta["scheme"] = scheme
            raw_headers    = dict(r.headers)
            tm = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I|re.S)
            meta["title"] = tm.group(1).strip()[:80] if tm else "No title"
            h    = json.dumps(dict(r.headers)).lower()
            body = r.text.lower()
            waf_map = [
                (["cf-ray","__cfduid","cloudflare"],        "Cloudflare"),
                (["x-amz-cf-id","awselb","awsalb"],         "AWS CloudFront/ELB"),
                (["akamai-origin-hop"],                     "Akamai"),
                (["x-sucuri-id","sucuri"],                  "Sucuri"),
                (["incap_ses","visid_incap"],                "Imperva Incapsula"),
                (["x-fastly","fastly-io"],                  "Fastly"),
                (["fortigate","forticdn"],                  "FortiGate WAF"),
            ]
            for sigs, name in waf_map:
                if any(s in h for s in sigs):
                    meta["waf"] = name; break
            techs = []
            tmap = {
                "WordPress":["wp-content","wp-includes"],
                "Drupal":["/sites/default/files","drupal.js"],
                "Joomla":["/templates/system/"],
                "Shopify":["myshopify.com"],
                "React":["react.production"],
                "Next.js":["__next","_next/static"],
                "Vue.js":["vue.min.js","__vue__"],
                "Angular":["ng-version"],
                "jQuery":["jquery.min.js"],
                "Bootstrap":["bootstrap.min.css"],
                "Laravel":["laravel_session"],
                "Django":["csrfmiddlewaretoken"],
                "ASP.NET":["__viewstate"],
            }
            for tech, pats in tmap.items():
                if any(p in body for p in pats):
                    techs.append(tech)
            ph = r.headers.get("X-Powered-By","")
            if ph and ph not in techs: techs.append(ph)
            meta["technologies"] = techs
            break
        except: continue

    hdr_checks = [
        ("Content-Security-Policy",      "HIGH",   "XSS & Content Injection"),
        ("Strict-Transport-Security",    "MEDIUM", "Protocol Downgrade / MITM"),
        ("X-Frame-Options",             "MEDIUM", "Clickjacking"),
        ("X-Content-Type-Options",      "LOW",    "MIME Sniffing"),
        ("Referrer-Policy",             "LOW",    "Referrer Data Leakage"),
        ("Permissions-Policy",          "LOW",    "Browser Feature Abuse"),
        ("Cross-Origin-Opener-Policy",  "LOW",    "Cross-Origin Attacks"),
        ("Cross-Origin-Resource-Policy","LOW",    "Data Cross-Origin Leakage"),
    ]
    for hdr, sev, risk in hdr_checks:
        if raw_headers and hdr not in raw_headers:
            findings.append({"severity":sev,"title":f"Missing {hdr}","risk":risk,"fix":f"Add {hdr} response header"})
    if raw_headers.get("X-Powered-By"):
        findings.append({"severity":"MEDIUM","title":"Technology Disclosure",
                         "risk":f'X-Powered-By reveals backend: {raw_headers["X-Powered-By"]}',
                         "fix":"Remove or obfuscate X-Powered-By header"})
    srv = raw_headers.get("Server","")
    if srv and srv not in ("","Unknown","Not disclosed"):
        findings.append({"severity":"LOW","title":"Server Banner Exposed",
                         "risk":f"Server header reveals: {srv}","fix":"Remove or genericize Server header"})
    return {"meta":meta,"findings":findings,"raw_headers":raw_headers}

# ─── PORT SCAN ────────────────────────────────────────────────────────────────
PORT_LABELS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",135:"RPC",143:"IMAP",443:"HTTPS",445:"SMB",
    993:"IMAPS",995:"POP3S",1433:"MSSQL",3306:"MySQL",3389:"RDP",
    5432:"PostgreSQL",5900:"VNC",8080:"HTTP-Alt",8443:"HTTPS-Alt",
    8888:"HTTP-Alt2",9200:"Elasticsearch",27017:"MongoDB"
}
def port_scan(domain):
    open_ports = []
    def chk(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CONNECT_TO)
                s.connect((domain, port))
                return port
        except: return None
    with ThreadPoolExecutor(max_workers=len(PORT_LABELS)) as ex:
        for r in ex.map(chk, PORT_LABELS.keys()):
            if r: open_ports.append(r)
    return sorted(open_ports)

# ─── IP GEOLOCATION ───────────────────────────────────────────────────────────
def get_geo(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,hosting",
            timeout=6)
        if r.status_code == 200:
            d = r.json()
            d["is_cdn"] = d.get("hosting", False)
            return d
    except: pass
    return {}

# ─── ALIENVAULT OTX ───────────────────────────────────────────────────────────
def get_alienvault(domain):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"User-Agent": UA}, timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {
                "pulse_count":   d.get("pulse_info",{}).get("count",0),
                "reputation":    d.get("reputation",0),
                "malware_count": len(d.get("malware",[])),
                "country":       d.get("country_name","Unknown"),
            }
    except: pass
    return {}

# ─── VIRUSTOTAL ───────────────────────────────────────────────────────────────
def get_virustotal(domain):
    if not VIRUSTOTAL_KEY:
        return {"disabled": True}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY, "User-Agent": UA}, timeout=8)
        if r.status_code == 200:
            d = r.json().get("data",{}).get("attributes",{})
            stats = d.get("last_analysis_stats",{})
            return {
                "malicious":  stats.get("malicious",0),
                "suspicious": stats.get("suspicious",0),
                "harmless":   stats.get("harmless",0),
                "reputation": d.get("reputation",0),
            }
    except: pass
    return {}

# ─── SHODAN ───────────────────────────────────────────────────────────────────
def get_shodan(ip):
    if not SHODAN_KEY:
        return {"disabled": True}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {
                "org":       d.get("org","?"),
                "isp":       d.get("isp","?"),
                "ports":     d.get("ports",[]),
                "country":   d.get("country_name","?"),
                "hostnames": d.get("hostnames",[]),
                "vulns":     list(d.get("vulns",{}).keys())[:10],
                "os":        d.get("os","Unknown"),
            }
    except: pass
    return {}

# ─── HUNTER.IO ────────────────────────────────────────────────────────────────
def get_hunter(domain):
    if not HUNTER_KEY:
        return {"disabled": True}
    try:
        r = requests.get(
            f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_KEY}",
            timeout=8)
        if r.status_code == 200:
            data = r.json().get("data",{})
            return {
                "total":   data.get("total",0),
                "pattern": data.get("pattern","?"),
                "emails":  [e.get("value") for e in data.get("emails",[])[:15]],
            }
    except: pass
    return {}

# ─── LEAKIX ───────────────────────────────────────────────────────────────────
def get_leakix(domain):
    try:
        r = requests.get(
            f"https://leakix.net/api/domains?domain={domain}",
            headers={"User-Agent": UA, "Accept": "application/json"}, timeout=8)
        if r.status_code == 200:
            return r.json()
    except: pass
    return {"note": "No data or rate limited"}

# ─── GOOGLE DORKS ─────────────────────────────────────────────────────────────
def gen_dorks(domain):
    return [
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:xlsx OR filetype:csv",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login OR inurl:signin",
        f"site:{domain} intitle:\"index of\"",
        f"site:{domain} ext:sql OR ext:dbf OR ext:mdb",
        f"site:{domain} ext:env OR ext:bak OR ext:conf OR ext:log",
        f"site:{domain} inurl:config OR inurl:setup",
        f"site:{domain} inurl:wp-content OR inurl:wp-admin",
        f"site:pastebin.com \"{domain}\"",
        f"site:github.com \"{domain}\" password OR secret OR api_key",
        f"\"{domain}\" email filetype:xlsx OR filetype:csv",
        f"site:linkedin.com \"{domain}\"",
        f"site:trello.com \"{domain}\"",
    ]

# ─── RISK SCORING ─────────────────────────────────────────────────────────────
def calc_risk(findings, ports, subdomains, wayback, alienvault, virustotal):
    score = 0
    breakdown = []
    for f in findings:
        pts = {"HIGH":8,"MEDIUM":4,"LOW":1}.get(f["severity"],0)
        score += pts
        if pts >= 4:
            breakdown.append(f"Header [{f['severity']}]: {f['title']}")
    risky = [p for p in ports if p not in [80,443]]
    if risky:
        score += len(risky) * 5
        breakdown.append(f"Risky open ports: {risky}")
    if 22 in ports:   breakdown.append("SSH exposed on port 22")
    if 3389 in ports: breakdown.append("RDP exposed — HIGH RISK")
    if any(p in ports for p in [3306,5432,27017]):
        breakdown.append("Database port(s) exposed")
    if len(subdomains) > 15:
        score += 5; breakdown.append(f"Large perimeter: {len(subdomains)} subdomains")
    elif len(subdomains) > 5:
        score += 2
    pulses = alienvault.get("pulse_count",0)
    if pulses > 0:
        score += min(pulses*3, 20)
        breakdown.append(f"AlienVault: {pulses} threat pulse(s)")
    if isinstance(virustotal, dict) and virustotal.get("malicious",0) > 0:
        score += virustotal["malicious"] * 5
        breakdown.append(f"VirusTotal: {virustotal['malicious']} malicious detections")
    if isinstance(wayback, dict) and wayback.get("admin_urls"):
        score += 5; breakdown.append("Admin/login URLs in Wayback archive")

    if score >= 30:   lvl, col = "CRITICAL ⚠️", "#ef4444"
    elif score >= 15: lvl, col = "HIGH 🔴",      "#f97316"
    elif score >= 8:  lvl, col = "MEDIUM 🟠",    "#eab308"
    else:             lvl, col = "LOW 🟢",        "#22c55e"
    return {"level":lvl,"color":col,"score":score,"breakdown":breakdown[:8]}

# ─── AI INSIGHT ───────────────────────────────────────────────────────────────
def ai_insight(risk, findings, ports, subdomains, waf, technologies):
    lvl      = risk["level"]
    high_n   = sum(1 for f in findings if f["severity"]=="HIGH")
    risky_p  = [p for p in ports if p not in [80,443]]
    has_waf  = waf not in ("None detected","")

    if "CRITICAL" in lvl:
        summary = ("The target exposes a CRITICAL attack surface. Multiple high-severity "
                   "misconfigurations were detected alongside exposed sensitive services. "
                   "Threat actors could leverage these weaknesses for reconnaissance, "
                   "credential harvesting, or service exploitation. Immediate remediation required.")
    elif "HIGH" in lvl:
        summary = ("The target exposes a moderate-to-high attack surface due to missing "
                   "security headers and publicly accessible services. "
                   + (f"WAF ({waf}) provides partial perimeter protection, however " if has_waf else "No WAF/CDN detected — ")
                   + "misconfigurations may still allow client-side attacks such as XSS "
                   "or sensitive data exposure via header leakage. "
                   "Security hardening is strongly recommended.")
    elif "MEDIUM" in lvl:
        summary = ("The target presents a moderate exposure due to configuration gaps. "
                   + (f"A WAF ({waf}) is active, reducing direct attack surface. " if has_waf else "No WAF/CDN detected. ")
                   + "Missing security policies may still allow cross-site scripting, "
                   "referrer leakage, or clickjacking under certain conditions. "
                   "Prioritize implementing missing headers and email security records.")
    else:
        summary = ("The target demonstrates a LOW risk posture with reasonable security controls. "
                   + (f"WAF ({waf}) is active. " if has_waf else "")
                   + "Remaining low-severity findings should be addressed as part of "
                   "routine hardening to achieve a comprehensive security baseline.")

    recs = []
    if high_n:              recs.append("Implement Content-Security-Policy and HSTS immediately")
    if risky_p:             recs.append(f"Firewall or restrict non-web ports: {risky_p}")
    if len(subdomains)>10:  recs.append("Audit subdomain inventory — wide perimeter increases attack surface")
    if not has_waf:         recs.append("Deploy a WAF/CDN to filter malicious traffic at the edge")
    if technologies:        recs.append(f"Keep {', '.join(technologies[:3])} components patched against CVEs")
    recs.append("Implement DMARC, SPF and DKIM to prevent email spoofing attacks")
    return {"summary":summary,"recommendations":recs[:5]}

# ─── ATTACK SURFACE ───────────────────────────────────────────────────────────
def build_surface(ports, findings, subdomains, waf, technologies, wayback):
    surface = []
    if 80 in ports or 443 in ports:
        surface.append("🌐 Public web services exposed (HTTP/HTTPS)")
    risky = [p for p in ports if p not in [80,443]]
    if risky:
        labels = ', '.join(f"{p} ({PORT_LABELS.get(p,'?')})" for p in risky)
        surface.append(f"🚨 Sensitive ports open: {labels}")
    if any(p in ports for p in [3306,5432,27017]):
        surface.append("🗄️ Database port(s) exposed — CRITICAL priority")
    if 22 in ports:   surface.append("🔑 SSH accessible (port 22)")
    if 3389 in ports: surface.append("🖥️ RDP exposed (port 3389) — HIGH RISK")
    if any(f["severity"]=="HIGH" for f in findings):
        surface.append("⚠️ High-risk security header missing — XSS/injection exposure")
    if any(f["severity"]=="MEDIUM" for f in findings):
        surface.append("🛡️ Medium-risk misconfiguration(s) detected")
    if any("Server" in f["title"] for f in findings):
        surface.append("🕵️ Server fingerprint leakage via banner")
    if len(subdomains)>10:
        surface.append(f"📡 Wide perimeter: {len(subdomains)} subdomains identified")
    elif subdomains:
        surface.append(f"📡 {len(subdomains)} subdomain(s) in scope")
    wb = wayback if isinstance(wayback, dict) else {}
    if wb.get("admin_urls"):
        surface.append(f"📜 {len(wb['admin_urls'])} admin/login URL(s) archived in Wayback")
    if technologies:
        surface.append(f"🔧 Detected stack: {', '.join(technologies[:4])}")
    if waf == "None detected":
        surface.append("⚡ No WAF/CDN detected — direct server exposure")
    else:
        surface.append(f"✅ WAF/CDN active: {waf}")
    return surface

# ─── KALI COMMANDS (shown only when API key is missing) ───────────────────────
KALI_COMMANDS = {
    "shodan": {
        "title": "Shodan CLI (Kali Linux)",
        "install": "pip install shodan",
        "commands": [
            "shodan init YOUR_API_KEY",
            "shodan host TARGET_IP",
            "shodan search 'hostname:TARGET_DOMAIN'",
            "shodan count 'org:TARGET_ORG'",
        ]
    },
    "hunter": {
        "title": "Hunter.io via curl (Kali Linux)",
        "install": "# No install needed — use curl",
        "commands": [
            "curl 'https://api.hunter.io/v2/domain-search?domain=TARGET&api_key=YOUR_KEY'",
            "curl 'https://api.hunter.io/v2/email-count?domain=TARGET&api_key=YOUR_KEY'",
        ]
    },
    "virustotal": {
        "title": "VirusTotal via curl (Kali Linux)",
        "install": "# No install needed — use curl",
        "commands": [
            "curl -H 'x-apikey: YOUR_KEY' 'https://www.virustotal.com/api/v3/domains/TARGET'",
        ]
    }
}

# ─── MAIN ORCHESTRATOR ────────────────────────────────────────────────────────
def full_scan(domain):
    t0 = time.time()
    try:    ip = socket.gethostbyname(domain)
    except: ip = "Unresolvable"

    with ThreadPoolExecutor(max_workers=16) as ex:
        fw   = ex.submit(get_whois, domain)
        fd   = ex.submit(get_dns, domain)
        fcs  = ex.submit(subs_crtsh, domain)
        fht  = ex.submit(subs_hackertarget, domain)
        frp  = ex.submit(subs_rapiddns, domain)
        fbr  = ex.submit(subs_bruteforce, domain)
        fcer = ex.submit(get_certs, domain)
        fwb  = ex.submit(get_wayback, domain)
        ftls = ex.submit(get_tls, domain)
        fweb = ex.submit(get_web, domain)
        fpo  = ex.submit(port_scan, domain)
        fgeo = ex.submit(get_geo, ip)
        fav  = ex.submit(get_alienvault, domain)
        flk  = ex.submit(get_leakix, domain)
        fvt  = ex.submit(get_virustotal, domain)
        fsh  = ex.submit(get_shodan, ip)
        fhu  = ex.submit(get_hunter, domain)

        whois_d = fw.result()
        dns_d   = fd.result()
        crt_s   = fcs.result()
        ht_s    = fht.result()
        rp_s    = frp.result()
        br_s    = fbr.result()
        certs   = fcer.result()
        wayback = fwb.result()
        tls     = ftls.result()
        web     = fweb.result()
        ports   = fpo.result()
        geo     = fgeo.result()
        av      = fav.result()
        leakix  = flk.result()
        vt      = fvt.result()
        shodan  = fsh.result()
        hunter  = fhu.result()

    all_subs_set = set(crt_s + rp_s)
    for s in ht_s: all_subs_set.add(s["subdomain"])
    for s in br_s: all_subs_set.add(s["subdomain"])
    all_subs = sorted(list(all_subs_set))

    findings = web["findings"]
    meta     = web["meta"]
    techs    = meta.get("technologies",[])
    waf      = meta.get("waf","None detected")

    risk    = calc_risk(findings, ports, all_subs, wayback, av, vt)
    insight = ai_insight(risk, findings, ports, all_subs, waf, techs)
    surface = build_surface(ports, findings, all_subs, waf, techs, wayback)
    dorks   = gen_dorks(domain)

    return {
        "target":      domain,
        "ip":          ip,
        "scan_time":   round(time.time()-t0, 1),
        "timestamp":   datetime.now().isoformat(),
        "risk":        risk,
        "ai_insight":  insight,
        "attack_surface": surface,
        "web_meta":    meta,
        "tls":         tls,
        "open_ports":  ports,
        "port_labels": PORT_LABELS,
        "geo":         geo,
        "whois":       whois_d,
        "dns":         dns_d,
        "subdomains":  all_subs[:30],
        "subdomain_sources": {
            "certificate_transparency": len(crt_s),
            "hackertarget_api":         len(ht_s),
            "rapiddns":                 len(rp_s),
            "dns_bruteforce":           len(br_s),
        },
        "subdomain_with_ip": (ht_s+br_s)[:15],
        "certificates": certs,
        "wayback":     wayback,
        "google_dorks": dorks,
        "alienvault":  av,
        "virustotal":  vt,
        "shodan":      shodan,
        "hunter":      hunter,
        "leakix":      leakix,
        "findings":    findings,
        "kali_commands": KALI_COMMANDS,
        "api_status": {
            "shodan":     "active" if SHODAN_KEY else "no_key",
            "hunter":     "active" if HUNTER_KEY else "no_key",
            "virustotal": "active" if VIRUSTOTAL_KEY else "no_key",
        }
    }

# ─── HTML ─────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnAI Pro — Beast Edition</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#030308;color:#c4c4cc;font-family:'JetBrains Mono',monospace}
.box{background:#0c0c14;border:1px solid #16162a;border-radius:6px}
.glow{box-shadow:0 0 24px rgba(0,255,157,.1)}
.sl{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:#32325a;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid #16162a}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:999px;font-size:.64rem;font-weight:700}
.bH{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}
.bM{background:#431407;color:#fdba74;border:1px solid #7c2d12}
.bL{background:#052e16;color:#86efac;border:1px solid #14532d}
.bI{background:#0c1a3d;color:#93c5fd;border:1px solid #1e3a8a}
.tag{display:inline-block;background:#111827;border:1px solid #1f2937;padding:2px 7px;border-radius:4px;font-size:.64rem;margin:2px}
.pb{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:4px;font-size:.72rem;font-weight:700;margin:3px;border:1px solid}
.ps{background:#0a1f0a;color:#86efac;border-color:#166534}
.pr{background:#1f0a0a;color:#fca5a5;border-color:#7f1d1d}
.fi{border-left:3px solid #1a1a30;padding:10px 14px;margin-bottom:7px;border-radius:0 4px 4px 0;background:#0c0c14}
.fH{border-color:#ef4444}.fM{border-color:#f97316}.fL{border-color:#22c55e}
.sub-i{background:#0c0c14;border:1px solid #16162a;border-radius:4px;padding:6px 12px;font-size:.7rem;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.dork{font-size:.7rem;padding:6px 0;border-bottom:1px solid #0d0d16;display:flex;gap:8px;align-items:flex-start}
.dork a{color:#00ff9d;text-decoration:none;word-break:break-all}
.dork a:hover{text-decoration:underline}
.kali-box{background:#000;border:1px solid #00ff9d22;border-radius:6px;padding:14px;font-size:.7rem}
.kali-cmd{color:#00ff9d;display:block;margin:4px 0;padding:3px 8px;background:#0a0a0a;border-radius:3px}
.kali-install{color:#fbbf24;font-size:.65rem;margin-bottom:8px;display:block}
.url-item{font-size:.68rem;padding:4px 0;border-bottom:1px solid #0d0d16;word-break:break-all}
.url-item a{text-decoration:none}
.url-item a:hover{text-decoration:underline}
.sb{max-height:200px;overflow-y:auto}
input[type=text]{background:#000;color:#00ff9d;border:1px solid #00ff9d33;border-radius:4px;padding:10px 14px;font-family:'JetBrains Mono',monospace;font-size:.95rem;width:100%;transition:border-color .2s}
input[type=text]:focus{outline:none;border-color:#00ff9d;box-shadow:0 0 0 2px rgba(0,255,157,.12)}
input[type=text]::placeholder{color:#1a3a2a}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#080808}::-webkit-scrollbar-thumb{background:#00ff9d1a;border-radius:99px}
/* Loading */
#lo{position:fixed;inset:0;background:#000;z-index:9999;display:none;flex-direction:column;align-items:center;justify-content:center}
.mx{position:absolute;inset:0;overflow:hidden;opacity:.04;font-size:.55rem;line-height:1.3;color:#00ff9d;word-break:break-all;pointer-events:none}
.orb{width:100px;height:100px;border-radius:50%;border:2px solid #00ff9d22;position:relative;margin-bottom:24px}
.orb-ring{position:absolute;inset:0;border-radius:50%;border:2px solid #00ff9d;animation:spin 2.5s linear infinite;border-bottom-color:transparent;border-left-color:transparent}
.orb-ring2{position:absolute;inset:10px;border-radius:50%;border:1px dashed #00ff9d33;animation:spin 1.8s linear infinite reverse}
.orb-core{position:absolute;inset:22px;border-radius:50%;background:radial-gradient(#00ff9d22,transparent)}
@keyframes spin{to{transform:rotate(360deg)}}
.pbw{width:260px;background:#0a0a0a;border:1px solid #00ff9d15;border-radius:99px;overflow:hidden;height:4px;margin-top:16px}
.pbf{height:100%;background:linear-gradient(90deg,#00ff9d,#00c3ff);border-radius:99px;transition:width .5s ease;width:0%}
.stxt{color:#00ff9d66;font-size:.7rem;margin-top:10px;text-align:center;min-height:16px}
/* Terminal */
.tbar{background:#0a0a0a;padding:8px 14px;display:flex;align-items:center;gap:7px;border-bottom:1px solid #111}
.dot{width:11px;height:11px;border-radius:50%}
#to{height:240px;overflow-y:auto;padding:12px;font-size:.72rem;line-height:1.8}
.lg{color:#00ff9d}.lb{color:#60a5fa}.ly{color:#fbbf24}.lr{color:#f87171}
@keyframes blink{50%{opacity:0}}
.blink{animation:blink 1s step-start infinite}
</style>
</head>
<body class="p-4 md:p-8">

<!-- LOADING -->
<div id="lo">
  <div class="mx" id="mx"></div>
  <div class="orb">
    <div class="orb-ring"></div>
    <div class="orb-ring2"></div>
    <div class="orb-core"></div>
  </div>
  <div style="color:#00ff9d;font-size:1.2rem;font-weight:900;letter-spacing:.25em">BEAST SCAN</div>
  <div style="color:#1a2a1a;font-size:.65rem;margin-top:3px;letter-spacing:.12em">PASSIVE OSINT ENGINE v3.0</div>
  <div class="pbw"><div class="pbf" id="pbf"></div></div>
  <div class="stxt" id="stxt">Initializing...</div>
</div>

<div class="max-w-6xl mx-auto">

<!-- HEADER -->
<div class="text-center mb-7">
  <div style="font-size:2.8rem;font-weight:900;color:#00ff9d;letter-spacing:.06em;text-shadow:0 0 40px rgba(0,255,157,.3)">VulnAI Pro</div>
  <div style="color:#fbbf24;font-weight:700;letter-spacing:.2em;font-size:.95rem;margin-top:2px">🦾 BEAST EDITION v3.0</div>
  <div style="display:flex;justify-content:center;gap:18px;margin-top:8px;font-size:.6rem;color:#1e2e2e">
    <span>◈ PASSIVE OSINT</span><span>◈ 17 SOURCES</span><span>◈ AI RISK ENGINE</span><span>◈ THREAT INTEL</span>
  </div>
</div>

<!-- LEGAL -->
<div class="box p-4 mb-5" style="border-color:#2a1500;background:#060400">
  <div style="color:#fbbf24;font-weight:700;font-size:.78rem">⚠ AUTHORIZED USE ONLY</div>
  <div style="color:#4a3a10;font-size:.66rem;margin-top:3px">Passive OSINT via public APIs only. No exploits. No active attacks. Only scan targets you own or have written authorization to test.</div>
</div>

<!-- FORM -->
<div class="box p-6 mb-5 glow">
  <form id="sf">
    <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
      <input type="text" id="dm" placeholder="target.com — no https://" required style="flex:1;min-width:200px">
      <button type="submit" id="sb" style="background:#00ff9d;color:#000;font-family:'JetBrains Mono',monospace;font-weight:900;padding:10px 22px;border:none;border-radius:4px;cursor:pointer;font-size:.88rem;white-space:nowrap">🦾 EXECUTE SCAN</button>
    </div>
    <label style="display:flex;align-items:center;gap:8px;font-size:.66rem;color:#2a3a2a;cursor:pointer">
      <input type="checkbox" id="co" required style="accent-color:#00ff9d;width:13px;height:13px">
      I confirm I have explicit authorization to perform reconnaissance on this target.
    </label>
  </form>
</div>

<!-- TERMINAL -->
<div id="tb" class="hidden mb-5">
  <div class="box" style="border-color:#00ff9d1a">
    <div class="tbar">
      <div class="dot" style="background:#ff5f56"></div>
      <div class="dot" style="background:#ffbd2e"></div>
      <div class="dot" style="background:#27c93f"></div>
      <span style="color:#1a2a1a;font-size:.66rem;margin-left:8px">vulnai-beast — passive-osint-engine v3.0</span>
    </div>
    <div id="to"><span class="lg">beast@vulnai:~$</span> <span class="blink lg">▌</span></div>
  </div>
</div>

<!-- RESULTS -->
<div id="res" style="display:none">

  <!-- S1: Risk + Summary + Insight -->
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px" class="rg3">
    <div class="box glow p-5" style="border-color:#0a200a">
      <div class="sl">🧠 AI RISK SCORE</div>
      <div id="rL" style="font-size:2rem;font-weight:900;color:#22c55e;line-height:1.1">—</div>
      <div style="font-size:.66rem;color:#2a3a2a;margin-top:4px">Weighted score: <span id="rS" style="color:#fbbf24">0</span></div>
      <div id="rB" style="margin-top:10px;font-size:.64rem;color:#2a3a4a;line-height:1.9"></div>
    </div>
    <div class="box p-5">
      <div class="sl">📊 EXECUTIVE SUMMARY</div>
      <div id="sumBlock" style="font-size:.75rem;line-height:2.1"></div>
    </div>
    <div class="box p-5">
      <div class="sl">🤖 AI SECURITY INSIGHT</div>
      <div id="aiS" style="font-size:.72rem;color:#b4b4bc;line-height:1.8;margin-bottom:10px"></div>
      <div class="sl" style="margin-top:6px">📌 RECOMMENDATIONS</div>
      <ul id="aiR" style="font-size:.68rem;color:#3a4a5a;line-height:2;list-style:none"></ul>
    </div>
  </div>

  <!-- S2: Attack Surface -->
  <div class="box p-5 mb-4">
    <div class="sl">⚔️ ATTACK SURFACE ANALYSIS</div>
    <div id="as" style="display:grid;grid-template-columns:1fr 1fr;gap:8px"></div>
  </div>

  <!-- S3: Infra + TLS + WHOIS -->
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px" class="rg3">
    <div class="box p-5">
      <div class="sl">🌐 INFRASTRUCTURE</div>
      <div id="infra" style="font-size:.76rem;line-height:2.1"></div>
      <div id="iTe" style="margin-top:8px"></div>
    </div>
    <div class="box p-5">
      <div class="sl">🔒 TLS / SSL</div>
      <div id="tls" style="font-size:.76rem;line-height:2.1"></div>
    </div>
    <div class="box p-5">
      <div class="sl">📖 WHOIS REGISTRATION</div>
      <div id="wh" style="font-size:.76rem;line-height:2.1"></div>
    </div>
  </div>

  <!-- S4: Geo + Ports -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
    <div class="box p-5">
      <div class="sl">🌍 IP GEOLOCATION / ASN</div>
      <div id="geo" style="font-size:.76rem;line-height:2.1"></div>
      <div id="geoN" style="font-size:.63rem;color:#2a3a4a;margin-top:6px;font-style:italic"></div>
    </div>
    <div class="box p-5">
      <div class="sl">🔌 PORT INTELLIGENCE</div>
      <div id="po" class="mb-3" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center"></div>
      <div style="font-size:.58rem;color:#1a2030">Scanned 23 ports: 21 22 23 25 53 80 110 135 143 443 445 993 995 1433 3306 3389 5432 5900 8080 8443 8888 9200 27017</div>
    </div>
  </div>

  <!-- S5: DNS -->
  <div class="box p-5 mb-4">
    <div class="sl">📡 DNS RECORDS</div>
    <div id="dns" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px"></div>
    <div class="sl">EMAIL SECURITY (SPF / DMARC / DKIM)</div>
    <div id="es" style="display:block"></div>
  </div>

  <!-- S6: Subdomains -->
  <div class="box p-5 mb-4">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
      <div class="sl" style="margin:0">🌐 SUBDOMAIN INTELLIGENCE</div>
      <span id="subB" class="badge bI">0 found</span>
    </div>
    <div id="subSrc" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;font-size:.62rem;color:#2a3a4a"></div>
    <div id="subG" class="sb"></div>
  </div>

  <!-- S7: Wayback -->
  <div class="box p-5 mb-4">
    <div class="sl">⏰ WAYBACK MACHINE INTELLIGENCE</div>
    <div id="wbSt" style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px"></div>
    <div id="wbN" style="font-size:.68rem;color:#2a3a4a;font-style:italic;margin-bottom:10px"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
      <div>
        <div class="sl">🔑 ADMIN / LOGIN URLS</div>
        <div id="wbA" class="sb" style="font-size:.65rem;line-height:1.9"></div>
      </div>
      <div>
        <div class="sl">🔌 API ENDPOINTS</div>
        <div id="wbAp" class="sb" style="font-size:.65rem;line-height:1.9"></div>
      </div>
      <div>
        <div class="sl">📄 INTERESTING FILES</div>
        <div id="wbF" class="sb" style="font-size:.65rem;line-height:1.9"></div>
      </div>
    </div>
  </div>

  <!-- S8: Findings -->
  <div class="box p-5 mb-4">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <div class="sl" style="margin:0">📋 SECURITY FINDINGS</div>
      <span id="fB" class="badge bH">0</span>
    </div>
    <div id="fi"></div>
  </div>

  <!-- S9: Threat Intel -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
    <div class="box p-5">
      <div class="sl">👾 ALIENVAULT OTX — THREAT INTEL</div>
      <div id="av" style="font-size:.76rem;line-height:2.1"></div>
    </div>
    <div class="box p-5">
      <div class="sl">🦠 VIRUSTOTAL — REPUTATION</div>
      <div id="vt" style="font-size:.76rem;line-height:2.1"></div>
    </div>
  </div>

  <!-- S10: Shodan + Hunter (with Kali commands when no key) -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
    <div class="box p-5">
      <div class="sl">🔭 SHODAN INTELLIGENCE</div>
      <div id="sh"></div>
    </div>
    <div class="box p-5">
      <div class="sl">📧 HUNTER.IO — EMAIL DISCOVERY</div>
      <div id="hu"></div>
    </div>
  </div>

  <!-- S11: Dorks -->
  <div class="box p-5 mb-4">
    <div class="sl">🔍 GOOGLE DORKS — MANUAL RECON QUERIES</div>
    <div style="font-size:.62rem;color:#2a3a4a;margin-bottom:8px">Click to open in Google — run these manually for deeper recon</div>
    <div id="dorks"></div>
  </div>

  <!-- S12: Certs -->
  <div class="box p-5 mb-4">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
      <div class="sl" style="margin:0">📜 CERTIFICATE TRANSPARENCY LOGS</div>
      <span id="cB" class="badge bI">0</span>
    </div>
    <div id="certs" class="sb" style="max-height:160px"></div>
  </div>

  <!-- S13: LeakIX -->
  <div class="box p-5 mb-4">
    <div class="sl">🔓 LEAKIX — LEAKED DATA DETECTION</div>
    <pre id="lx" style="font-size:.64rem;color:#4a5568;max-height:90px;overflow-y:auto;white-space:pre-wrap"></pre>
  </div>

  <!-- DOWNLOAD -->
  <div style="text-align:center;padding:20px 0">
    <button id="dl" style="background:#0c0c14;border:1px solid #00ff9d33;color:#00ff9d;font-family:'JetBrains Mono',monospace;font-weight:700;padding:12px 36px;border-radius:4px;cursor:pointer;font-size:.8rem">⬇ DOWNLOAD FULL OSINT REPORT (JSON)</button>
  </div>

</div><!-- /results -->
</div><!-- /container -->

<style>
@media(max-width:768px){
  .rg3{grid-template-columns:1fr !important}
  #as{grid-template-columns:1fr !important}
  #wbSt{grid-template-columns:1fr 1fr !important}
}
</style>

<script>
let RD = null;
const G = id => document.getElementById(id);

// ── MATRIX ──────────────────────────────────────────────────────────────────
function fillMatrix(){
  const c='01アイウエオカキクケコABCDEFGHIJ01アイウ';
  let s='';
  for(let i=0;i<5000;i++) s+=c[Math.floor(Math.random()*c.length)];
  G('mx').textContent=s;
}

// ── LOADING ─────────────────────────────────────────────────────────────────
const STEPS=[
  "Resolving IP and DNS records...",
  "Querying WHOIS registry...",
  "Pulling Certificate Transparency logs (crt.sh)...",
  "Running DNS bruteforce (50 words)...",
  "Fetching HackerTarget subdomain API...",
  "Querying RapidDNS passive database...",
  "Analyzing HTTP headers and WAF fingerprints...",
  "Extracting TLS/SSL certificate chain...",
  "Scanning 23 TCP ports...",
  "Querying Wayback Machine CDX API (400 URLs)...",
  "Fetching AlienVault OTX threat intelligence...",
  "Checking VirusTotal reputation...",
  "Querying LeakIX for leaked services...",
  "Running Shodan / Hunter.io modules...",
  "Running AI risk scoring engine...",
  "Building attack surface map...",
  "Compiling intelligence report...",
];
let si=0,pi=null;
function startLoad(){
  fillMatrix(); G('lo').style.display='flex';
  si=0; G('pbf').style.width='0%'; G('stxt').textContent=STEPS[0];
  pi=setInterval(()=>{
    si=Math.min(si+1,STEPS.length-1);
    G('pbf').style.width=Math.round(si/(STEPS.length-1)*92)+'%';
    G('stxt').textContent=STEPS[si];
  },900);
}
function stopLoad(){
  clearInterval(pi);
  G('pbf').style.width='100%';
  G('stxt').textContent='✓ Intelligence report ready';
  setTimeout(()=>{G('lo').style.display='none';},500);
}

// ── TERMINAL ─────────────────────────────────────────────────────────────────
const TMSGS=[
  {c:'lb',t:'[INIT] Loading 17 passive OSINT modules...'},
  {c:'lg',t:'[OK]   crt.sh Certificate Transparency logs'},
  {c:'lg',t:'[OK]   HackerTarget subdomain API'},
  {c:'lg',t:'[OK]   RapidDNS passive database'},
  {c:'lg',t:'[OK]   Wayback Machine CDX API'},
  {c:'lg',t:'[OK]   AlienVault OTX threat intelligence'},
  {c:'lg',t:'[OK]   VirusTotal reputation database'},
  {c:'lg',t:'[OK]   LeakIX leaked data detection'},
  {c:'lb',t:'[DNS]  Querying A, AAAA, MX, NS, TXT, SOA, CNAME...'},
  {c:'lb',t:'[CERT] Pulling certificate transparency logs...'},
  {c:'lb',t:'[SUB]  crtsh + HackerTarget + RapidDNS + DNS bruteforce...'},
  {c:'lb',t:'[PORT] Scanning 23 TCP ports (1.2s timeout)...'},
  {c:'lb',t:'[WEB]  Fingerprinting headers, WAF, technologies...'},
  {c:'lb',t:'[WAYB] Fetching + cleaning archived URLs...'},
  {c:'lb',t:'[RISK] Running weighted AI risk scoring...'},
  {c:'lg',t:'[✓]   BEAST SCAN COMPLETE — All 17 modules finished'},
];
let ti=0,tiv=null;
function startTerm(domain){
  G('tb').classList.remove('hidden');
  G('to').innerHTML=`<div class="lg">beast@vulnai:~$ ./beast-scan.py --target ${domain} --passive --all-modules</div>`;
  ti=0;
  tiv=setInterval(()=>{
    if(ti<TMSGS.length){
      const m=TMSGS[ti];
      G('to').innerHTML+=`<div class="${m.c}">${m.t}</div>`;
      G('to').scrollTop=99999; ti++;
    }
  },950);
}
function stopTerm(){
  clearInterval(tiv);
  G('to').innerHTML+=`<div class="lg" style="font-weight:700">[✓]   BEAST SCAN COMPLETE</div>`;
  G('to').scrollTop=99999;
}

// ── SUBMIT ───────────────────────────────────────────────────────────────────
G('sf').addEventListener('submit',async e=>{
  e.preventDefault();
  const domain=G('dm').value.trim().replace(/^https?:\/\//,'').split('/')[0].toLowerCase();
  if(!domain) return;
  G('res').style.display='none';
  G('sb').disabled=true; G('sb').textContent='⏳ Scanning...';
  startLoad(); startTerm(domain);
  try{
    const r=await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`);
    const d=await r.json();
    if(!r.ok){alert('Error: '+(d.error||'Scan failed'));return;}
    RD=d; stopLoad(); stopTerm();
    render(d);
    G('res').style.display='block';
    setTimeout(()=>G('res').scrollIntoView({behavior:'smooth'}),100);
  }catch(err){
    stopLoad();
    alert('Network error. Is Flask server running on port 5000?');
  }finally{
    G('sb').disabled=false; G('sb').textContent='🦾 EXECUTE SCAN';
  }
});

// ── HELPERS ──────────────────────────────────────────────────────────────────
function row(label,val,col){
  return `<div><span style="color:#2a3a4a">${label}: </span><span style="color:${col||'#c4c4cc'};font-weight:${col?'700':'400'}">${val??'—'}</span></div>`;
}
function urlLink(u,col){
  // Truncate very long URLs for display
  const disp=u.length>90?u.substring(0,87)+'…':u;
  return `<div class="url-item"><a href="${u}" target="_blank" style="color:${col}">${disp}</a></div>`;
}
const NONE='<span style="color:#1a2030;font-size:.68rem">None found</span>';

// ── RENDER ───────────────────────────────────────────────────────────────────
function render(d){
  const ports=d.open_ports||[];
  const pl=d.port_labels||{};
  const apiSt=d.api_status||{};
  const kali=d.kali_commands||{};

  // Risk
  const rk=d.risk||{};
  G('rL').textContent=rk.level||'—'; G('rL').style.color=rk.color||'#22c55e';
  G('rS').textContent=rk.score||0;
  G('rB').innerHTML=(rk.breakdown||[]).map(b=>`<div>▸ ${b}</div>`).join('');

  // Executive Summary
  G('sumBlock').innerHTML=[
    row('Target IP', d.ip, '#60a5fa'),
    row('Subdomains', (d.subdomains||[]).length),
    row('Certificates', (d.certificates||[]).length),
    row('Wayback URLs', (d.wayback||{}).total_snapshots||0),
    row('Open Ports', ports.length?ports.map(p=>`${p} (${pl[p]||'?'})`).join(', '):'None','#fbbf24'),
    row('Security Findings', (d.findings||[]).length, '#f87171'),
    row('Scan Duration', (d.scan_time||'—')+'s', '#00ff9d'),
  ].join('');

  // AI Insight
  const ins=d.ai_insight||{};
  G('aiS').textContent=ins.summary||'—';
  G('aiR').innerHTML=(ins.recommendations||[]).map(rc=>
    `<li style="padding-left:14px;position:relative"><span style="position:absolute;left:0;color:#00ff9d">›</span>${rc}</li>`
  ).join('');

  // Attack Surface
  G('as').innerHTML=(d.attack_surface||[]).map(s=>
    `<div style="background:#0c0c14;border:1px solid #16162a;border-radius:4px;padding:8px 12px;font-size:.72rem">${s}</div>`
  ).join('');

  // Infrastructure
  const m=d.web_meta||{};
  G('infra').innerHTML=[
    row('IP', d.ip, '#60a5fa'),
    row('Server', m.server),
    row('WAF/CDN', m.waf, '#fbbf24'),
    row('Status', m.status),
    row('Title', m.title),
  ].join('');
  G('iTe').innerHTML=(m.technologies||[]).map(t=>`<span class="tag" style="color:#00ff9d">${t}</span>`).join('');

  // TLS
  const tls=d.tls||{};
  G('tls').innerHTML=[
    row('Issuer', tls.issuer||(tls.error||'—')),
    row('Subject', tls.subject),
    row('Version', tls.tls_version, '#00ff9d'),
    row('Cipher', tls.cipher),
    row('Expires', tls.valid_until),
  ].join('');

  // WHOIS
  const w=d.whois||{};
  G('wh').innerHTML=w.note?`<div style="color:#2a3a4a;font-style:italic">${w.note}</div>`:[
    row('Registrar', w.registrar),
    row('Organization', w.organization),
    row('Created', w.created),
    row('Expires', w.expires),
    row('Name Servers', (w.name_servers||[]).join(', ')),
  ].join('');

  // Geo
  const g=d.geo||{};
  G('geo').innerHTML=[
    row('Country', g.country),
    row('Region', g.regionName),
    row('City', g.city),
    row('ISP', g.isp),
    row('ASN', g.as),
  ].join('');
  G('geoN').textContent=g.is_cdn
    ?'📍 Edge/CDN location — reflects CDN node, NOT the origin server'
    :'📍 Direct IP — likely reflects actual server location';

  // Ports
  G('po').innerHTML=ports.length
    ?ports.map(p=>`<span class="pb ${[80,443].includes(p)?'ps':'pr'}">${p} <span style="font-weight:400;font-size:.64rem">(${pl[p]||'?'})</span></span>`).join('')
    :'<span style="color:#2a3a4a;font-size:.76rem">No open ports detected in scanned range</span>';

  // DNS
  const dn=d.dns||{};
  G('dns').innerHTML=['A','AAAA','MX','NS','TXT','SOA','CNAME'].map(t=>{
    const vals=dn[t]||[];
    if(!vals.length) return '';
    return `<div class="box p-3">
      <span style="color:#fbbf24;font-weight:700;font-size:.66rem">${t}</span>
      <div style="color:#b4b4bc;font-size:.64rem;margin-top:4px;line-height:1.9">${vals.map(v=>`<div>${v}</div>`).join('')}</div>
    </div>`;
  }).join('');
  const es=dn._email_security||{};
  G('es').innerHTML=['SPF','DMARC','DKIM'].map(k=>{
    const ok=(es[k]||'').includes('Found');
    return `<div style="margin-bottom:6px"><span class="badge ${ok?'bL':'bH'}">${k}</span> <span style="font-size:.72rem;color:${ok?'#86efac':'#fca5a5'};margin-left:6px">${es[k]||'—'}</span></div>`;
  }).join('');

  // Subdomains
  const subs=d.subdomains||[];
  G('subB').textContent=subs.length+' found';
  const src=d.subdomain_sources||{};
  G('subSrc').innerHTML=Object.entries(src).map(([k,v])=>
    `<span class="tag" style="color:#2a3a4a">${k.replace(/_/g,' ')}: <strong style="color:#60a5fa">${v}</strong></span>`
  ).join('');
  const sipMap={};
  (d.subdomain_with_ip||[]).forEach(s=>{if(s.subdomain) sipMap[s.subdomain]=s.ip;});
  G('subG').innerHTML=subs.length
    ?subs.map(s=>`<div class="sub-i">
        <span style="color:#00ff9d">${s}</span>
        <span style="color:#1a2a40">→</span>
        <span style="color:#60a5fa;font-size:.65rem">${sipMap[s]||'—'}</span>
      </div>`).join('')
    :'<div style="color:#2a3a4a;font-size:.76rem">No subdomains discovered</div>';

  // Wayback
  const wb=d.wayback||{};
  G('wbN').textContent=wb.note||'';
  G('wbSt').innerHTML=[
    ['Total Snapshots',wb.total_snapshots||0,'#60a5fa'],
    ['Unique URLs',wb.unique_urls||0,'#00ff9d'],
    ['First Capture',wb.first_capture||'—','#fbbf24'],
    ['Last Capture',wb.last_capture||'—','#fbbf24'],
  ].map(([k,v,c])=>`<div class="box p-3" style="text-align:center">
    <div style="font-size:.58rem;color:#2a3a4a;text-transform:uppercase;letter-spacing:.08em">${k}</div>
    <div style="font-size:.95rem;font-weight:900;color:${c};margin-top:4px">${v}</div>
  </div>`).join('');
  G('wbA').innerHTML =(wb.admin_urls||[]).map(u=>urlLink(u,'#f87171')).join('')||NONE;
  G('wbAp').innerHTML=(wb.api_urls||[]).map(u=>urlLink(u,'#60a5fa')).join('')||NONE;
  G('wbF').innerHTML =(wb.file_urls||[]).map(u=>urlLink(u,'#fbbf24')).join('')||NONE;

  // Findings
  const fi=d.findings||[];
  G('fB').textContent=fi.length;
  G('fi').innerHTML=fi.length?fi.map(f=>{
    const lc={'HIGH':'fH','MEDIUM':'fM','LOW':'fL'}[f.severity]||'';
    const bc={'HIGH':'bH','MEDIUM':'bM','LOW':'bL'}[f.severity]||'bI';
    return `<div class="fi ${lc}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span class="badge ${bc}">${f.severity}</span>
        <span style="font-weight:700;color:#e2e2e8;font-size:.78rem">${f.title}</span>
      </div>
      <div style="font-size:.66rem;color:#6b7280">Risk: ${f.risk}</div>
      <div style="font-size:.66rem;color:#00ff9d;margin-top:2px">Fix: ${f.fix}</div>
    </div>`;
  }).join(''):'<div style="color:#22c55e;font-size:.76rem">No findings detected</div>';

  // AlienVault
  const aav=d.alienvault||{};
  G('av').innerHTML=Object.keys(aav).length?[
    row('Pulse Count',aav.pulse_count,aav.pulse_count>0?'#f87171':'#22c55e'),
    row('Reputation',aav.reputation),
    row('Malware Refs',aav.malware_count,aav.malware_count>0?'#f87171':'#22c55e'),
    row('Country',aav.country),
  ].join(''):'<span style="color:#2a3a4a">No data returned</span>';

  // VirusTotal
  const vvt=d.virustotal||{};
  if(vvt.disabled){
    G('vt').innerHTML=`<div class="kali-box">
      <span style="color:#fbbf24;font-size:.7rem;font-weight:700">📋 How to use VirusTotal on Kali:</span>
      <span class="kali-install"># Add your key in app.py → VIRUSTOTAL_KEY = "your-key"</span>
      ${(kali.virustotal?.commands||[]).map(c=>`<span class="kali-cmd">$ ${c}</span>`).join('')}
    </div>`;
  }else{
    G('vt').innerHTML=[
      row('Malicious',vvt.malicious,vvt.malicious>0?'#f87171':'#22c55e'),
      row('Suspicious',vvt.suspicious,vvt.suspicious>0?'#fbbf24':'#22c55e'),
      row('Harmless',vvt.harmless,'#22c55e'),
      row('Reputation',vvt.reputation),
    ].join('');
  }

  // Shodan
  const ssh=d.shodan||{};
  if(ssh.disabled){
    G('sh').innerHTML=`<div class="kali-box">
      <span style="color:#fbbf24;font-size:.7rem;font-weight:700">📋 Shodan CLI commands (Kali):</span>
      <span class="kali-install">${kali.shodan?.install||''}</span>
      ${(kali.shodan?.commands||[]).map(c=>`<span class="kali-cmd">$ ${c}</span>`).join('')}
      <div style="color:#2a3a4a;font-size:.63rem;margin-top:8px">Get key free: account.shodan.io · Add to SHODAN_KEY in app.py</div>
    </div>`;
  }else{
    G('sh').innerHTML=`<div style="font-size:.76rem;line-height:2.1">
      ${row('Org',ssh.org)}${row('ISP',ssh.isp)}${row('OS',ssh.os)}
      ${row('Ports',(ssh.ports||[]).join(', '),'#00ff9d')}
      ${(ssh.vulns||[]).length?row('CVEs',(ssh.vulns||[]).join(', '),'#f87171'):''}
    </div>`;
  }

  // Hunter.io
  const hhu=d.hunter||{};
  if(hhu.disabled){
    G('hu').innerHTML=`<div class="kali-box">
      <span style="color:#fbbf24;font-size:.7rem;font-weight:700">📋 Hunter.io curl commands (Kali):</span>
      <span class="kali-install">${kali.hunter?.install||''}</span>
      ${(kali.hunter?.commands||[]).map(c=>`<span class="kali-cmd">$ ${c}</span>`).join('')}
      <div style="color:#2a3a4a;font-size:.63rem;margin-top:8px">Get key free: hunter.io/api-keys · Add to HUNTER_KEY in app.py</div>
    </div>`;
  }else{
    G('hu').innerHTML=`<div style="font-size:.76rem;line-height:2.1">
      ${row('Total Emails',hhu.total,'#00ff9d')}${row('Pattern',hhu.pattern)}
      <div style="font-size:.68rem;color:#60a5fa;margin-top:6px;line-height:1.9">${(hhu.emails||[]).join('<br>')}</div>
    </div>`;
  }

  // Dorks
  G('dorks').innerHTML=(d.google_dorks||[]).map(q=>
    `<div class="dork"><span style="color:#1a2a1a">$</span><a href="https://www.google.com/search?q=${encodeURIComponent(q)}" target="_blank">${q}</a></div>`
  ).join('');

  // Certificates
  const cc=d.certificates||[];
  G('cB').textContent=cc.length;
  G('certs').innerHTML=cc.length?cc.map(c=>`<div style="background:#0c0c14;border:1px solid #16162a;border-radius:4px;padding:7px 10px;margin-bottom:5px;font-size:.64rem">
    <div style="color:#c4c4cc;font-weight:700">${(c.subject||'').substring(0,90)}</div>
    <div style="color:#2a3a4a;margin-top:2px">Issuer: ${(c.issuer||'').substring(0,70)}</div>
    <div style="color:#2a3a4a">Valid: ${c.valid_from} → ${c.valid_until}</div>
  </div>`).join(''):'<div style="color:#2a3a4a;font-size:.76rem">No certificates found in CT logs</div>';

  // LeakIX
  G('lx').textContent=JSON.stringify(d.leakix||{},null,2);
}

// ── DOWNLOAD ─────────────────────────────────────────────────────────────────
G('dl').addEventListener('click',()=>{
  if(!RD) return;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(RD,null,2)],{type:'application/json'}));
  a.download=`vulnai_beast_${RD.target}_${Date.now()}.json`;
  a.click();
});
</script>
</body>
</html>"""

# ─── ROUTES ───────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/api/scan")
def api_scan():
    domain = request.args.get("domain","").strip()
    domain = re.sub(r'^https?://', '', domain).split('/')[0].rstrip('.').lower()
    if not domain or not valid_domain(domain):
        return jsonify({"error": "Invalid domain format. Example: example.com"}), 400
    try:
        report = full_scan(domain)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    import os
    os.makedirs("logs", exist_ok=True)
    print("\n" + "="*62)
    print("  🦾  VulnAI Pro — BEAST EDITION v3.0  (Final)")
    print("  PASSIVE OSINT INTELLIGENCE PLATFORM")
    print("  ─────────────────────────────────────────────")
    print("  Open: http://127.0.0.1:5000")
    print()
    print("  Optional API keys (add in app.py to unlock modules):")
    print("    SHODAN_KEY     → https://account.shodan.io")
    print("    HUNTER_KEY     → https://hunter.io/api-keys")
    print("    VIRUSTOTAL_KEY → https://virustotal.com/gui/my-apikey")
    print()
    print("  When keys are absent, the UI shows Kali Linux curl")
    print("  commands so users can run them manually in terminal.")
    print("  ─────────────────────────────────────────────")
    print("  ⚠  Authorized targets only. Passive OSINT only.")
    print("="*62 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
