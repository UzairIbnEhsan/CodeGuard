"""
CODEGUARD - Advanced Security Scanner with Detailed Vulnerability Analysis
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import requests
import ssl
import socket
import re
from urllib.parse import urlparse
import sqlite3
import json
from datetime import datetime

# ============================================================
# DATABASE
# ============================================================

DB_PATH = Path(__file__).resolve().parent.parent / "codeguard.db"

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            type TEXT NOT NULL,
            score INTEGER NOT NULL,
            findings TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan(target, scan_type, score, findings):
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO scans (target, type, score, findings) VALUES (?, ?, ?, ?)",
        (target, scan_type, score, json.dumps(findings))
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_scans():
    conn = get_db()
    rows = conn.execute("SELECT id, target, type, score, created_at FROM scans ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    avg = conn.execute("SELECT AVG(score) FROM scans").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM scans WHERE score < 30").fetchone()[0]
    safe = conn.execute("SELECT COUNT(*) FROM scans WHERE score >= 80").fetchone()[0]
    conn.close()
    return {"total": total, "average": avg or 0, "critical": critical, "safe": safe}

def delete_scans():
    conn = get_db()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()

# ============================================================
# DETAILED VULNERABILITY DATABASE
# ============================================================

VULNERABILITY_DETAILS = {
    # Website Vulnerabilities
    "missing_hsts": {
        "cve": "CWE-524",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "HTTP Strict Transport Security (HSTS) header is missing. HSTS forces browsers to use HTTPS connections only.",
        "impact": "Man-in-the-Middle (MITM) attacks can downgrade connections from HTTPS to HTTP, exposing sensitive data.",
        "remediation": "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": [
            "https://owasp.org/www-project-secure-headers/#hsts",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ],
        "scan_type": "website"
    },
    "missing_csp": {
        "cve": "CWE-693",
        "severity": "HIGH",
        "cvss_score": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "owasp": "A03:2021 - Injection",
        "description": "Content Security Policy (CSP) header is missing. CSP prevents Cross-Site Scripting (XSS) attacks.",
        "impact": "Attackers can inject and execute malicious scripts in the browser, steal cookies, and deface websites.",
        "remediation": "Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
        "references": [
            "https://owasp.org/www-project-secure-headers/#csp",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        ],
        "scan_type": "website"
    },
    "xss_vulnerability": {
        "cve": "CWE-79",
        "severity": "CRITICAL",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "owasp": "A03:2021 - Injection",
        "description": "Cross-Site Scripting (XSS) vulnerability detected. User input is reflected without sanitization.",
        "impact": "Attackers can execute arbitrary JavaScript in victims' browsers, steal session cookies, and perform actions on behalf of users.",
        "remediation": "Sanitize all user inputs. Use output encoding. Implement Content Security Policy.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
        "scan_type": "website"
    },
    "server_info_disclosure": {
        "cve": "CWE-200",
        "severity": "MEDIUM",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Server information is exposed in HTTP response headers (Server, X-Powered-By, etc.).",
        "impact": "Attackers can identify server software versions and find known vulnerabilities for that version.",
        "remediation": "Remove or obscure Server headers. Use generic values or disable header exposure.",
        "references": [
            "https://owasp.org/www-project-secure-headers/#server",
            "https://www.acunetix.com/blog/articles/why-server-information-disclosure-is-a-problem/"
        ],
        "scan_type": "website"
    },
    "http_not_https": {
        "cve": "CWE-319",
        "severity": "CRITICAL",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Website uses unencrypted HTTP instead of HTTPS. All data is transmitted in plain text.",
        "impact": "Passwords, credit cards, and sensitive data can be intercepted by attackers on the network.",
        "remediation": "Install SSL certificate and redirect all HTTP traffic to HTTPS using 301 redirects.",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Security_Cheat_Sheet",
            "https://letsencrypt.org/"
        ],
        "scan_type": "website"
    },
    "ssl_error": {
        "cve": "CWE-295",
        "severity": "CRITICAL",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "SSL certificate is invalid, self-signed, or expired.",
        "impact": "Connection is not trusted. Users see security warnings. Data can be intercepted.",
        "remediation": "Install a valid SSL certificate from a trusted Certificate Authority (CA).",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Security_Cheat_Sheet",
            "https://docs.openssl.org/"
        ],
        "scan_type": "website"
    },
    
    # API Vulnerabilities
    "no_rate_limiting": {
        "cve": "CWE-770",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "owasp": "A04:2021 - Insecure Design",
        "description": "API does not implement rate limiting. Unlimited requests can be sent.",
        "impact": "Attackers can launch Denial of Service (DoS) attacks, brute force passwords, and exhaust system resources.",
        "remediation": "Implement rate limiting (e.g., 100 requests per minute). Use Redis or in-memory counters.",
        "references": [
            "https://owasp.org/www-community/controls/Rate_Limiting",
            "https://cloud.google.com/architecture/rate-limiting-strategies-techniques"
        ],
        "scan_type": "api"
    },
    "api_no_auth": {
        "cve": "CWE-306",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "API endpoint is accessible without authentication. No credentials required.",
        "impact": "Anyone can access the API and potentially read or modify sensitive data.",
        "remediation": "Implement authentication using API keys, OAuth2, or JWT tokens.",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/API_Security_Cheat_Sheet",
            "https://oauth.net/2/"
        ],
        "scan_type": "api"
    },
    "cors_misconfiguration": {
        "cve": "CWE-942",
        "severity": "HIGH",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "CORS allows any origin (*) to access the API. This is a misconfiguration.",
        "impact": "Any website can make requests to this API, potentially leaking sensitive data.",
        "remediation": "Restrict CORS to specific trusted origins. Never use wildcard (*) in production.",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
        ],
        "scan_type": "api"
    },
    "api_error_disclosure": {
        "cve": "CWE-209",
        "severity": "MEDIUM",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "API error messages expose internal details (stack traces, database errors).",
        "impact": "Attackers can gather system information to plan more sophisticated attacks.",
        "remediation": "Use generic error messages. Log detailed errors server-side only.",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Error_Handling_Cheat_Sheet"
        ],
        "scan_type": "api"
    },
    
    # Application Vulnerabilities
    "open_ports": {
        "cve": "CWE-284",
        "severity": "HIGH",
        "cvss_score": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Unnecessary network ports are open, increasing attack surface.",
        "impact": "Attackers can target open services for vulnerabilities and gain unauthorized access.",
        "remediation": "Close unnecessary ports with firewall rules. Use port scanning to identify open ports.",
        "references": [
            "https://owasp.org/www-community/attacks/Port_Scanning",
            "https://nmap.org/"
        ],
        "scan_type": "application"
    },
    "admin_panel_exposed": {
        "cve": "CWE-425",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Admin panel is exposed and accessible without authentication.",
        "impact": "Attackers can access admin functionality, steal data, or deface the application.",
        "remediation": "Restrict access to admin panels. Use IP whitelisting and strong authentication.",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Administrative_Management_Cheat_Sheet"
        ],
        "scan_type": "application"
    },
    "host_unreachable": {
        "cve": "CWE-703",
        "severity": "HIGH",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "owasp": "A04:2021 - Insecure Design",
        "description": "Application is not reachable or is down.",
        "impact": "Service disruption. Users cannot access the application.",
        "remediation": "Check server status. Ensure services are running. Monitor availability.",
        "references": [
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Logging_Cheat_Sheet"
        ],
        "scan_type": "application"
    },
    
    # Generic
    "invalid_input": {
        "cve": "N/A",
        "severity": "LOW",
        "cvss_score": 0.0,
        "cvss_vector": "N/A",
        "owasp": "N/A",
        "description": "Invalid input provided for scanning.",
        "impact": "Scan cannot be performed.",
        "remediation": "Provide valid input (URL, IP, domain, or API endpoint).",
        "references": [],
        "scan_type": "generic"
    }
}

# ============================================================
# HELPER: Get detailed vulnerability info
# ============================================================

def get_vulnerability_details(title, category):
    """Get detailed vulnerability information based on title and category"""
    
    # Map finding titles to vulnerability keys
    mapping = {
        "Missing: Strict-Transport-Security": "missing_hsts",
        "Missing: Content-Security-Policy": "missing_csp",
        "Missing: X-Frame-Options": "missing_hsts",  # Similar category
        "Missing: X-Content-Type-Options": "missing_hsts",  # Similar category
        "HTTP Instead of HTTPS": "http_not_https",
        "SSL Certificate Error": "ssl_error",
        "SSL Certificate Valid": None,  # Positive finding
        "XSS Vulnerability": "xss_vulnerability",
        "Server Info Exposed": "server_info_disclosure",
        "No Rate Limiting": "no_rate_limiting",
        "API Accessible": "api_no_auth",
        "CORS Misconfiguration": "cors_misconfiguration",
        "API Not Reachable": "api_error_disclosure",
        "Open Ports Found": "open_ports",
        "Admin Panel Exposed": "admin_panel_exposed",
        "Application Not Reachable": "host_unreachable",
        "Invalid URL": "invalid_input",
        "Invalid API URL": "invalid_input",
        "Invalid Target": "invalid_input",
        "Domain Not Found": "invalid_input",
        "Invalid IP Address": "invalid_input",
    }
    
    # Find the key
    key = None
    for pattern, vuln_key in mapping.items():
        if pattern.lower() in title.lower():
            key = vuln_key
            break
    
    # If not found, try to find by category
    if not key:
        if "SSL" in title or "Certificate" in title:
            key = "ssl_error"
        elif "Headers" in title:
            key = "missing_csp"
        elif "Authentication" in title:
            key = "api_no_auth"
        else:
            key = None
    
    if key and key in VULNERABILITY_DETAILS:
        return VULNERABILITY_DETAILS[key]
    return None

# ============================================================
# ENHANCED SCANNER FUNCTIONS
# ============================================================

def enrich_findings(findings):
    """Add detailed vulnerability information to findings"""
    enriched = []
    for finding in findings:
        enriched_finding = finding.copy()
        
        # Get detailed info
        details = get_vulnerability_details(finding.get("title", ""), finding.get("category", ""))
        
        if details:
            enriched_finding["cve"] = details.get("cve", "N/A")
            enriched_finding["cvss_score"] = details.get("cvss_score", 0.0)
            enriched_finding["cvss_vector"] = details.get("cvss_vector", "N/A")
            enriched_finding["owasp"] = details.get("owasp", "N/A")
            enriched_finding["detailed_impact"] = details.get("impact", finding.get("impact", ""))
            enriched_finding["detailed_remediation"] = details.get("remediation", finding.get("fix", ""))
            enriched_finding["references"] = details.get("references", [])
            enriched_finding["severity_score"] = details.get("cvss_score", 0.0)
        else:
            # For positive findings (SSL Valid, etc.)
            if "Valid" in finding.get("title", "") or "Reachable" in finding.get("title", ""):
                enriched_finding["cve"] = "N/A"
                enriched_finding["cvss_score"] = 0.0
                enriched_finding["cvss_vector"] = "N/A"
                enriched_finding["owasp"] = "N/A"
                enriched_finding["detailed_impact"] = "No vulnerability detected"
                enriched_finding["detailed_remediation"] = "No action required"
                enriched_finding["references"] = []
                enriched_finding["severity_score"] = 0.0
            else:
                enriched_finding["cve"] = "N/A"
                enriched_finding["cvss_score"] = 0.0
                enriched_finding["cvss_vector"] = "N/A"
                enriched_finding["owasp"] = "N/A"
                enriched_finding["detailed_impact"] = finding.get("impact", "")
                enriched_finding["detailed_remediation"] = finding.get("fix", "")
                enriched_finding["references"] = []
                enriched_finding["severity_score"] = 0.0
        
        enriched.append(enriched_finding)
    
    return enriched

# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def is_valid_url(url):
    if not url:
        return False
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(url_pattern, url) is not None

def is_valid_domain_or_ip(target):
    if not target:
        return False
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if re.match(ip_pattern, target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$')
    return re.match(domain_pattern, target) is not None

# ============================================================
# WEBSITE SCANNER (Enhanced)
# ============================================================

def scan_website(url):
    findings = []
    
    if not url or not is_valid_url(url):
        findings.append({
            "category": "Validation Error",
            "title": "Invalid URL",
            "severity": "CRITICAL",
            "description": f"'{url}' is not a valid URL",
            "impact": "Cannot scan - invalid input",
            "fix": "Please enter a valid URL starting with http:// or https://"
        })
        return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            findings.append({
                "category": "Validation Error",
                "title": "Invalid URL Format",
                "severity": "CRITICAL",
                "description": "Could not parse the URL",
                "impact": "Cannot scan",
                "fix": "Please enter a valid URL like https://example.com"
            })
            return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
        
        # SSL Check
        if parsed.scheme != 'https':
            findings.append({
                "category": "SSL/TLS",
                "title": "HTTP Instead of HTTPS",
                "severity": "CRITICAL",
                "description": "Website uses unencrypted HTTP protocol. All data transmitted in plain text.",
                "impact": "Passwords, credit cards, and sensitive data can be intercepted by attackers on the network.",
                "fix": "Install SSL certificate and redirect all HTTP traffic to HTTPS using 301 redirects."
            })
        else:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        import datetime
                        expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.datetime.now()).days
                        findings.append({
                            "category": "SSL/TLS",
                            "title": f"SSL Certificate Valid (Expires in {days_left} days)",
                            "severity": "LOW",
                            "description": f"SSL certificate is valid. Issued by: {dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown')}",
                            "impact": "Connection is encrypted and secure.",
                            "fix": "Keep certificate updated and renew before expiry."
                        })
            except socket.gaierror:
                findings.append({
                    "category": "DNS Error",
                    "title": "Domain Not Found",
                    "severity": "CRITICAL",
                    "description": f"Could not resolve domain: {hostname}",
                    "impact": "Website does not exist or DNS is misconfigured",
                    "fix": "Check the domain name spelling"
                })
                return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
            except socket.timeout:
                findings.append({
                    "category": "Connection Error",
                    "title": "Connection Timeout",
                    "severity": "CRITICAL",
                    "description": "Connection to server timed out",
                    "impact": "Server is not responding",
                    "fix": "Check if the server is online"
                })
                return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
            except Exception as e:
                findings.append({
                    "category": "SSL/TLS",
                    "title": "SSL Certificate Error",
                    "severity": "CRITICAL",
                    "description": f"Could not verify SSL: {str(e)[:100]}",
                    "impact": "Connection is insecure. Users cannot trust this website.",
                    "fix": "Check SSL configuration and ensure certificate is properly installed."
                })
        
        # Headers
        try:
            response = requests.get(url, timeout=15, verify=False)
            headers = response.headers
            
            sec_headers = {
                'Strict-Transport-Security': 'HSTS (HTTP Strict Transport Security)',
                'Content-Security-Policy': 'CSP (Content Security Policy)',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection'
            }
            
            for header, name in sec_headers.items():
                if header not in headers:
                    findings.append({
                        "category": "Security Headers",
                        "title": f"Missing: {name}",
                        "severity": "MEDIUM",
                        "description": f"{header} header is not set. This header provides protection against various web attacks.",
                        "impact": f"Website may be vulnerable to attacks that this header would prevent.",
                        "fix": f"Add {header} header to your response."
                    })
            
            if 'Server' in headers:
                findings.append({
                    "category": "Information Disclosure",
                    "title": "Server Information Exposed",
                    "severity": "MEDIUM",
                    "description": f"Server: {headers['Server']}",
                    "impact": "Attackers can identify server software version and find known vulnerabilities.",
                    "fix": "Remove or hide the Server header."
                })
                
            if 'X-Powered-By' in headers:
                findings.append({
                    "category": "Information Disclosure",
                    "title": "Technology Stack Exposed",
                    "severity": "LOW",
                    "description": f"X-Powered-By: {headers['X-Powered-By']}",
                    "impact": "Attackers can identify the technology stack and target known vulnerabilities.",
                    "fix": "Remove the X-Powered-By header."
                })
                
        except requests.exceptions.Timeout:
            findings.append({
                "category": "Connection Error",
                "title": "Request Timeout",
                "severity": "CRITICAL",
                "description": "Website took too long to respond",
                "impact": "Server is slow or unresponsive",
                "fix": "Check server performance"
            })
        except requests.exceptions.ConnectionError:
            findings.append({
                "category": "Connection Error",
                "title": "Connection Failed",
                "severity": "CRITICAL",
                "description": "Could not connect to the website",
                "impact": "Website is down or unreachable",
                "fix": "Check if website is online"
            })
        except Exception as e:
            findings.append({
                "category": "Error",
                "title": "Scan Error",
                "severity": "HIGH",
                "description": f"Error scanning website: {str(e)[:100]}",
                "impact": "Scan incomplete",
                "fix": "Please try again or check the URL"
            })
        
        # XSS Check
        try:
            test_payload = '<script>alert("XSS")</script>'
            test_url = f"{url}?q={test_payload}"
            r = requests.get(test_url, timeout=10, verify=False)
            if test_payload in r.text:
                findings.append({
                    "category": "XSS (Cross-Site Scripting)",
                    "title": "Potential XSS Vulnerability",
                    "severity": "CRITICAL",
                    "description": "URL parameter is reflected in the response without sanitization.",
                    "impact": "Attackers can inject malicious scripts to steal cookies, sessions, or redirect users.",
                    "fix": "Sanitize all user inputs. Implement Content Security Policy (CSP). Use output encoding."
                })
        except:
            pass
        
    except Exception as e:
        findings.append({
            "category": "Error",
            "title": "Unexpected Error",
            "severity": "HIGH",
            "description": f"Error: {str(e)[:100]}",
            "impact": "Scan failed",
            "fix": "Please try again"
        })
    
    # Enrich findings with detailed information
    enriched_findings = enrich_findings(findings)
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100 - sum(weights.get(f["severity"], 5) for f in enriched_findings)
    score = max(0, min(100, score))
    summary = {
        "critical": sum(1 for f in enriched_findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in enriched_findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in enriched_findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in enriched_findings if f["severity"] == "LOW")
    }
    return {"score": score, "summary": summary, "findings": enriched_findings}

# ============================================================
# API SCANNER (Enhanced)
# ============================================================

def scan_api(api_url):
    findings = []
    
    if not api_url or not is_valid_url(api_url):
        findings.append({
            "category": "Validation Error",
            "title": "Invalid API URL",
            "severity": "CRITICAL",
            "description": f"'{api_url}' is not a valid URL",
            "impact": "Cannot scan - invalid input",
            "fix": "Please enter a valid API URL starting with http:// or https://"
        })
        return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
    
    if not api_url.startswith(('http://', 'https://')):
        api_url = 'https://' + api_url
    
    try:
        response = requests.get(api_url, timeout=10, verify=False)
        headers = response.headers
        
        if response.status_code == 200:
            findings.append({
                "category": "Authentication",
                "title": "API Accessible",
                "severity": "LOW",
                "description": "API returned 200 OK - endpoint is accessible",
                "impact": "Ensure proper authentication is in place",
                "fix": "Implement authentication if not already present"
            })
        elif response.status_code == 401:
            findings.append({
                "category": "Authentication",
                "title": "Authentication Required",
                "severity": "LOW",
                "description": "API requires authentication (401 Unauthorized)",
                "impact": "Good - authentication is enforced",
                "fix": "Keep authentication in place"
            })
        elif response.status_code == 403:
            findings.append({
                "category": "Authentication",
                "title": "Access Forbidden",
                "severity": "LOW",
                "description": "Access is forbidden (403 Forbidden)",
                "impact": "Good - proper authorization controls are in place",
                "fix": "Maintain proper authorization controls"
            })
        elif response.status_code == 404:
            findings.append({
                "category": "Error",
                "title": "API Endpoint Not Found",
                "severity": "HIGH",
                "description": "API returned 404 Not Found",
                "impact": "The endpoint does not exist",
                "fix": "Check the API URL"
            })
        elif response.status_code >= 500:
            findings.append({
                "category": "Error",
                "title": "API Server Error",
                "severity": "CRITICAL",
                "description": f"API returned {response.status_code} Server Error",
                "impact": "API is experiencing issues",
                "fix": "Check API server status"
            })
        
        # CORS Check
        if 'Access-Control-Allow-Origin' in headers:
            if headers['Access-Control-Allow-Origin'] == '*':
                findings.append({
                    "category": "CORS Configuration",
                    "title": "CORS Misconfiguration",
                    "severity": "HIGH",
                    "description": "CORS allows any origin (*). This is a security misconfiguration.",
                    "impact": "Any website can access this API, potentially exposing sensitive data.",
                    "fix": "Restrict CORS to specific trusted origins only."
                })
        
        # Rate Limiting
        if 'X-RateLimit-Limit' not in headers:
            findings.append({
                "category": "Rate Limiting",
                "title": "No Rate Limiting Detected",
                "severity": "HIGH",
                "description": "Rate limiting headers not found. API may not have rate limiting.",
                "impact": "API is vulnerable to Denial of Service (DoS) attacks and brute force attempts.",
                "fix": "Implement rate limiting (e.g., 100 requests per minute)."
            })
        
        # Security Headers
        if 'X-Content-Type-Options' not in headers:
            findings.append({
                "category": "Security Headers",
                "title": "Missing Security Header: X-Content-Type-Options",
                "severity": "MEDIUM",
                "description": "X-Content-Type-Options header is not set",
                "impact": "MIME sniffing attacks possible",
                "fix": "Add: X-Content-Type-Options: nosniff"
            })
            
        # Error message disclosure
        if response.status_code >= 400:
            if 'error' in response.text.lower() or 'exception' in response.text.lower():
                findings.append({
                    "category": "Information Disclosure",
                    "title": "Error Message Disclosure",
                    "severity": "MEDIUM",
                    "description": "Error messages reveal internal details",
                    "impact": "Attackers can gather system information",
                    "fix": "Use generic error messages"
                })
            
    except requests.exceptions.Timeout:
        findings.append({
            "category": "Connection Error",
            "title": "API Timeout",
            "severity": "CRITICAL",
            "description": "API request timed out",
            "impact": "API is slow or unresponsive",
            "fix": "Check API performance"
        })
    except requests.exceptions.ConnectionError:
        findings.append({
            "category": "Connection Error",
            "title": "API Not Reachable",
            "severity": "CRITICAL",
            "description": "Could not connect to API",
            "impact": "API is down or unreachable",
            "fix": "Check API status and URL"
        })
    except Exception as e:
        findings.append({
            "category": "Error",
            "title": "API Scan Error",
            "severity": "HIGH",
            "description": f"Error: {str(e)[:100]}",
            "impact": "Scan failed",
            "fix": "Please check the API URL"
        })
    
    enriched_findings = enrich_findings(findings)
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100 - sum(weights.get(f["severity"], 5) for f in enriched_findings)
    score = max(0, min(100, score))
    summary = {
        "critical": sum(1 for f in enriched_findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in enriched_findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in enriched_findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in enriched_findings if f["severity"] == "LOW")
    }
    return {"score": score, "summary": summary, "findings": enriched_findings}

# ============================================================
# APPLICATION SCANNER (Enhanced)
# ============================================================

def scan_application(target):
    findings = []
    
    if not target or not is_valid_domain_or_ip(target):
        findings.append({
            "category": "Validation Error",
            "title": "Invalid Target",
            "severity": "CRITICAL",
            "description": f"'{target}' is not a valid IP address or domain",
            "impact": "Cannot scan - invalid input",
            "fix": "Please enter a valid IP (e.g., 8.8.8.8) or domain (e.g., google.com)"
        })
        return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
    
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
    
    try:
        if is_ip:
            ports = {
                21: 'FTP - File Transfer',
                22: 'SSH - Secure Shell',
                23: 'Telnet - Insecure Remote Access',
                25: 'SMTP - Email',
                80: 'HTTP - Web Server',
                443: 'HTTPS - Secure Web Server',
                3306: 'MySQL - Database',
                5432: 'PostgreSQL - Database',
                27017: 'MongoDB - Database',
                6379: 'Redis - Cache'
            }
            open_ports = []
            
            for port, service in ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(f"{port} ({service})")
                    sock.close()
                except socket.gaierror:
                    findings.append({
                        "category": "DNS Error",
                        "title": "Invalid IP Address",
                        "severity": "CRITICAL",
                        "description": f"Could not resolve IP: {target}",
                        "impact": "IP address is invalid",
                        "fix": "Check the IP address"
                    })
                    return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": enrich_findings(findings)}
                except:
                    pass
            
            if open_ports:
                findings.append({
                    "category": "Network Security",
                    "title": "Open Ports Found",
                    "severity": "HIGH",
                    "description": f"Open ports detected: {', '.join(open_ports)}",
                    "impact": "Each open port is a potential entry point for attackers. Unnecessary services increase attack surface.",
                    "fix": "Close unnecessary ports with firewall rules. Secure open services."
                })
            else:
                findings.append({
                    "category": "Network Security",
                    "title": "No Open Ports Found",
                    "severity": "LOW",
                    "description": "No common ports are open on this IP",
                    "impact": "Good - limited attack surface",
                    "fix": "Keep firewall rules strict"
                })
        else:
            try:
                response = requests.get(f"https://{target}", timeout=10, verify=False)
                findings.append({
                    "category": "Accessibility",
                    "title": "Application Reachable",
                    "severity": "LOW",
                    "description": f"Successfully connected to {target}",
                    "impact": "Application is live and responding",
                    "fix": "Keep application running"
                })
                
                if 'Server' in response.headers:
                    findings.append({
                        "category": "Information Disclosure",
                        "title": "Server Information Exposed",
                        "severity": "MEDIUM",
                        "description": f"Server: {response.headers['Server']}",
                        "impact": "Attackers can identify server version and find known vulnerabilities.",
                        "fix": "Hide or remove Server header."
                    })
                
                # Check admin paths
                admin_paths = [
                    {'path': '/admin', 'description': 'Admin Panel'},
                    {'path': '/login', 'description': 'Login Page'},
                    {'path': '/wp-admin', 'description': 'WordPress Admin'},
                    {'path': '/phpmyadmin', 'description': 'phpMyAdmin'},
                    {'path': '/cpanel', 'description': 'cPanel'},
                    {'path': '/dashboard', 'description': 'Dashboard'},
                    {'path': '/manager', 'description': 'Manager Panel'},
                    {'path': '/control', 'description': 'Control Panel'}
                ]
                
                for item in admin_paths:
                    try:
                        r = requests.get(f"https://{target}{item['path']}", timeout=5, verify=False)
                        if r.status_code == 200:
                            findings.append({
                                "category": "Security Misconfiguration",
                                "title": f"Admin Panel Exposed: {item['path']}",
                                "severity": "HIGH",
                                "description": f"{item['description']} at {item['path']} is accessible",
                                "impact": "Attackers can access administrative interfaces and potentially take control.",
                                "fix": f"Restrict access to {item['path']} using IP whitelisting and strong authentication."
                            })
                            break
                    except:
                        pass
                        
            except socket.gaierror:
                findings.append({
                    "category": "DNS Error",
                    "title": "Domain Not Found",
                    "severity": "CRITICAL",
                    "description": f"Could not resolve domain: {target}",
                    "impact": "Domain does not exist or DNS is misconfigured",
                    "fix": "Check the domain name spelling"
                })
            except requests.exceptions.Timeout:
                findings.append({
                    "category": "Connection Error",
                    "title": "Connection Timeout",
                    "severity": "HIGH",
                    "description": "Request timed out",
                    "impact": "Application is slow or unresponsive",
                    "fix": "Check application performance"
                })
            except requests.exceptions.ConnectionError:
                findings.append({
                    "category": "Connection Error",
                    "title": "Application Not Reachable",
                    "severity": "CRITICAL",
                    "description": "Could not connect to application",
                    "impact": "Application may be down",
                    "fix": "Check application status"
                })
            except Exception as e:
                findings.append({
                    "category": "Error",
                    "title": "Scan Error",
                    "severity": "HIGH",
                    "description": f"Error: {str(e)[:100]}",
                    "impact": "Scan failed",
                    "fix": "Please try again"
                })
                
    except Exception as e:
        findings.append({
            "category": "Error",
            "title": "Unexpected Error",
            "severity": "HIGH",
            "description": f"Error: {str(e)[:100]}",
            "impact": "Scan failed",
            "fix": "Please try again"
        })
    
    enriched_findings = enrich_findings(findings)
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100 - sum(weights.get(f["severity"], 5) for f in enriched_findings)
    score = max(0, min(100, score))
    summary = {
        "critical": sum(1 for f in enriched_findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in enriched_findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in enriched_findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in enriched_findings if f["severity"] == "LOW")
    }
    return {"score": score, "summary": summary, "findings": enriched_findings}

# ============================================================
# FASTAPI APP
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

app = FastAPI(title="CodeGuard", version="1.0.0")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.on_event("startup")
def startup():
    init_db()
    print("\n" + "=" * 50)
    print("🛡️ CODEGUARD - ADVANCED SECURITY SCANNER")
    print("=" * 50)
    print("🌐 http://127.0.0.1:8000")
    print("=" * 50)

# ============================================================
# ROUTES
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    stats = get_stats()
    scans = get_scans()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_scans": stats["total"],
        "avg_score": round(stats["average"], 1),
        "critical_scans": stats["critical"],
        "safe_scans": stats["safe"],
        "scans": scans
    })

@app.post("/api/scan-website")
async def api_scan_website(url: str = Form(...)):
    result = scan_website(url)
    scan_id = save_scan(url, "website", result["score"], result["findings"])
    return {"scan_id": scan_id, "target": url, **result, "scan_type": "Website"}

@app.post("/api/scan-api")
async def api_scan_api(url: str = Form(...)):
    result = scan_api(url)
    scan_id = save_scan(url, "api", result["score"], result["findings"])
    return {"scan_id": scan_id, "target": url, **result, "scan_type": "API"}

@app.post("/api/scan-application")
async def api_scan_app(target: str = Form(...)):
    result = scan_application(target)
    scan_id = save_scan(target, "application", result["score"], result["findings"])
    return {"scan_id": scan_id, "target": target, **result, "scan_type": "Application"}

@app.get("/api/scans")
async def get_all_scans():
    return {"scans": get_scans()}

@app.get("/api/stats")
async def get_all_stats():
    return get_stats()

@app.post("/api/reset-history")
async def reset_history():
    delete_scans()
    return {"success": True}

@app.get("/health")
async def health():
    return {"status": "ok", "project": "CodeGuard"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

    # ============================================================
# SECURITY SCORE DETAILS - How secure is it?
# ============================================================

def get_security_details(score, findings, scan_type):
    """Generate detailed security breakdown"""
    
    # Security Level
    if score >= 90:
        level = "🌟 EXCELLENT"
        level_color = "green"
        description = "Outstanding security posture. No critical or high vulnerabilities found."
        recommendation = "Maintain current security practices and conduct regular audits."
        badge = "🟢"
    elif score >= 70:
        level = "✅ GOOD"
        level_color = "teal"
        description = "Good security with minor issues. Low-risk vulnerabilities present."
        recommendation = "Address medium and low severity issues to achieve excellent rating."
        badge = "🟡"
    elif score >= 50:
        level = "⚠️ FAIR"
        level_color = "yellow"
        description = "Moderate security issues detected. Several vulnerabilities need attention."
        recommendation = "Prioritize fixing high severity issues. Schedule comprehensive security review."
        badge = "🟠"
    elif score >= 30:
        level = "⚠️ POOR"
        level_color = "orange"
        description = "Significant security weaknesses. Multiple high and critical vulnerabilities."
        recommendation = "IMMEDIATE ACTION REQUIRED. Fix all critical and high vulnerabilities first."
        badge = "🔴"
    else:
        level = "🚨 CRITICAL"
        level_color = "red"
        description = "Severe security issues detected. Immediate action required to prevent compromise."
        recommendation = "CRITICAL EMERGENCY. Take all systems offline until vulnerabilities are fixed."
        badge = "🚨"
    
    # Count vulnerabilities by severity
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")
    total = len(findings)
    
    # Risk assessment
    if critical > 0:
        risk_level = "CRITICAL RISK"
        risk_color = "red"
        urgency = "IMMEDIATE"
    elif high > 0:
        risk_level = "HIGH RISK"  
        risk_color = "orange"
        urgency = "URGENT"
    elif medium > 0:
        risk_level = "MODERATE RISK"
        risk_color = "yellow"
        urgency = "SOON"
    elif low > 0:
        risk_level = "LOW RISK"
        risk_color = "green"
        urgency = "LATER"
    else:
        risk_level = "NO RISK"
        risk_color = "green"
        urgency = "NONE"
    
    # Security summary
    security_summary = {
        "security_level": level,
        "level_color": level_color,
        "badge": badge,
        "description": description,
        "recommendation": recommendation,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "urgency": urgency,
        "total_vulnerabilities": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "scan_type": scan_type,
        "score": score
    }
    
    return security_summary