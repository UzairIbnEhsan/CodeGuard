"""
CODEGUARD - Advanced Security Scanner
Website, API & Application Scanner
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
# WEBSITE SCANNER - Different vulnerabilities for websites
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
            "fix": "Please enter a valid URL"
        })
        return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": findings}
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # ============================================================
    # WEBSITE-SPECIFIC CHECKS
    # ============================================================
    
    # 1. SSL/TLS Check
    if parsed.scheme != 'https':
        findings.append({
            "category": "SSL/TLS",
            "title": "HTTP Instead of HTTPS",
            "severity": "CRITICAL",
            "description": "Website is using unencrypted HTTP. All data transmitted in plain text.",
            "impact": "Passwords, credit cards, and sensitive data can be intercepted.",
            "fix": "Install SSL certificate and redirect HTTP to HTTPS."
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
                    if days_left < 30:
                        findings.append({
                            "category": "SSL/TLS",
                            "title": "SSL Certificate Expiring Soon",
                            "severity": "HIGH",
                            "description": f"SSL certificate expires in {days_left} days",
                            "impact": "Users will see security warnings after expiry",
                            "fix": f"Renew SSL certificate before {cert['notAfter']}"
                        })
                    else:
                        findings.append({
                            "category": "SSL/TLS",
                            "title": "SSL Certificate Valid",
                            "severity": "LOW",
                            "description": "SSL certificate is valid and secure",
                            "impact": "Connection is encrypted and secure",
                            "fix": "Keep certificate updated"
                        })
        except:
            findings.append({
                "category": "SSL/TLS",
                "title": "SSL Certificate Error",
                "severity": "CRITICAL",
                "description": "Could not verify SSL certificate",
                "impact": "Connection is insecure. Users cannot trust this website.",
                "fix": "Check SSL configuration and install valid certificate"
            })
    
    # 2. Security Headers Check
    try:
        response = requests.get(url, timeout=15, verify=False)
        headers = response.headers
        
        sec_headers = {
            'Strict-Transport-Security': 'HSTS - Prevents SSL stripping',
            'Content-Security-Policy': 'CSP - Prevents XSS attacks',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'X-XSS-Protection': 'XSS Protection'
        }
        
        for header, name in sec_headers.items():
            if header not in headers:
                findings.append({
                    "category": "Security Headers",
                    "title": f"Missing Security Header: {name}",
                    "severity": "MEDIUM",
                    "description": f"{header} header is not set",
                    "impact": "Website may be vulnerable to attacks",
                    "fix": f"Add {header} header to your response"
                })
        
        # 3. Server Info Disclosure
        if 'Server' in headers:
            findings.append({
                "category": "Information Disclosure",
                "title": "Server Information Exposed",
                "severity": "MEDIUM",
                "description": f"Server: {headers['Server']}",
                "impact": "Attackers can identify server version and find known vulnerabilities",
                "fix": "Remove or hide the Server header"
            })
        
        # 4. XSS Check
        try:
            test_payload = '<script>alert("XSS")</script>'
            test_url = f"{url}?q={test_payload}"
            r = requests.get(test_url, timeout=10, verify=False)
            if test_payload in r.text:
                findings.append({
                    "category": "XSS (Cross-Site Scripting)",
                    "title": "Potential XSS Vulnerability",
                    "severity": "CRITICAL",
                    "description": "URL parameter is reflected in the response without sanitization",
                    "impact": "Attackers can inject malicious scripts to steal cookies or redirect users",
                    "fix": "Sanitize all user inputs and implement Content Security Policy"
                })
        except:
            pass
        
    except:
        findings.append({
            "category": "Accessibility",
            "title": "Website Not Reachable",
            "severity": "CRITICAL",
            "description": "Could not connect to the website",
            "impact": "Website is down or blocking connections",
            "fix": "Check server status and firewall"
        })
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100 - sum(weights.get(f["severity"], 5) for f in findings)
    score = max(0, min(100, score))
    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW")
    }
    return {"score": score, "summary": summary, "findings": findings}

# ============================================================
# API SCANNER - Different vulnerabilities for APIs
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
            "fix": "Please enter a valid API URL"
        })
        return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": findings}
    
    if not api_url.startswith(('http://', 'https://')):
        api_url = 'https://' + api_url
    
    try:
        response = requests.get(api_url, timeout=10, verify=False)
        headers = response.headers
        
        # ============================================================
        # API-SPECIFIC CHECKS
        # ============================================================
        
        # 1. Authentication Status
        if response.status_code == 200:
            findings.append({
                "category": "Authentication",
                "title": "API Accessible Without Authentication",
                "severity": "HIGH",
                "description": "API returned 200 OK. No authentication detected.",
                "impact": "Anyone can access this API endpoint without credentials",
                "fix": "Implement authentication using API keys, OAuth2, or JWT"
            })
        elif response.status_code == 401:
            findings.append({
                "category": "Authentication",
                "title": "Authentication Required (401)",
                "severity": "LOW",
                "description": "API requires authentication. Good practice!",
                "impact": "Authentication is enforced properly",
                "fix": "Keep authentication in place"
            })
        elif response.status_code == 403:
            findings.append({
                "category": "Authentication",
                "title": "Access Forbidden (403)",
                "severity": "LOW",
                "description": "API properly restricts access",
                "impact": "Good - proper authorization controls",
                "fix": "Maintain proper authorization controls"
            })
        elif response.status_code == 404:
            findings.append({
                "category": "Error",
                "title": "API Endpoint Not Found (404)",
                "severity": "HIGH",
                "description": "The API endpoint does not exist",
                "impact": "May indicate misconfiguration or typo in URL",
                "fix": "Check the API URL and ensure the endpoint exists"
            })
        
        # 2. CORS Check
        if 'Access-Control-Allow-Origin' in headers:
            if headers['Access-Control-Allow-Origin'] == '*':
                findings.append({
                    "category": "CORS Configuration",
                    "title": "CORS Misconfiguration - Wildcard Origin",
                    "severity": "HIGH",
                    "description": "CORS allows any origin (*) to access this API",
                    "impact": "Any website can access this API, potentially exposing sensitive data",
                    "fix": "Restrict CORS to specific trusted origins only"
                })
        else:
            findings.append({
                "category": "CORS Configuration",
                "title": "CORS Header Not Set",
                "severity": "LOW",
                "description": "Access-Control-Allow-Origin header is not set",
                "impact": "API may not be accessible from browsers",
                "fix": "Set CORS headers if browser access is needed"
            })
        
        # 3. Rate Limiting Check
        if 'X-RateLimit-Limit' not in headers:
            findings.append({
                "category": "Rate Limiting",
                "title": "No Rate Limiting Detected",
                "severity": "HIGH",
                "description": "Rate limiting headers not found. API may not have rate limiting.",
                "impact": "API is vulnerable to Denial of Service (DoS) attacks and brute force attempts",
                "fix": "Implement rate limiting (e.g., 100 requests per minute)"
            })
        else:
            limit = headers.get('X-RateLimit-Limit', 'Unknown')
            remaining = headers.get('X-RateLimit-Remaining', 'Unknown')
            findings.append({
                "category": "Rate Limiting",
                "title": "Rate Limiting Implemented",
                "severity": "LOW",
                "description": f"Rate limit: {limit} requests. Remaining: {remaining}",
                "impact": "Good - API has rate limiting to prevent abuse",
                "fix": "Keep rate limiting in place"
            })
        
        # 4. Security Headers
        if 'X-Content-Type-Options' not in headers:
            findings.append({
                "category": "Security Headers",
                "title": "Missing Security Header: X-Content-Type-Options",
                "severity": "MEDIUM",
                "description": "X-Content-Type-Options header is not set",
                "impact": "MIME sniffing attacks possible",
                "fix": "Add: X-Content-Type-Options: nosniff"
            })
        
        # 5. Error Message Disclosure
        if response.status_code >= 400:
            if 'error' in response.text.lower() or 'exception' in response.text.lower():
                findings.append({
                    "category": "Information Disclosure",
                    "title": "Error Message Disclosure",
                    "severity": "MEDIUM",
                    "description": "Error messages reveal internal details",
                    "impact": "Attackers can gather system information",
                    "fix": "Use generic error messages (e.g., 'Something went wrong')"
                })
        
        # 6. Server Info
        if 'Server' in headers:
            findings.append({
                "category": "Information Disclosure",
                "title": "Server Information Exposed",
                "severity": "LOW",
                "description": f"Server: {headers['Server']}",
                "impact": "Attackers can identify server version",
                "fix": "Hide or remove Server header"
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
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100 - sum(weights.get(f["severity"], 5) for f in findings)
    score = max(0, min(100, score))
    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW")
    }
    return {"score": score, "summary": summary, "findings": findings}

# ============================================================
# APPLICATION SCANNER - Different vulnerabilities for apps
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
        return {"score": 0, "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": findings}
    
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
    
    try:
        # ============================================================
        # APPLICATION-SPECIFIC CHECKS
        # ============================================================
        
        if is_ip:
            # Check for open ports
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
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(f"{port} ({service})")
                    sock.close()
                except:
                    pass
            
            if open_ports:
                findings.append({
                    "category": "Network Security",
                    "title": "Open Ports Detected",
                    "severity": "HIGH",
                    "description": f"Open ports detected: {', '.join(open_ports)}",
                    "impact": "Each open port is a potential entry point for attackers",
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
            
            # Ping test
            try:
                import subprocess
                result = subprocess.run(['ping', '-n', '1', target], capture_output=True, timeout=5)
                if result.returncode == 0:
                    findings.append({
                        "category": "Accessibility",
                        "title": "Host is Reachable",
                        "severity": "LOW",
                        "description": f"Host {target} responded to ping",
                        "impact": "Host is online and responding",
                        "fix": "Keep host accessible"
                    })
                else:
                    findings.append({
                        "category": "Accessibility",
                        "title": "Host Not Reachable",
                        "severity": "HIGH",
                        "description": f"Host {target} did not respond to ping",
                        "impact": "Host may be down or blocking ICMP",
                        "fix": "Check if host is online"
                    })
            except:
                pass
        
        else:
            # Domain/Application scan
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
                
                # Check admin paths
                admin_paths = [
                    '/admin', '/login', '/wp-admin', '/phpmyadmin', '/cpanel',
                    '/dashboard', '/manager', '/control', '/administrator'
                ]
                
                for path in admin_paths:
                    try:
                        r = requests.get(f"https://{target}{path}", timeout=5, verify=False)
                        if r.status_code == 200:
                            findings.append({
                                "category": "Security Misconfiguration",
                                "title": f"Admin Panel Exposed: {path}",
                                "severity": "HIGH",
                                "description": f"{path} is accessible without authentication",
                                "impact": "Attackers can access administrative interfaces",
                                "fix": f"Restrict access to {path} using IP whitelisting and strong authentication"
                            })
                            break
                    except:
                        pass
                
                # Check server info
                if 'Server' in response.headers:
                    findings.append({
                        "category": "Information Disclosure",
                        "title": "Server Information Exposed",
                        "severity": "MEDIUM",
                        "description": f"Server: {response.headers['Server']}",
                        "impact": "Attackers can identify server version",
                        "fix": "Hide or remove Server header"
                    })
                
            except:
                findings.append({
                    "category": "Accessibility",
                    "title": "Application Not Reachable",
                    "severity": "CRITICAL",
                    "description": "Could not connect to application",
                    "impact": "Application may be down",
                    "fix": "Check application status"
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
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100 - sum(weights.get(f["severity"], 5) for f in findings)
    score = max(0, min(100, score))
    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW")
    }
    return {"score": score, "summary": summary, "findings": findings}

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
    print("🌐 Website Scanner - SSL, Headers, XSS")
    print("🔌 API Scanner - Auth, CORS, Rate Limiting")
    print("🖥️ Application Scanner - Ports, Admin Panels")
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