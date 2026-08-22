# 🛡️ CodeGuard - Vulnerability Finder

## AI-Powered Application Security & Vulnerability Analyzer

---

**Version:** 2.0.0  
**Developer:** Uzair Ehsan  
**Status:** Production Ready  
**Live Demo:** [https://codeguard.vercel.app](https://codeguard.vercel.app)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)
- [API Endpoints](#api-endpoints)
- [Testing Examples](#testing-examples)
- [Security Ratings](#security-ratings)
- [Troubleshooting](#troubleshooting)
- [Future Roadmap](#future-roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## 📌 Overview

**CodeGuard** is a comprehensive, AI-powered security analysis platform that automatically detects vulnerabilities in **websites**, **APIs**, and **applications**. It provides real-time security scoring, detailed vulnerability reports, and actionable remediation guidance.

### Why CodeGuard?

| Problem | Solution |
|---------|----------|
| Developers unintentionally write insecure code | Automated vulnerability scanning |
| Manual security review is time-consuming | Instant results (< 1 second) |
| Security knowledge is specialized | Clear explanations with fixes |
| AI-generated code introduces new risks | Continuous security monitoring |
| Vulnerabilities reach production | Early detection in development |

### What Makes CodeGuard Different?

- ✅ **3-in-1 Scanner** - Websites, APIs, and Applications
- ✅ **Security Rating System** - 5-star rating with detailed metrics
- ✅ **CVE & OWASP Mapping** - Industry-standard compliance
- ✅ **Watchable History** - Clickable history with full details
- ✅ **Real-time Charts** - Visual security score trends
- ✅ **Professional Dashboard** - Cyber-security themed UI

---

## ✨ Features

### 🔍 Vulnerability Detection (9+ Types)

| # | Vulnerability | Severity | Detection Method | OWASP |
|---|---------------|----------|------------------|-------|
| 1 | eval() Usage | CRITICAL | AST Parsing | A06:2021 |
| 2 | exec() Usage | CRITICAL | AST Parsing | A06:2021 |
| 3 | SQL Injection | CRITICAL | AST + Regex | A03:2021 |
| 4 | Command Injection | HIGH | AST Parsing | A03:2021 |
| 5 | Hardcoded Secrets | HIGH | Regex | A02:2021 |
| 6 | shell=True Usage | HIGH | AST Parsing | A03:2021 |
| 7 | Unsafe Pickle | HIGH | AST Parsing | A04:2021 |
| 8 | Weak Passwords | HIGH | Regex | A02:2021 |
| 9 | Debug Mode | MEDIUM | Regex | A05:2021 |

### 🌐 Website Scanner

- SSL/TLS Certificate Validation
- Security Headers (HSTS, CSP, X-Frame-Options, etc.)
- XSS (Cross-Site Scripting) Detection
- Server Information Disclosure
- Open Ports Detection
- robots.txt Analysis

### 🔌 API Scanner

- Authentication Status (401, 403, 200)
- CORS Misconfiguration Detection
- Rate Limiting Analysis
- Security Headers Validation
- Error Message Disclosure
- Response Time Analysis

### 🖥️ Application Scanner

- IP Address & Domain Scanning
- Open Port Detection (21, 22, 80, 443, 3306, etc.)
- Admin Panel Exposure Detection
- Server Information Disclosure
- Ping/Reachability Testing

### 📊 Security Scoring

- **Score Range:** 0-100
- **Critical:** -25 points
- **High:** -15 points
- **Medium:** -8 points
- **Low:** -3 points

### ⭐ Security Rating System

| Score Range | Rating | Badge |
|-------------|--------|-------|
| 90-100 | 🌟 EXCELLENT | 🟢 |
| 70-89 | ✅ GOOD | 🟡 |
| 50-69 | ⚠️ FAIR | 🟠 |
| 30-49 | ⚠️ POOR | 🔴 |
| 0-29 | 🚨 CRITICAL | 🚨 |

### 📈 Dashboard Features

- **Real-time Stats Cards** - Total scans, average score, critical issues
- **Security Rating Stars** - 5-star rating system with animated stars
- **Score Trend Chart** - Line chart showing security score history
- **Severity Distribution** - Donut chart showing vulnerability breakdown
- **Recent Activity** - Latest scans with status indicators
- **Watchable History** - Clickable history with detailed modal view

---

## 🛠️ Technology Stack

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.9+ | Programming Language |
| **FastAPI** | 0.104.1 | Web Framework |
| **Uvicorn** | 0.24.0 | ASGI Server |
| **SQLite3** | Built-in | Database |
| **AST** | Built-in | Code Parsing |
| **Requests** | 2.31.0 | HTTP Requests |

### Frontend
| Technology | Purpose |
|------------|---------|
| **HTML5** | Page Structure |
| **CSS3** | Styling & Animation |
| **JavaScript** | Interactivity |
| **Chart.js** | Charts & Graphs |
| **Font Awesome** | Icons |

### Deployment
| Platform | Purpose |
|----------|---------|
| **Vercel** | Production Hosting |
| **GitHub** | Version Control |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/codeguard.git
cd codeguard