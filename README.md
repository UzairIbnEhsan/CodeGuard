# 🛡️ CodeGuard - AI-Powered Application Security & Vulnerability Analyzer

**Version:** 1.0.0  
**Developer:** Uzair Ehsan  
**Status:** Production Ready MVP

---

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Commands Reference](#commands-reference)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Future Roadmap](#future-roadmap)

---

## 📌 Overview

CodeGuard is an automated security analysis platform that detects vulnerabilities in Python applications using AST (Abstract Syntax Tree) parsing and pattern matching. It provides:

- 🔍 **8+ Vulnerability Detections**
- 📊 **Security Scoring (0-100)**
- 🎯 **Severity Classification**
- 💡 **Remediation Guidance**
- 📈 **Scan History Tracking**
- 🌐 **Web Dashboard**

---

## ✨ Features

### Vulnerability Detection
| Vulnerability | Severity | Detection Method |
|---------------|----------|------------------|
| eval() Usage | Critical | AST Parsing |
| exec() Usage | Critical | AST Parsing |
| SQL Injection | Critical | AST + Regex |
| Command Injection | High | AST Parsing |
| Hardcoded Secrets | High | Regex |
| Unsafe Pickle | High | AST Parsing |
| Debug Mode | Medium | Regex |
| Weak Passwords | High | Regex |

### Security Scoring
- Start: 100/100
- Critical: -25 points
- High: -15 points
- Medium: -8 points
- Low: -3 points

---

## 🚀 Quick Start

### 1. Clone/Download the Project
```bash
git clone https://github.com/yourusername/codeguard.git
cd codeguard