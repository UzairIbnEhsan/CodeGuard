"""
SCANNER ENGINE - Core Security Analysis
=======================================
This module parses Python code using AST (Abstract Syntax Tree)
and detects security vulnerabilities.

COMMANDS FOR SCANNER:
---------------------
# Test scanner on vulnerable file:
python -c "from app.scanner.engine import scan_python_code; code=open('sample_vulnerable.py').read(); findings,score=scan_python_code(code,'sample_vulnerable.py'); print(f'Score: {score}'); print(f'Findings: {len(findings)}')"

# Test scanner on safe file:
python -c "from app.scanner.engine import scan_python_code; code=open('sample_safe.py').read(); findings,score=scan_python_code(code,'sample_safe.py'); print(f'Score: {score}'); print(f'Findings: {len(findings)}')"

# Show detailed findings:
python -c "from app.scanner.engine import scan_python_code; import json; code=open('sample_vulnerable.py').read(); findings,score=scan_python_code(code,'sample_vulnerable.py'); print(json.dumps(findings, indent=2))"

# Test scanner with custom code:
python -c "from app.scanner.engine import scan_python_code; code='''password=\"secret\"\nprint(\"hello\")'''; findings,score=scan_python_code(code,'test.py'); print(f'Score: {score}')"

# Count vulnerabilities by severity:
python -c "from app.scanner.engine import scan_python_code; code=open('sample_vulnerable.py').read(); findings,score=scan_python_code(code,'sample_vulnerable.py'); from collections import Counter; print(Counter(f['severity'] for f in findings))"
"""

import ast
import re
from typing import List, Dict, Tuple
from app.scanner.rules import RULES, SEVERITY_WEIGHTS

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def make_finding(rule_key, filename, line, snippet=""):
    """
    Create a finding object from a rule.
    
    Args:
        rule_key (str): Key in RULES dictionary
        filename (str): Name of the file
        line (int): Line number
        snippet (str): Code snippet
    
    Returns:
        dict: Finding object with all details
    """
    rule = RULES.get(rule_key, RULES.get('unknown'))
    
    # If rule not found, use unknown rule
    if rule is None:
        rule = {
            "title": "Unknown Vulnerability",
            "category": "Unknown",
            "severity": "Low",
            "description": "Unknown vulnerability pattern detected.",
            "impact": "Unknown impact.",
            "recommendation": "Review the code manually."
        }
    
    # Get OWASP mapping
    from app.config import config
    owasp = config.OWASP_MAPPING.get(rule["category"], "A06:2021 Vulnerable and Outdated Components")
    
    return {
        "title": rule["title"],
        "category": rule["category"],
        "severity": rule["severity"],
        "file": filename,
        "line": line,
        "snippet": snippet.strip()[:240],
        "description": rule["description"],
        "impact": rule["impact"],
        "recommendation": rule["recommendation"],
        "owasp": owasp,
    }

# ============================================================
# MAIN SCANNER FUNCTION
# ============================================================

def scan_python_code(code: str, filename: str = "uploaded.py") -> Tuple[List[Dict], int]:
    """
    Scan Python code for security vulnerabilities.
    
    Args:
        code (str): Python source code
        filename (str): Name of the file (for reporting)
    
    Returns:
        Tuple[List[Dict], int]: (findings_list, security_score)
    
    How it works:
        1. Parse code into AST (Abstract Syntax Tree)
        2. Walk through the AST nodes
        3. Check for dangerous patterns
        4. Use regex for patterns AST can't detect
        5. Remove duplicates
        6. Calculate security score
    """
    findings = []
    lines = code.splitlines()
    total_lines = len(lines)
    
    # ============================================================
    # AST-BASED DETECTION (Most Accurate)
    # ============================================================
    
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        # Handle syntax errors gracefully
        findings.append({
            "title": "Python Syntax Error",
            "category": "Code Quality",
            "severity": "Medium",
            "file": filename,
            "line": exc.lineno or 1,
            "snippet": (lines[(exc.lineno or 1) - 1] if lines else ""),
            "description": "The scanner could not fully parse the Python file because it contains a syntax error.",
            "impact": "The application may fail to run and security analysis may be incomplete.",
            "recommendation": "Fix the syntax error and scan the file again.",
            "owasp": "N/A",
        })
        return findings, 92
    
    # Walk through AST
    for node in ast.walk(tree):
        # Check for Call nodes (function calls)
        if isinstance(node, ast.Call):
            
            # --- Check for eval() ---
            if isinstance(node.func, ast.Name) and node.func.id == "eval":
                findings.append(make_finding("eval", filename, node.lineno, lines[node.lineno - 1]))
            
            # --- Check for exec() ---
            if isinstance(node.func, ast.Name) and node.func.id == "exec":
                findings.append(make_finding("exec", filename, node.lineno, lines[node.lineno - 1]))
            
            # --- Check for os.system() ---
            if (isinstance(node.func, ast.Attribute)
                and node.func.attr == "system"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"):
                findings.append(make_finding("os.system", filename, node.lineno, lines[node.lineno - 1]))
            
            # --- Check for subprocess(..., shell=True) ---
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "run", "Popen", "call", "check_call", "check_output"
            }:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(make_finding(
                            "subprocess_shell", filename, node.lineno, lines[node.lineno - 1]
                        ))
                        break
            
            # --- Check for pickle.loads() / pickle.load() ---
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"load", "loads"}:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                    findings.append(make_finding("pickle", filename, node.lineno, lines[node.lineno - 1]))
    
    # ============================================================
    # REGEX-BASED DETECTION (For patterns AST misses)
    # ============================================================
    
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        
        # --- Hardcoded Secrets ---
        secret_pattern = re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*=\s*['\"][^'\"]{4,}['\"]"
        )
        if secret_pattern.search(stripped):
            findings.append(make_finding("hardcoded_secret", filename, i, line))
        
        # --- SQL Injection ---
        sql_pattern = re.compile(
            r"(?i)(select|insert|update|delete)\b.*(\+|%|\{[^}]+\})"
        )
        if sql_pattern.search(stripped):
            findings.append(make_finding("sql_concat", filename, i, line))
        
        # --- Debug Mode ---
        if re.search(r"(?i)\bdebug\s*=\s*true\b", stripped):
            findings.append(make_finding("debug", filename, i, line))
        
        # --- Weak Password Check (Bonus) ---
        weak_password_pattern = re.compile(
            r"(?i)password\s*=\s*['\"](123456|password|admin|qwerty|letmein|welcome)['\"]"
        )
        if weak_password_pattern.search(stripped):
            findings.append(make_finding("weak_password", filename, i, line))
    
    # ============================================================
    # REMOVE DUPLICATES
    # ============================================================
    
    unique = []
    seen = set()
    for f in findings:
        key = (f["title"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    # ============================================================
    # CALCULATE SECURITY SCORE
    # ============================================================
    
    score = 100
    for finding in unique:
        score -= SEVERITY_WEIGHTS.get(finding["severity"], 5)
    score = max(0, min(100, score))
    
    # ============================================================
    # PRINT SUMMARY
    # ============================================================
    
    if unique:
        print(f"\n📊 SCAN RESULTS for {filename}:")
        print(f"   • Findings: {len(unique)}")
        print(f"   • Score: {score}/100")
        for f in unique:
            print(f"   • [{f['severity']}] {f['title']} at line {f['line']}")
    
    return unique, score

# ============================================================
# TEST FUNCTION
# ============================================================

if __name__ == "__main__":
    """Test the scanner on sample files"""
    print("\n🔍 Running Scanner Tests...\n")
    
    # Test 1: Vulnerable file
    print("=" * 50)
    print("TEST 1: sample_vulnerable.py")
    print("=" * 50)
    try:
        with open("sample_vulnerable.py", "r") as f:
            code = f.read()
        findings, score = scan_python_code(code, "sample_vulnerable.py")
        print(f"✅ Score: {score}/100")
        print(f"   Findings: {len(findings)}")
        for f in findings:
            print(f"   - [{f['severity']}] {f['title']} (line {f['line']})")
    except FileNotFoundError:
        print("❌ sample_vulnerable.py not found")
    
    print("\n")
    
    # Test 2: Safe file
    print("=" * 50)
    print("TEST 2: sample_safe.py")
    print("=" * 50)
    try:
        with open("sample_safe.py", "r") as f:
            code = f.read()
        findings, score = scan_python_code(code, "sample_safe.py")
        print(f"✅ Score: {score}/100")
        print(f"   Findings: {len(findings)}")
        for f in findings:
            print(f"   - [{f['severity']}] {f['title']} (line {f['line']})")
    except FileNotFoundError:
        print("❌ sample_safe.py not found")
    
    print("\n✅ Scanner tests complete!")