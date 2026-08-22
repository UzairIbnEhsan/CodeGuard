"""
SECURITY RULES DATABASE
=======================
This file defines all security rules that CodeGuard checks for.

COMMANDS TO VIEW RULES:
----------------------
# List all rules:
python -c "from app.scanner.rules import RULES; print('\n'.join(RULES.keys()))"

# Get rule details:
python -c "from app.scanner.rules import RULES; import json; print(json.dumps(RULES['eval'], indent=2))"

# Count total rules:
python -c "from app.scanner.rules import RULES; print(f'Total rules: {len(RULES)}')"

# List rules by severity:
python -c "from app.scanner.rules import RULES; critical=[k for k,v in RULES.items() if v['severity']=='Critical']; print(f'Critical: {critical}')"

# Show all severities:
python -c "from app.scanner.rules import SEVERITY_WEIGHTS; print(SEVERITY_WEIGHTS)"

# Export rules to JSON:
python -c "from app.scanner.rules import RULES; import json; print(json.dumps(RULES, indent=2))"
"""

# ============================================================
# RULES DATABASE
# ============================================================

RULES = {
    "eval": {
        "title": "Dangerous eval() Usage",
        "category": "Code Execution",
        "severity": "Critical",
        "description": "eval() can execute dynamically supplied Python expressions and may allow unintended code execution when input is attacker-controlled.",
        "impact": "Potential arbitrary code execution. An attacker could run any Python code on your server.",
        "recommendation": "Avoid eval(). Use explicit parsing or a safe allow-list of supported operations. Consider using ast.literal_eval() for safe evaluation.",
    },
    "exec": {
        "title": "Dangerous exec() Usage",
        "category": "Code Execution",
        "severity": "Critical",
        "description": "exec() dynamically executes Python code and is dangerous when the executed content is not fully trusted.",
        "impact": "Potential arbitrary code execution. Attackers can execute any Python code.",
        "recommendation": "Avoid exec() for untrusted or user-controlled input. Use alternative approaches like dictionaries or allow-lists.",
    },
    "os.system": {
        "title": "Potential Command Injection",
        "category": "Injection",
        "severity": "High",
        "description": "os.system() executes an operating-system command. Risk increases when command data comes from users or external input.",
        "impact": "An attacker may influence command execution and run arbitrary system commands.",
        "recommendation": "Prefer subprocess with a fixed argument list and validate all external input. Use shlex.quote() if necessary.",
    },
    "subprocess_shell": {
        "title": "Shell Execution Risk",
        "category": "Injection",
        "severity": "High",
        "description": "subprocess calls using shell=True can make command construction dangerous when input is not strictly controlled.",
        "impact": "Potential command injection. Attackers can inject shell commands.",
        "recommendation": "Avoid shell=True where possible and pass arguments as a list. Use subprocess.run(['command', arg1, arg2]) instead.",
    },
    "hardcoded_secret": {
        "title": "Possible Hardcoded Secret",
        "category": "Cryptographic Failures",
        "severity": "High",
        "description": "A variable appears to contain a password, token, API key, or secret directly in source code.",
        "impact": "Credentials may be exposed through source control, logs, or application packages. Attackers can access sensitive data.",
        "recommendation": "Use environment variables or a dedicated secret manager and rotate exposed credentials immediately.",
    },
    "sql_concat": {
        "title": "Potential SQL Injection",
        "category": "Injection",
        "severity": "Critical",
        "description": "A SQL statement appears to be constructed using string concatenation or interpolation.",
        "impact": "Potential unauthorized database access or modification. Attackers can read, modify, or delete data.",
        "recommendation": "Use parameterized queries or a secure ORM query interface. Never concatenate user input into SQL.",
    },
    "pickle": {
        "title": "Unsafe Deserialization Risk",
        "category": "Insecure Design",
        "severity": "High",
        "description": "Python pickle deserialization can execute attacker-controlled code when untrusted data is loaded.",
        "impact": "Potential arbitrary code execution. Malicious pickle data can run system commands.",
        "recommendation": "Do not deserialize untrusted pickle data. Prefer a safe data format such as JSON. Use a secure deserialization library.",
    },
    "debug": {
        "title": "Debug Mode Enabled",
        "category": "Security Misconfiguration",
        "severity": "Medium",
        "description": "Debug mode appears to be enabled in application code.",
        "impact": "Detailed errors and internal information may be exposed to users. Stack traces can reveal sensitive system information.",
        "recommendation": "Disable debug mode in production and use environment-based configuration. Use logging for debugging in production.",
    },
    "weak_password": {
        "title": "Weak Password Detected",
        "category": "Cryptographic Failures",
        "severity": "High",
        "description": "A weak, easily guessable password appears in the code.",
        "impact": "Accounts using weak passwords are easily compromised.",
        "recommendation": "Use strong passwords (12+ characters with mixed case, numbers, symbols). Never hardcode passwords.",
    },
}

# ============================================================
# SEVERITY WEIGHTS FOR SCORE CALCULATION
# ============================================================

SEVERITY_WEIGHTS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
}

# ============================================================
# ADDITIONAL RULE METADATA
# ============================================================

# Number of rules by severity
RULES_BY_SEVERITY = {}
for rule_key, rule in RULES.items():
    severity = rule["severity"]
    if severity not in RULES_BY_SEVERITY:
        RULES_BY_SEVERITY[severity] = []
    RULES_BY_SEVERITY[severity].append(rule_key)

# ============================================================
# TEST: Print rule summary
# ============================================================

if __name__ == "__main__":
    print("\n📋 CODE GUARD - RULES SUMMARY")
    print("=" * 50)
    print(f"Total Rules: {len(RULES)}")
    print("\nRules by Severity:")
    for severity, rules in RULES_BY_SEVERITY.items():
        print(f"  [{severity}] {len(rules)} rules: {', '.join(rules)}")
    print("\nSeverity Weights:")
    for severity, weight in SEVERITY_WEIGHTS.items():
        print(f"  {severity}: -{weight} points")
    print("\n" + "=" * 50)