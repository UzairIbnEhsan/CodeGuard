"""
SCANNER PACKAGE - Security Analysis Module
==========================================

This package contains all security scanning functionality.

COMMANDS TO TEST:
----------------
# Test import:
python -c "from app.scanner import engine, rules; print('✅ Scanner package loaded')"

# Check available rules:
python -c "from app.scanner.rules import RULES; print(f'Available rules: {len(RULES)}')"

# Test engine:
python -c "from app.scanner.engine import scan_python_code; print('✅ Engine loaded')"
"""

from app.scanner.engine import scan_python_code
from app.scanner.rules import RULES, SEVERITY_WEIGHTS

__all__ = ['scan_python_code', 'RULES', 'SEVERITY_WEIGHTS']