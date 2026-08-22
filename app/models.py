"""
DATA MODELS - Pydantic Models for API

============================================================
COMMANDS:
============================================================
# Test model creation:
python -c "from app.models import Finding; f=Finding(title='Test', category='Security', severity='High', file='test.py', line=1, snippet='code', description='desc', impact='impact', recommendation='fix'); print(f'✅ Model created: {f.title}')"

# Test scan response:
python -c "from app.models import ScanResponse; print('✅ Models imported successfully')"

============================================================
PURPOSE: Define data structures for API responses
============================================================
"""

from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime


class Finding(BaseModel):
    """Represents a security finding"""
    title: str
    category: str
    severity: str
    file: str
    line: int
    snippet: str
    description: str
    impact: str
    recommendation: str
    
    class Config:
        """Pydantic config"""
        schema_extra = {
            "example": {
                "title": "SQL Injection",
                "category": "Injection",
                "severity": "Critical",
                "file": "app.py",
                "line": 42,
                "snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
                "description": "SQL appears to be built using concatenation",
                "impact": "Could allow unauthorized database access",
                "recommendation": "Use parameterized queries"
            }
        }


class ScanResponse(BaseModel):
    """Response model for scan endpoint"""
    scan_id: int
    filename: str
    score: int
    summary: dict
    findings: List[Finding]


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    project: str
    version: str
    timestamp: datetime


class ScanHistory(BaseModel):
    """Scan history item"""
    id: int
    filename: str
    score: int
    created_at: str


# ============================================================
# QUICK TEST COMMAND (uncomment to test)
# ============================================================
# if __name__ == "__main__":
#     # Test finding creation
#     test_finding = Finding(
#         title="Test Vulnerability",
#         category="Security",
#         severity="High",
#         file="test.py",
#         line=1,
#         snippet="test code",
#         description="Test description",
#         impact="Test impact",
#         recommendation="Test fix"
#     )
#     print(f"✅ Finding model works: {test_finding.title}")