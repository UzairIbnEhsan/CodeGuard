"""
DATA MODELS - Pydantic models for API responses

These models define the structure of data returned by the API.
"""

from typing import List, Optional
from pydantic import BaseModel


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