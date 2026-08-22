"""
MAIN APPLICATION - FastAPI Server Entry Point
=============================================
This is the main entry point for the CodeGuard application.

COMMANDS FOR RUNNING:
---------------------
# DEVELOPMENT MODE (with auto-reload):
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# PRODUCTION MODE (without auto-reload):
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# RUN ON CUSTOM PORT:
python -m uvicorn app.main:app --reload --port 9000

# RUN WITH DEBUG LOGGING:
python -m uvicorn app.main:app --reload --log-level debug

# TEST API HEALTH:
curl http://127.0.0.1:8000/health

# VIEW API DOCUMENTATION:
# Open browser: http://127.0.0.1:8000/docs

# SCAN A FILE USING API (curl):
curl -X POST -F "file=@sample_vulnerable.py" http://127.0.0.1:8000/api/scan

# QUICK START SCRIPT:
python -c "import uvicorn; uvicorn.run('app.main:app', host='127.0.0.1', port=8000, reload=True)"
"""

import sys
import os
from pathlib import Path
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanner.engine import scan_python_code
from app.database.database import init_db, save_scan

# ============================================================
# APPLICATION SETUP
# ============================================================

# Get the base directory
BASE_DIR = Path(__file__).resolve().parent

# Set up templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ============================================================
# CREATE FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="CodeGuard",
    description="""
    🔍 AI-Powered Application Security & Vulnerability Analyzer
    
    ## Features
    - Automatic vulnerability detection
    - Security scoring
    - Remediation guidance
    - Scan history tracking
    - OWASP mapping
    
    ## Supported Checks
    - eval()/exec() usage
    - SQL Injection
    - Command Injection
    - Hardcoded secrets
    - Unsafe deserialization
    - Debug mode
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Mount static files (CSS, JS)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# ============================================================
# STARTUP EVENTS
# ============================================================

@app.on_event("startup")
def startup():
    """
    Run when the application starts.
    - Initializes the database
    - Creates necessary directories
    """
    print("\n" + "=" * 60)
    print("🛡️  CODE GUARD - APPLICATION SECURITY ANALYZER")
    print("=" * 60)
    print(f"📁 Base Directory: {BASE_DIR}")
    print(f"📊 Database: {BASE_DIR.parent / 'codeguard.db'}")
    print(f"🌐 Server: http://127.0.0.1:8000")
    print(f"📖 API Docs: http://127.0.0.1:8000/docs")
    print("=" * 60 + "\n")
    
    # Initialize database
    init_db()
    print("✅ Database initialized")

# ============================================================
# ROUTES - WEB PAGES
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Serve the main dashboard.
    
    COMMAND: Open in browser
    >>> http://127.0.0.1:8000
    """
    return templates.TemplateResponse("index.html", {"request": request})

# ============================================================
# ROUTES - API ENDPOINTS
# ============================================================

@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    """
    Scan a Python file for security vulnerabilities.
    
    COMMAND: Test with curl
    >>> curl -X POST -F "file=@sample_vulnerable.py" http://127.0.0.1:8000/api/scan
    
    COMMAND: Test with python requests
    >>> python -c "import requests; r=requests.post('http://127.0.0.1:8000/api/scan', files={'file': open('sample_vulnerable.py','rb')}); print(r.json())"
    """
    # Validate file selection
    if not file.filename:
        return JSONResponse({"error": "No file selected."}, status_code=400)
    
    # Validate file extension
    if not file.filename.lower().endswith(".py"):
        return JSONResponse(
            {"error": "MVP currently supports Python (.py) source files only."},
            status_code=400,
        )
    
    # Read file content
    raw = await file.read()
    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        return JSONResponse({"error": "File must be UTF-8 encoded."}, status_code=400)
    
    # Scan the code
    findings, score = scan_python_code(code, file.filename)
    
    # Save to database
    scan_id = save_scan(file.filename, score, findings)
    
    # Prepare response
    severity_counts = {
        "critical": sum(f["severity"] == "Critical" for f in findings),
        "high": sum(f["severity"] == "High" for f in findings),
        "medium": sum(f["severity"] == "Medium" for f in findings),
        "low": sum(f["severity"] == "Low" for f in findings),
    }
    
    return {
        "scan_id": scan_id,
        "filename": file.filename,
        "score": score,
        "summary": severity_counts,
        "findings": findings,
    }

@app.get("/api/scans")
def get_scans():
    """
    Get recent scan history.
    
    COMMAND: Test with curl
    >>> curl http://127.0.0.1:8000/api/scans
    """
    from app.database.database import get_recent_scans
    return {"scans": get_recent_scans(20)}

@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int):
    """
    Get a specific scan by ID.
    
    COMMAND: Test with curl
    >>> curl http://127.0.0.1:8000/api/scan/1
    """
    from app.database.database import get_scan_by_id
    result = get_scan_by_id(scan_id)
    if result:
        return result
    return JSONResponse({"error": "Scan not found"}, status_code=404)

# ============================================================
# ROUTES - HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    """
    Health check endpoint.
    
    COMMAND: Test with curl
    >>> curl http://127.0.0.1:8000/health
    
    COMMAND: Test in browser
    >>> http://127.0.0.1:8000/health
    """
    return {
        "status": "ok",
        "project": "CodeGuard",
        "version": "1.0.0",
        "author": "Uzair Ehsan"
    }

# ============================================================
# MAIN ENTRY POINT
# ============================================================

# For running directly: python app/main.py
if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Starting CodeGuard Server...")
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
    # Add this at the very end of app/main.py
# ============================================================
# For Vercel deployment - Vercel looks for 'app' variable
# ============================================================

# Vercel expects the FastAPI app to be named 'app'
# Your app is already named 'app', so this is ready!

# Optional: Add this handler for serverless environment
async def handler(request, **kwargs):
    """Vercel serverless function handler"""
    from mangum import Mangum
    handler = Mangum(app)
    return await handler(request, **kwargs)