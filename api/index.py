"""
Vercel Serverless Function Entry Point
This file is the entry point for Vercel deployment.
"""
import sys
from pathlib import Path

# Add the parent directory to Python path so we can import app
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.main import app

# Vercel expects a handler named 'app'
# FastAPI app is already named 'app' in main.py

# For Vercel serverless functions
handler = app