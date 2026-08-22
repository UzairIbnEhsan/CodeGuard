"""
CONFIGURATION - Application Settings
====================================
Loads configuration from environment variables and provides default values.

COMMANDS FOR THIS FILE:
-----------------------
# Test configuration:
python -c "from app.config import config; print(f'Project: {config.PROJECT_NAME}, Version: {config.VERSION}')"

# Check if debug mode is enabled:
python -c "from app.config import config; print(f'Debug mode: {config.DEBUG}')"

# List all config values:
python -c "from app.config import config; print(config.__dict__)"
"""

import os
from pathlib import Path

# Try to load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed - using environment variables directly
    pass

class Config:
    """
    Application configuration class.
    
    Reads settings from environment variables with fallback defaults.
    """
    
    # ============================================================
    # PROJECT INFORMATION
    # ============================================================
    PROJECT_NAME = os.getenv("PROJECT_NAME", "CodeGuard")
    VERSION = os.getenv("VERSION", "1.0.0")
    
    # ============================================================
    # ENVIRONMENT SETTINGS
    # ============================================================
    # Set DEBUG=True for development, False for production
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    
    # Secret key for sessions (change in production!)
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production-12345")
    
    # ============================================================
    # DATABASE SETTINGS
    # ============================================================
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./codeguard.db")
    
    # ============================================================
    # FILE UPLOAD SETTINGS
    # ============================================================
    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 10485760))  # 10MB
    ALLOWED_EXTENSIONS = {'.py'}  # Only Python files
    UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
    
    # Create upload directory if it doesn't exist
    UPLOAD_DIR.mkdir(exist_ok=True)
    
    # ============================================================
    # SECURITY SETTINGS
    # ============================================================
    SEVERITY_WEIGHTS = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3
    }
    
    # OWASP Category Mapping
    OWASP_MAPPING = {
        "Injection": "A03:2021 Injection",
        "Cryptographic Failures": "A02:2021 Cryptographic Failures",
        "Security Misconfiguration": "A05:2021 Security Misconfiguration",
        "Code Execution": "A06:2021 Vulnerable and Outdated Components",
        "Insecure Design": "A04:2021 Insecure Design",
        "Secrets Management": "A02:2021 Cryptographic Failures"
    }
    
    def __repr__(self):
        """Show configuration when printed"""
        return f"""
        <Config>
        Project: {self.PROJECT_NAME}
        Version: {self.VERSION}
        Debug: {self.DEBUG}
        Database: {self.DATABASE_URL}
        Max File Size: {self.MAX_FILE_SIZE/1024/1024}MB
        Allowed Extensions: {self.ALLOWED_EXTENSIONS}
        """

# Create a global config instance
config = Config()

# Command to see configuration
if __name__ == "__main__":
    print(config)