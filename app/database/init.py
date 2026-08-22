"""
DATABASE PACKAGE - Data Storage Module
=====================================

This package handles all database operations.

COMMANDS TO TEST:
----------------
# Test import:
python -c "from app.database import database; print('✅ Database package loaded')"

# Initialize database:
python -c "from app.database.database import init_db; init_db(); print('✅ Database initialized')"
"""

from app.database.database import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    delete_scan,
    delete_all_scans,
    get_scan_statistics,
)

__all__ = [
    'init_db',
    'save_scan',
    'get_recent_scans',
    'get_scan_by_id',
    'delete_scan',
    'delete_all_scans',
    'get_scan_statistics',
]