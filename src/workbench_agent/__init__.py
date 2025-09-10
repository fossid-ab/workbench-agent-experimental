"""
FossID Workbench Agent - Modular API client for automated scanning
"""

__version__ = "0.8.0"

# Import main API class
from .api import WorkbenchAPI

# Keep backward compatibility by creating an alias
Workbench = WorkbenchAPI
