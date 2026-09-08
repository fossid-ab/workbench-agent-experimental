"""
FossID Workbench Agent - Modular API client for automated scanning
"""

__version__ = "0.11.1"

# Import main API client
from .api.workbench_client import WorkbenchClient

__all__ = ["WorkbenchClient"]
