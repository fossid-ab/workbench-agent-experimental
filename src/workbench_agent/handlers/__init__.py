import logging
from .blind_scan import handle_blind_scan
from .download_reports import handle_download_reports
from .evaluate_gates import handle_evaluate_gates
from .import_da import handle_import_da
from .import_sbom import handle_import_sbom
from .quick_scan import handle_quick_scan
from .scan import handle_scan
from .scan_git import handle_scan_git
from .show_results import handle_show_results

# Common logger for all handlers
logger = logging.getLogger("workbench-agent")

__all__ = [
    "handle_scan",
    "handle_scan_git",
    "handle_blind_scan",
    "handle_import_da",
    "handle_import_sbom",
    "handle_show_results",
    "handle_evaluate_gates",
    "handle_download_reports",
    "handle_quick_scan",
]
