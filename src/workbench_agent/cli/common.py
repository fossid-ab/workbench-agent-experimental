# workbench_agent/cli/common.py

import logging
from typing import Set

logger = logging.getLogger("workbench-agent")

# --- Shared Constants ---
KNOWN_SUBCOMMANDS: Set[str] = {
    "scan",
    "blind-scan",
    "import-da",
    "import-sbom",
    "show-results",
    "evaluate-gates",
    "download-reports",
    "scan-git",
}

LEGACY_INDICATORS: Set[str] = {
    "--project_code",
    "--scan_code",
    "--blind_scan",
    "--api_url",
    "--api_user",
    "--api_token",
    "--path-result",
    "--run_dependency_analysis",
    "--identification_reuse_type",
}


# --- Detection Functions ---
def uses_modern_interface(args: list) -> bool:
    """
    Detect if modern command-based interface is being used.

    Args:
        args: List of command line arguments (typically sys.argv[1:])

    Returns:
        bool: True if modern interface detected, False for legacy
    """
    return any(arg in KNOWN_SUBCOMMANDS for arg in args)


def uses_legacy_interface(args: list) -> bool:
    """
    Detect if legacy underscore-based interface is being used.

    Args:
        args: List of command line arguments (typically sys.argv[1:])

    Returns:
        bool: True if legacy interface detected, False for modern
    """
    for arg in args:
        arg_name = arg.split("=")[0]
        if arg_name in LEGACY_INDICATORS:
            return True
    return False
