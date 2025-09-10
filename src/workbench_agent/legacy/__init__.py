"""
Legacy compatibility module for workbench-agent.

This module provides complete backward compatibility with the original wb-agent.py
script by embedding the inspiration codebase classes directly. It is completely
isolated from the modern refactored architecture.

Legacy users can continue using underscore-separated arguments without any changes:
  workbench-agent --project_code PROJ --scan_code SCAN --path ./src --blind_scan

This module will be removed in a future version when legacy support is discontinued.
"""

import logging
import sys
from typing import Optional

from ..exceptions import ValidationError
from .legacy_cli import parse_legacy_args
from .legacy_error_handling import agent_error_wrapper
from .legacy_scan_handler import handle_legacy_scan
from .legacy_utils import save_results
from .legacy_workbench_api import Workbench

logger = logging.getLogger("workbench-agent")


def setup_legacy_logging(log_level: str) -> logging.Logger:
    """
    Set up logging for legacy mode, maintaining compatibility with original script.

    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    numeric_level = getattr(logging, log_level.upper(), logging.ERROR)

    # Use original script's logging setup
    logger = logging.getLogger("log")
    logger.setLevel(numeric_level)

    # Add file handler (matches original script)
    f_handler = logging.FileHandler("log-agent.txt")
    logger.addHandler(f_handler)

    return logger


def print_legacy_configuration(params) -> None:
    """
    Print configuration in legacy format, matching original script output.
    Only displays parameters relevant to the legacy workflow.

    Args:
        params: Parsed command line parameters
    """
    # Define legacy-relevant parameters (from original-wb-agent.py)
    legacy_parameters = {
        # Required core parameters
        "api_url",
        "api_user",
        "api_token",
        "project_code",
        "scan_code",
        "path",
        # Optional scan parameters
        "limit",
        "sensitivity",
        "recursively_extract_archives",
        "jar_file_extraction",
        "blind_scan",
        "run_dependency_analysis",
        "run_only_dependency_analysis",
        "auto_identification_detect_declaration",
        "auto_identification_detect_copyright",
        "auto_identification_resolve_pending_ids",
        "delta_only",
        "reuse_identifications",
        "identification_reuse_type",
        "specific_code",
        "advanced_match_scoring",
        "match_filtering_threshold",
        "target_path",
        "chunked_upload",
        # Process control parameters
        "scan_number_of_tries",
        "scan_wait_time",
        "log",
        # Result collection parameters
        "get_scan_identified_components",
        "scans_get_policy_warnings_counter",
        "projects_get_policy_warnings_info",
        "scans_get_results",
        "path-result",
        # CLI-specific parameters (for blind scan)
        "cli_path",
        "config_path",
    }

    print("Parsed parameters: ")

    # Display parameters in a logical order, but only legacy-relevant ones
    for param_name in sorted(legacy_parameters):
        if hasattr(params, param_name):
            value = getattr(params, param_name)
            print("{} = {}".format(param_name, value))


def handle_legacy_main() -> int:
    """
    Main entry point for legacy compatibility mode.

    This function provides complete backward compatibility with the original
    wb-agent.py script while using the refactored components internally.

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    try:
        # Parse legacy arguments
        params = parse_legacy_args()

        # Setup logging using legacy format
        setup_legacy_logging(params.log)

        # Print configuration in legacy format
        print_legacy_configuration(params)

        # Initialize legacy Workbench API client
        logger.info("Initializing legacy Workbench API client...")
        workbench = Workbench(
            api_url=params.api_url, api_user=params.api_user, api_token=params.api_token
        )

        # Execute legacy scan workflow
        success = handle_legacy_scan(workbench, params)

        if success:
            return 0
        else:
            logger.error("Legacy scan workflow reported failure")
            return 1

    except ValidationError as e:
        print(f"Validation Error: {e}")
        logger.error(f"Validation error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1


# Export the main entry point
__all__ = ["handle_legacy_main"]
