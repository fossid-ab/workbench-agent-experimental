# workbench_agent/handlers/show_results.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.exceptions import (
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ValidationError,
)
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.scan_workflows import fetch_display_save_results

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_show_results(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'show-results' command. Fetches and displays results for an existing scan.

    Args:
        workbench: The Workbench API client
        params: Command line parameters

    Returns:
        bool: True if the operation was successful
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Validate that at least one show flag is provided
    show_flags = [
        params.show_licenses,
        params.show_components,
        params.show_dependencies,
        params.show_scan_metrics,
        params.show_policy_warnings,
        params.show_vulnerabilities,
    ]
    if not any(show_flags):
        raise ValidationError("At least one '--show-*' flag must be provided to display results")

    # Resolve project and scan (find only)
    print("\nResolving scan for results display...")
    project_code = workbench.resolve_project(params.project_name, create_if_missing=False)
    scan_code, _ = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=False,
        params=params,
    )

    # Ensure scan processes are idle before fetching results
    print("\nEnsuring scans finished before showing results...")
    try:
        workbench.check_and_wait_for_process(
            process_types=["SCAN", "DEPENDENCY_ANALYSIS"],
            scan_code=scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )

    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        logger.warning(
            f"Could not verify scan completion for '{scan_code}': {e}. Proceeding anyway."
        )
        print("\nWarning: Could not verify scan completion status. Results may be incomplete.")

    # Fetch and display results
    print(f"\nFetching results for scan '{scan_code}'...")
    fetch_display_save_results(workbench, params, scan_code)

    return True
