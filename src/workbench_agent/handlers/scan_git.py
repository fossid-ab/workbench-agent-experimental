# workbench_agent/handlers/scan_git.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.exceptions import ProcessError, ProcessTimeoutError, WorkbenchAgentError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.scan_target_validators import (
    ensure_scan_compatibility,
    validate_reuse_source,
)
from workbench_agent.api.helpers.scan_operations_api import ScanOperationsAPI
from workbench_agent.utilities.scan_workflows import (
    determine_scans_to_run,
    fetch_display_save_results,
    print_operation_summary,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

logger = logging.getLogger("workbench-agent")


def _get_project_and_scan_codes(
    workbench: "WorkbenchAPI", params: argparse.Namespace
) -> tuple[str, str]:
    """
    Resolve project and scan codes for git scan.

    Args:
        workbench: The Workbench API client instance
        params: Command line parameters

    Returns:
        tuple[str, str]: Project code and scan code
    """
    project_code = workbench.resolve_project(params.project_name, create_if_missing=True)
    scan_code, _ = workbench.resolve_scan(
        params.scan_name, params.project_name, create_if_missing=True, params=params
    )
    return project_code, scan_code


@handler_error_wrapper
def handle_scan_git(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-git' command. Triggers a scan on code directly from Git.

    Args:
        workbench: The Workbench API client instance
        params: Command line parameters

    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Initialize timing dictionary
    durations = {"kb_scan": 0.0, "dependency_analysis": 0.0, "git_clone": 0.0}

    # Translate new CLI arguments to internal format and validate ID reuse source
    api_helper = ScanOperationsAPI(workbench.api_url, workbench.api_user, workbench.api_token)
    id_reuse, id_reuse_type, id_reuse_source = api_helper.translate_reuse_arguments(params)

    # Validate ID reuse source if reuse is enabled - WARN if it cannot be validated
    api_reuse_type = None
    resolved_specific_code_for_reuse = None
    if id_reuse:
        print("\nValidating ID reuse source before proceeding...")
        # Set the translated values on params for validation
        params.id_reuse = id_reuse
        params.id_reuse_type = id_reuse_type
        params.id_reuse_source = id_reuse_source

        try:
            api_reuse_type, resolved_specific_code_for_reuse = validate_reuse_source(
                workbench, params
            )
            print("Successfully validated ID reuse source.")
        except Exception as e:
            # Log the error but don't show additional warnings since validate_reuse_source already shows them
            logger.warning(
                f"ID reuse validation failed ({type(e).__name__}): {e}. Continuing without ID reuse."
            )
            # Disable ID reuse for this scan
            id_reuse = False
            params.id_reuse = False

    # Resolve project and scan (find or create)
    print("\nChecking if the Project and Scan exist or need to be created...")
    project_code, scan_code = _get_project_and_scan_codes(workbench, params)

    print(f"Processing git scan for scan '{scan_code}' in project '{project_code}'...")

    # Ensure scan is compatible with the current operation
    ensure_scan_compatibility(workbench, params, scan_code)

    # Ensure scan is idle before triggering Git clone
    print("\nEnsuring the Scan is idle before triggering Git clone...")
    workbench.check_and_wait_for_process(
        process_types=["GIT_CLONE", "SCAN", "DEPENDENCY_ANALYSIS"],
        scan_code=scan_code,
        max_tries=params.scan_number_of_tries,
        wait_interval=params.scan_wait_time,
    )

    # Trigger Git clone
    git_ref_type = "tag" if params.git_tag else ("commit" if params.git_commit else "branch")
    git_ref_value = params.git_tag or params.git_commit or params.git_branch
    print(f"\nCloning the '{params.git_url}' repository using {git_ref_type}: '{git_ref_value}'.")

    # Download content from Git
    try:
        workbench.download_content_from_git(scan_code)
        git_clone_status = workbench.check_and_wait_for_process(
            process_types="GIT_CLONE",
            scan_code=scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=3,  # hardcoded wait time since git clone finishes quickly
        )
        # Store git clone duration
        durations["git_clone"] = git_clone_status.duration or 0.0
        print(f"\nSuccessfully cloned Git repository from {params.git_url}")
    except Exception as e:
        logger.error(f"Failed to clone Git repository for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchAgentError(
            f"Failed to clone Git repository: {e}", details={"error": str(e)}
        ) from e

    # Remove .git directory before starting scan
    print("\nRemoving .git directory to optimize scan...")
    try:
        if workbench.remove_uploaded_content(scan_code, ".git/"):
            print("Successfully removed .git directory.")
    except Exception as e:
        logger.warning(f"Error removing .git directory: {e}. Continuing with scan...")
        print(f"Warning: Error removing .git directory: {e}. Continuing with scan...")

    # Determine which scan operations to run
    scan_operations = determine_scans_to_run(params)

    # Run KB Scan
    scan_completed = False
    da_completed = False

    try:
        # Verify scan can start
        workbench.check_and_wait_for_process(
            process_types=["GIT_CLONE", "SCAN", "DEPENDENCY_ANALYSIS"],
            scan_code=scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )

        # Handle dependency analysis only mode
        if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
            print("\nStarting Dependency Analysis only (skipping KB scan)...")
            workbench.start_dependency_analysis(scan_code, import_only=False)

            # Handle no-wait mode
            if getattr(params, "no_wait", False):
                print("Dependency Analysis has been started.")
                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the status later using the 'show-results' command.")
                print_operation_summary(params, True, project_code, scan_code, durations)
                return True

            # Wait for dependency analysis to complete
            try:
                dependency_analysis_status = workbench.check_and_wait_for_process(
                    process_types="DEPENDENCY_ANALYSIS",
                    scan_code=scan_code,
                    max_tries=params.scan_number_of_tries,
                    wait_interval=params.scan_wait_time,
                )

                # Store the duration
                durations["dependency_analysis"] = dependency_analysis_status.duration or 0.0
                da_completed = True

                # We didn't run a KB scan but we'll mark it as completed for result processing
                scan_completed = True

                # Print operation summary
                print_operation_summary(params, da_completed, project_code, scan_code, durations)

                # Show results
                fetch_display_save_results(workbench, params, scan_code)

                return True

            except Exception as e:
                logger.error(
                    f"Error waiting for dependency analysis to complete: {e}", exc_info=True
                )
                print(f"\nError: Dependency analysis failed: {e}")
                return False

        # Start the KB scan (only if run_kb_scan is True)
        if scan_operations["run_kb_scan"]:
            print("\nStarting KB Scan Process...")
            workbench.run_scan(
                scan_code,
                params.limit,
                params.sensitivity,
                params.autoid_file_licenses,
                params.autoid_file_copyrights,
                params.autoid_pending_ids,
                params.delta_scan,
                id_reuse,
                api_reuse_type if id_reuse else None,
                resolved_specific_code_for_reuse if id_reuse else None,
                run_dependency_analysis=scan_operations["run_dependency_analysis"],
            )

            # Check if no-wait mode is enabled - if so, exit early
            if getattr(params, "no_wait", False):
                print("\nKB Scan started successfully.")
                if scan_operations["run_dependency_analysis"]:
                    print("Dependency Analysis will automatically start after scan completion.")

                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the scan status later using the 'show-results' command.")
                print_operation_summary(params, True, project_code, scan_code, durations)
                return True
            else:
                # Determine which processes to wait for
                process_types_to_wait = ["SCAN"]
                if scan_operations["run_dependency_analysis"]:
                    process_types_to_wait.append("DEPENDENCY_ANALYSIS")

                print(f"\nWaiting for {', '.join(process_types_to_wait)} to complete...")

                try:
                    # Wait for all requested processes using unified interface
                    results = workbench.check_and_wait_for_process(
                        process_types=process_types_to_wait,
                        scan_code=scan_code,
                        max_tries=params.scan_number_of_tries,
                        wait_interval=params.scan_wait_time,
                        should_track_files=True,  # Will apply to SCAN process
                    )

                    # Extract individual results (results is Dict[str, WaitResult])
                    kb_scan_status = results["SCAN"]
                    durations["kb_scan"] = kb_scan_status.duration or 0.0
                    scan_completed = True

                    if "DEPENDENCY_ANALYSIS" in results:
                        dependency_analysis_status = results["DEPENDENCY_ANALYSIS"]
                        if not dependency_analysis_status.success:
                            logger.warning(
                                f"Error in dependency analysis: {dependency_analysis_status.error_message}"
                            )
                            print(
                                f"\nWarning: Error waiting for dependency analysis to complete: {dependency_analysis_status.error_message}"
                            )
                            da_completed = False
                        else:
                            durations["dependency_analysis"] = (
                                dependency_analysis_status.duration or 0.0
                            )
                            da_completed = True
                    else:
                        da_completed = False

                except Exception as e:
                    logger.error(f"Error waiting for processes to complete: {e}", exc_info=True)
                    print(f"\nError: Process failed: {e}")
                    scan_completed = False
                    da_completed = False

    except (ProcessTimeoutError, ProcessError) as e:
        scan_completed = False
        raise
    except Exception as e:
        scan_completed = False
        logger.error(f"Error during KB scan for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchAgentError(f"Error during KB scan: {e}", details={"error": str(e)}) from e

    # Process completed operations
    if scan_completed:
        # Print operation summary
        print_operation_summary(params, da_completed, project_code, scan_code, durations)

        # Check for pending files (informational)
        try:
            pending_files = workbench.get_pending_files(scan_code)
            if pending_files:
                print(f"\nNote: {len(pending_files)} files are Pending Identification.")
            else:
                print("\nNote: No files are Pending Identification.")
        except Exception as e:
            logger.warning(f"Could not retrieve pending file count: {e}")
            print(f"\nWarning: Could not retrieve pending file count: {e}")

    # Fetch and display results if scan completed successfully
    if scan_completed or da_completed:
        fetch_display_save_results(workbench, params, scan_code)
    else:
        print("\nSkipping result fetching since scan did not complete successfully.")

    return scan_completed or da_completed
