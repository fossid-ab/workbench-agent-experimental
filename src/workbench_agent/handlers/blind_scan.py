import argparse
import logging
import os
import time

from workbench_agent.api.workbench_api import WorkbenchAPI
from workbench_agent.exceptions import FileSystemError, ValidationError
from workbench_agent.utilities.cli_wrapper import CliWrapper
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.scan_target_validators import (
    ensure_scan_compatibility,
    validate_reuse_source,
)
from workbench_agent.api.helpers.scan_operations_api import ScanOperationsAPI
from workbench_agent.utilities.scan_workflows import (
    determine_scans_to_run,
    fetch_display_save_results,
    format_duration,
    print_operation_summary,
)

logger = logging.getLogger("workbench-agent")


def cleanup_temp_file(file_path: str) -> bool:
    """
    Clean up a temporary file.

    Args:
        file_path: Path to the temporary file to delete

    Returns:
        bool: True if file was successfully deleted or doesn't need cleanup, False otherwise
    """
    if not file_path:
        # No file path provided, consider this a successful "no-op" cleanup
        return True

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.debug(f"Cleaned up temporary file: {file_path}")
            return True
        else:
            # File doesn't exist, so it's effectively "cleaned up" already
            logger.debug(f"Temporary file already doesn't exist: {file_path}")
            return True
    except Exception as e:
        logger.error(f"Failed to clean up temporary file {file_path}: {e}")
        return False


@handler_error_wrapper
def handle_blind_scan(workbench: WorkbenchAPI, params: argparse.Namespace) -> bool:
    """
    Handler for the 'blind-scan' command. Uses FossID CLI to generate file hashes,
    uploads the hash file, and then follows the same pattern as regular scan.

    Args:
        workbench: The Workbench API client instance
        params: Command line parameters

    Returns:
        bool: True if the operation completed successfully

    Raises:
        ValidationError: If required parameters are missing or invalid
        FileSystemError: If specified paths don't exist
        ProcessError: If CLI execution fails
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Initialize timing dictionary
    durations = {"hash_generation": 0.0, "kb_scan": 0.0, "dependency_analysis": 0.0}

    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the blind-scan command.")
    if not os.path.exists(params.path):
        raise FileSystemError(f"The provided path does not exist: {params.path}")
    if not os.path.isdir(params.path):
        raise ValidationError(
            f"The provided path must be a directory for blind-scan operations. "
            f"Files are not supported. Provided: {params.path}"
        )

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
    project_code = workbench.resolve_project(params.project_name, create_if_missing=True)
    scan_code, _ = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params,
    )

    # Ensure scan is compatible with the current operation
    ensure_scan_compatibility(workbench, params, scan_code)

    # Assert scan is idle before starting blind scan operations
    print("\nEnsuring the Scan is idle before starting blind scan operations...")
    workbench.check_and_wait_for_process(
        process_types=["SCAN", "DEPENDENCY_ANALYSIS"],
        scan_code=scan_code,
        max_tries=params.scan_number_of_tries,
        wait_interval=params.scan_wait_time,
    )

    # Clear existing scan content
    print("\nClearing existing scan content...")
    try:
        workbench.remove_uploaded_content(scan_code, "")
        print("Successfully cleared existing scan content.")
    except Exception as e:
        logger.warning(f"Failed to clear existing scan content: {e}")
        print(f"Warning: Could not clear existing scan content: {e}")
        print("Continuing with hash generation...")

    # Initialize CLI wrapper
    cli_wrapper = CliWrapper(
        cli_path=getattr(params, "fossid_cli_path", "/usr/bin/fossid-cli"),
    )

    # Validate FossID CLI
    print("\nValidating FossID CLI...")
    try:
        version = cli_wrapper.get_version()
        print(f"Using {version}")
    except Exception as e:
        logger.warning(f"Could not get CLI version: {e}")
        print(f"Warning: Could not validate CLI version: {e}")

    hash_file_path = None

    try:
        # KEY DIFFERENCE: Generate file hashes using FossID CLI instead of uploading files directly
        print("\nGenerating file hashes using FossID CLI...")
        hash_start_time = time.time()
        hash_file_path = cli_wrapper.blind_scan(
            path=params.path,
            run_dependency_analysis=getattr(params, "run_dependency_analysis", False),
        )
        hash_duration = time.time() - hash_start_time
        durations["hash_generation"] = hash_duration
        print(f"Hash generation completed in {format_duration(hash_duration)}.")

        # Upload the hash file instead of the original files
        print("\nUploading hash file to Workbench...")
        workbench.upload_scan_target(scan_code, hash_file_path)
        print("Hash file uploaded successfully.")

        # Verify scan can start
        workbench.check_and_wait_for_process(
            process_types=["SCAN", "DEPENDENCY_ANALYSIS"],
            scan_code=scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )

        # Determine which scan operations to run
        scan_operations = determine_scans_to_run(params)
        da_completed = False

        # Handle dependency analysis only mode
        if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
            print("\nStarting Dependency Analysis only (skipping KB scan)...")
            workbench.start_dependency_analysis(scan_code, import_only=False)

            # Handle no-wait mode
            if getattr(params, "no_wait", False):
                print("Dependency Analysis has been started.")
                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the status later using the 'show-results' command.")
                return True

            # Wait for dependency analysis to complete
            result = workbench.check_and_wait_for_process(
                process_types="DEPENDENCY_ANALYSIS",
                scan_code=scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
            # Single process returns WaitResult directly
            durations["dependency_analysis"] = result.duration or 0.0
            da_completed = True

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

            # Check if we should wait for completion
            if getattr(params, "no_wait", False):
                print("\nKB Scan started successfully.")
                if scan_operations["run_dependency_analysis"]:
                    print("Dependency Analysis will automatically start after scan completion.")
                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the scan status later using the 'show-results' command.")
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
                    da_completed = False

        # Print standardized operation summary
        print_operation_summary(params, da_completed, project_code, scan_code, durations)

        # Show scan results if any were requested
        if any(
            [
                params.show_licenses,
                params.show_components,
                params.show_dependencies,
                params.show_scan_metrics,
                params.show_policy_warnings,
                params.show_vulnerabilities,
            ]
        ):
            fetch_display_save_results(workbench, params, scan_code)

        print("\n✅ Blind Scan completed successfully!")
        logger.info("Blind Scan completed successfully.")

        return True

    finally:
        # Cleanup temporary hash file
        if hash_file_path:
            cleanup_success = cleanup_temp_file(hash_file_path)
            if cleanup_success:
                logger.debug("Temporary hash file cleaned up successfully.")
            else:
                logger.warning("Failed to clean up temporary hash file.")
