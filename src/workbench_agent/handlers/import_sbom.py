# workbench_agent/handlers/import_sbom.py

import argparse
import logging
import os
from typing import TYPE_CHECKING, Any, Dict, Tuple

from workbench_agent.exceptions import (
    ProcessError,
    ProcessTimeoutError,
    WorkbenchAgentError,
)
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.sbom_validator import SBOMValidator
from workbench_agent.utilities.scan_target_validators import ensure_scan_compatibility
from workbench_agent.utilities.scan_workflows import (
    fetch_display_save_results,
    get_workbench_links,
    print_operation_summary,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

logger = logging.getLogger("workbench-agent")


def _validate_sbom_file(file_path: str) -> Tuple[str, str, Dict, Any]:
    """
    Validates SBOM file and returns format information and parsed document.

    Args:
        file_path: Path to the SBOM file to validate

    Returns:
        tuple[str, str, Dict, Any]: (format, version, metadata, parsed_document)

    Raises:
        ValidationError: If SBOM validation fails
        FileSystemError: If file doesn't exist or can't be read
    """
    try:
        sbom_format, version, metadata, parsed_document = SBOMValidator.validate_sbom_file(
            file_path
        )
        logger.debug(f"SBOM validation successful: {sbom_format} v{version}")
        return sbom_format, version, metadata, parsed_document
    except Exception as e:
        logger.error(f"SBOM validation failed for '{file_path}': {e}")
        raise


def _prepare_sbom_for_upload(
    file_path: str, sbom_format: str, parsed_document: Any
) -> Tuple[str, bool]:
    """
    Prepares SBOM file for upload, converting format if needed.

    Args:
        file_path: Original file path
        sbom_format: Detected SBOM format
        parsed_document: Parsed document from validation

    Returns:
        tuple[str, bool]: (upload_path, temp_file_created)

    Raises:
        ValidationError: If preparation/conversion fails
    """
    try:
        upload_path = SBOMValidator.prepare_sbom_for_upload(file_path, sbom_format, parsed_document)
        temp_file_created = upload_path != file_path
        logger.debug(
            f"SBOM preparation successful: upload_path={upload_path}, converted={temp_file_created}"
        )
        return upload_path, temp_file_created
    except Exception as e:
        logger.error(f"SBOM preparation failed for '{file_path}': {e}")
        raise


def _get_project_and_scan_codes(
    workbench: "WorkbenchAPI", params: argparse.Namespace
) -> tuple[str, str]:
    """
    Resolve project and scan codes for SBOM import.

    Args:
        workbench: The Workbench API client instance
        params: Command line parameters

    Returns:
        tuple[str, str]: Project code and scan code
    """
    project_code = workbench.resolve_project(params.project_name, create_if_missing=True)

    # Create scan with import_from_report=True
    scan_code, _ = workbench.resolve_scan(
        params.scan_name,
        params.project_name,
        create_if_missing=True,
        params=params,
        import_from_report=True,
    )
    return project_code, scan_code


def _print_validation_summary(sbom_format: str, version: str, metadata: Dict):
    """Prints a summary of the SBOM validation results."""
    print("SBOM validation successful:")
    print(f"  Format: {sbom_format.upper()}")
    print(f"  Version: {version}")
    if sbom_format == "cyclonedx":
        print(f"  Components: {metadata.get('components_count', 'Unknown')}")
        if metadata.get("serial_number"):
            print(f"  Serial Number: {metadata['serial_number']}")
    elif sbom_format == "spdx":
        print(f"  Document Name: {metadata.get('name', 'Unknown')}")
        print(f"  Packages: {metadata.get('packages_count', 'Unknown')}")
        print(f"  Files: {metadata.get('files_count', 'Unknown')}")


@handler_error_wrapper
def handle_import_sbom(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'import-sbom' command. Imports SBOM data from a file.

    Args:
        workbench: The Workbench API client instance
        params: Command line parameters

    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Initialize timing dictionary
    durations = {"sbom_import": 0.0}

    # Track upload path for cleanup
    upload_path = None
    temp_file_created = False

    try:
        # Validate SBOM file FIRST - before any project/scan creation
        print("\n--- Validating SBOM File ---")
        sbom_format, version, metadata, parsed_document = _validate_sbom_file(params.path)
        _print_validation_summary(sbom_format, version, metadata)

        # Prepare SBOM file for upload (convert if needed)
        print("\n--- Preparing SBOM for Upload ---")
        upload_path, temp_file_created = _prepare_sbom_for_upload(
            params.path, sbom_format, parsed_document
        )

        if temp_file_created:
            print(f"  Converted for upload: {os.path.basename(upload_path)}")
        else:
            print("  Using original file format")

        # Resolve project and scan (find or create) - AFTER validation and preparation
        print("\nChecking if the Project and Scan exist or need to be created...")
        project_code, scan_code = _get_project_and_scan_codes(workbench, params)

        print(f"Processing SBOM import for scan '{scan_code}' in project '{project_code}'...")
        print(f"Importing from: {params.path}")

        # Ensure scan is compatible with the current operation
        ensure_scan_compatibility(workbench, params, scan_code)

        # Ensure scan is idle before starting SBOM import
        print("\nEnsuring the Scan is idle before starting SBOM import...")
        workbench.check_and_wait_for_process(
            process_types=["REPORT_IMPORT"],
            scan_code=scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )

        # Upload SBOM file using the prepared upload path
        print("\n--- Uploading SBOM File ---")
        try:
            workbench.upload_sbom_file(scan_code=scan_code, path=upload_path)
            print(f"SBOM file uploaded successfully from: {upload_path}")
        except Exception as e:
            logger.error(f"Failed to upload SBOM file for '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(
                f"Failed to upload SBOM file: {e}", details={"error": str(e)}
            ) from e

        # Start SBOM import
        print("\n--- Starting SBOM Import ---")

        try:
            workbench.import_report(scan_code=scan_code)
            print("SBOM import initiated successfully.")
        except Exception as e:
            logger.error(f"Failed to start SBOM import for '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(
                f"Failed to start SBOM import: {e}", details={"error": str(e)}
            ) from e

        # Wait for SBOM import to complete
        sbom_completed = False
        try:
            print("\nWaiting for SBOM import to complete...")
            # Use optimized 3-second wait interval for import-only mode
            report_import_status = workbench.check_and_wait_for_process(
                process_types="REPORT_IMPORT",
                scan_code=scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=3,  # Use 3-second wait interval for import-only mode as it finishes faster
            )

            # Store the SBOM import duration
            durations["sbom_import"] = report_import_status.duration or 0.0
            sbom_completed = True

            print("SBOM import completed successfully.")

        except (ProcessTimeoutError, ProcessError) as e:
            logger.error(f"Error during SBOM import for '{scan_code}': {e}", exc_info=True)
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error during SBOM import for '{scan_code}': {e}", exc_info=True
            )
            raise WorkbenchAgentError(
                f"Error during SBOM import: {e}", details={"error": str(e)}
            ) from e

        # Print operation summary
        print_operation_summary(params, sbom_completed, project_code, scan_code, durations)

        # Fetch and display results - CRITICAL: Match import-da implementation behavior
        if sbom_completed:
            print("\n--- Fetching Results ---")
            try:
                fetch_display_save_results(workbench, params, scan_code)
            except Exception as e:
                logger.warning(f"Failed to fetch and display results: {e}")
                print(f"Warning: Failed to fetch and display results: {e}")

            # Add Workbench link for easy navigation to view SBOM results
            try:
                scan_info = workbench.get_scan_information(scan_code)
                scan_id = scan_info.get("id")
                if scan_id:
                    links = get_workbench_links(workbench.api_url, int(scan_id))
                    main_link = links.get("main", {})
                    if main_link.get("url"):
                        print(f"\n🔗 {main_link['message']}: {main_link['url']}")
            except Exception as e:
                logger.debug(f"Could not generate Workbench link: {e}")
                # Don't fail the whole operation if link generation fails

        return sbom_completed

    finally:
        # Clean up temporary file if one was created
        if temp_file_created and upload_path:
            try:
                SBOMValidator.cleanup_temp_file(upload_path)
            except Exception as e:
                logger.warning(f"Failed to clean up temporary file: {e}")
                # Don't fail the operation if cleanup fails
