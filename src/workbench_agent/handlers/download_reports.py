# workbench_agent/handlers/download_reports.py

import argparse
import logging
import os
from typing import TYPE_CHECKING

from workbench_agent.exceptions import (
    ApiError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ValidationError,
)
from workbench_agent.utilities.error_handling import handler_error_wrapper

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_download_reports(workbench: "WorkbenchAPI", params: argparse.Namespace):
    """
    Handler for the 'download-reports' command.
    Downloads reports for a scan or project.

    Args:
        workbench: The Workbench API client
        params: Command line parameters

    Returns:
        True if the operation was successful

    Raises:
        Various exceptions based on errors that occur during the process
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Process report_types (comma-separated list or ALL)
    report_types = set()
    if not params.report_type or params.report_type.upper() == "ALL":
        if params.report_scope == "scan":
            report_types = workbench.SCAN_REPORT_TYPES
        else:  # project
            report_types = workbench.PROJECT_REPORT_TYPES
    else:
        # Split comma-separated list
        for rt in params.report_type.split(","):
            rt = rt.strip().lower()
            # Validate report type
            if params.report_scope == "scan" and rt not in workbench.SCAN_REPORT_TYPES:
                raise ValidationError(
                    f"Report type '{rt}' is not supported for scan scope reports. "
                    f"Supported types: {', '.join(sorted(list(workbench.SCAN_REPORT_TYPES)))}"
                )
            elif params.report_scope == "project" and rt not in workbench.PROJECT_REPORT_TYPES:
                raise ValidationError(
                    f"Report type '{rt}' is not supported for project scope reports. "
                    f"Supported types: {', '.join(sorted(list(workbench.PROJECT_REPORT_TYPES)))}"
                )
            report_types.add(rt)

    logger.debug(f"Resolved report types to download: {report_types}")

    # Create output directory if it doesn't exist
    output_dir = params.report_save_path
    if not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)

    # Resolve project, scan
    print(
        f"\nResolving {'scan' if params.report_scope == 'scan' else 'project'} '{params.scan_name if params.report_scope == 'scan' else params.project_name}'..."
    )

    project_code = None
    scan_code = None

    if params.project_name:
        project_code = workbench.resolve_project(params.project_name, create_if_missing=False)

    if params.report_scope == "scan":
        # If scan scope, we need a scan code
        if params.scan_name:
            # Try to resolve using project context first if provided
            if project_code and params.project_name:
                scan_code, _ = workbench.resolve_scan(
                    scan_name=params.scan_name,
                    project_name=params.project_name,
                    create_if_missing=False,
                    params=params,
                )
            else:
                # Try to resolve globally if project not provided
                scan_code, _ = workbench.resolve_scan(
                    scan_name=params.scan_name,
                    project_name=None,
                    create_if_missing=False,
                    params=params,
                )
        else:
            raise ValidationError("Scan name is required for scan scope reports")
    elif not project_code:
        # If project scope but no project_code, that's an error
        raise ValidationError("Project name is required for project scope reports")

    # Check scan completion status for scan-scope reports
    if params.report_scope == "scan" and scan_code:
        print("\nChecking scan completion status...")
        # Wait for KB scan and dependency analysis using modern waiters
        try:
            print("\nEnsuring KB Scan finished...")
            workbench.check_and_wait_for_process(
                process_types="SCAN",
                scan_code=scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
            kb_scan_completed = True
            print("KB Scan has completed successfully.")
        except (ProcessTimeoutError, ProcessError) as e:
            print(f"\nError waiting for KB Scan completion: {e}")
            kb_scan_completed = False

        try:
            print("\nEnsuring Dependency Analysis finished...")
            workbench.check_and_wait_for_process(
                process_types="DEPENDENCY_ANALYSIS",
                scan_code=scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
            da_completed = True
            print("Dependency Analysis has completed successfully.")
        except (ProcessTimeoutError, ProcessError) as e:
            print(f"\nError waiting for Dependency Analysis completion: {e}")
            da_completed = False

            if not kb_scan_completed:
                print(
                    "\nWarning: The KB scan has not completed successfully. Reports may be incomplete."
                )
                logger.warning(
                    f"Generating reports for scan '{scan_code}' that has not completed successfully."
                )

            # Dependency analysis might be relevant for certain report types
            if not da_completed:
                print(
                    "\nNote: Dependency Analysis has not completed. Some reports may have incomplete information."
                )
                logger.warning(f"Generating reports for scan '{scan_code}' without completed DA.")
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            print(f"\nWarning: Could not verify scan completion status: {e}")
            print("Proceeding to generate reports anyway, but they may be incomplete.")
            logger.warning(
                f"Could not verify scan completion for '{scan_code}': {e}. Proceeding anyway."
            )

    # Generate and download reports based on scope
    print(
        f"\nGenerating and downloading {len(report_types)} {'project' if params.report_scope == 'project' else 'scan'} report(s)..."
    )

    # Print the actual report types being downloaded
    for rt in sorted(report_types):
        print(f"- {rt}")

    # Track results for summary
    success_count = 0
    error_count = 0
    error_types = []

    # Process each report type sequentially
    for report_type in sorted(report_types):
        print(f"\nProcessing {report_type} report...")

        try:
            # Generate the report
            print(f"Generating {report_type} report...")

            # Get the right name component for file naming
            name_component = (
                params.project_name if params.report_scope == "project" else params.scan_name
            )

            # Common parameters for report generation
            common_params = {
                "report_type": report_type,
            }

            # Add optional parameters if they were provided
            if params.selection_type is not None:
                common_params["selection_type"] = params.selection_type

            if params.selection_view is not None:
                common_params["selection_view"] = params.selection_view

            if params.disclaimer is not None:
                common_params["disclaimer"] = params.disclaimer

            # Include VEX data if requested (default is True)
            common_params["include_vex"] = params.include_vex

            # Check if this report type is synchronous or asynchronous
            is_async = report_type in workbench.ASYNC_REPORT_TYPES

            # Start report generation
            if is_async:
                # Asynchronous report generation
                print(f"Starting asynchronous generation of {report_type} report...")

                if params.report_scope == "project":
                    process_id = workbench.generate_project_report(project_code, **common_params)
                else:
                    process_id = workbench.generate_scan_report(scan_code, **common_params)

                # Wait for report generation to complete using unified architecture
                try:
                    print(f"Waiting for {report_type} report generation to complete...")

                    if params.report_scope == "project":
                        # Project reports now use the unified architecture with PROJECT_REPORT_GENERATION
                        max_tries = getattr(params, "scan_number_of_tries", 60)
                        workbench.check_and_wait_for_process(
                            process_types="PROJECT_REPORT_GENERATION",
                            scan_code=None,  # Project operations don't need scan_code per API schema
                            max_tries=max_tries,
                            wait_interval=3,  # Fixed 3-second interval for consistency
                            process_id=str(
                                process_id
                            ),  # Required for PROJECT_REPORT_GENERATION operations
                        )
                    else:
                        # Scan reports use the unified architecture with SCAN_REPORT_GENERATION
                        max_tries = getattr(params, "scan_number_of_tries", 60)
                        workbench.check_and_wait_for_process(
                            process_types="SCAN_REPORT_GENERATION",
                            scan_code=scan_code,
                            max_tries=max_tries,
                            wait_interval=3,  # Fixed 3-second interval for consistency
                            process_id=str(
                                process_id
                            ),  # Required for SCAN_REPORT_GENERATION operations
                        )
                    print("Report generation complete!")
                except (ProcessTimeoutError, ProcessError) as e:
                    logger.error(
                        f"Failed waiting for '{report_type}' report (Process ID: {process_id}): {e}"
                    )
                    error_count += 1
                    error_types.append(report_type)
                    continue
                except (ApiError, NetworkError) as e:
                    logger.error(
                        f"API error during '{report_type}' report generation (Process ID: {process_id}): {e}"
                    )
                    error_count += 1
                    error_types.append(report_type)
                    continue
                except Exception as e:
                    logger.error(
                        f"Unexpected error during '{report_type}' report generation (Process ID: {process_id}): {e}",
                        exc_info=True,
                    )
                    error_count += 1
                    error_types.append(report_type)
                    continue

                # Download the generated report
                print(f"Downloading {report_type} report...")
                if params.report_scope == "project":
                    response = workbench.download_project_report(process_id)
                else:
                    response = workbench.download_scan_report(process_id)

            else:
                # Synchronous report generation (returns response directly)
                print(f"Directly downloading {report_type} report...")
                if params.report_scope == "project":
                    # Note: Project reports are typically async, but handle sync case
                    response = workbench.generate_project_report(project_code, **common_params)
                else:
                    response = workbench.generate_scan_report(scan_code, **common_params)

            # Save the report content
            workbench._save_report_content(
                response, output_dir, params.report_scope, name_component, report_type
            )
            print(f"Successfully saved {report_type} report.")
            success_count += 1

        except (ApiError, NetworkError, FileSystemError, ValidationError) as e:
            print(f"Error processing {report_type} report: {getattr(e, 'message', str(e))}")
            logger.error(f"Failed to generate/download {report_type} report: {e}", exc_info=True)
            error_count += 1
            error_types.append(report_type)

    # Print summary
    print("\n" + "=" * 50)
    print("Report Download Summary")
    print("=" * 50)
    print(f"Total reports requested: {len(report_types)}")
    print(f"Successfully downloaded: {success_count}")
    if error_count > 0:
        print(f"Failed to download: {error_count} ({', '.join(error_types)})")
    print("=" * 50)

    # Return True if at least one report was successfully downloaded
    return success_count > 0
