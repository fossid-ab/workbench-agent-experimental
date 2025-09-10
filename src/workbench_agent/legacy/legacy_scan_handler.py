import argparse
import json
import logging
import os
import time
from typing import Any, Dict

from workbench_agent.exceptions import FileSystemError, ValidationError
from workbench_agent.legacy.legacy_cli_wrapper import CliWrapper
from workbench_agent.legacy.legacy_error_handling import handler_error_wrapper
from workbench_agent.legacy.legacy_utils import format_duration, save_results
from workbench_agent.legacy.legacy_workbench_api import Workbench

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_legacy_scan(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Legacy scan handler that maintains exact compatibility with original-wb-agent.py.
    Enhanced with modern progress notifications while preserving original behavior.

    This handler preserves the original script's behavior including:
    - Using --blind_scan flag to determine scan type
    - Original error handling and output messages
    - Exact workflow sequence and timing
    - Result collection and saving logic

    New enhancements:
    - Duration tracking for operations
    - Enhanced progress notifications
    - Operation summaries

    Args:
        workbench: The Workbench API client instance
        params: Command line parameters (legacy format)

    Returns:
        bool: True if the operation completed successfully

    Raises:
        Exception: Uses original script's exception handling
    """
    print("--- Running LEGACY SCAN Mode ---")
    print("NOTE: Legacy mode is deprecated. Please migrate to modern commands:")
    print("  Legacy: workbench-agent --blind_scan ...")
    print("  Modern: workbench-agent blind-scan ...")
    print("  Legacy: workbench-agent --path ...")
    print("  Modern: workbench-agent scan --path ...")
    print("")

    # Initialize duration tracking (enhanced feature)
    durations = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "hash_generation": 0.0,
        "upload": 0.0,
        "extraction": 0.0,
    }

    # Handle blind scan path
    blind_scan_result_path = None

    if getattr(params, "blind_scan", False):
        print("\n--- Executing Blind Scan Workflow ---")
        cli_wrapper = CliWrapper(
            getattr(params, "cli_path", "/usr/bin/fossid-cli"),
            getattr(params, "config_path", "/etc/fossid.conf"),
        )

        # Display fossid-cli version (original behavior)
        print("CLI Version Information:")
        print(cli_wrapper.get_version())

        # Run scan and save .fossid file as temporary file (with timing)
        print("\nGenerating file hashes using FossID CLI...")
        hash_start_time = time.time()
        blind_scan_result_path = cli_wrapper.blind_scan(
            params.path, getattr(params, "run_dependency_analysis", False)
        )
        durations["hash_generation"] = time.time() - hash_start_time
        print(f"Hash generation completed in {format_duration(durations['hash_generation'])}.")
        print(f"Temporary file containing hashes generated at path: {blind_scan_result_path}")

    # Create Project if it doesn't exist (original logic with enhanced feedback)
    print("\n--- Checking Project and Scan Status ---")
    if not workbench.check_if_project_exists(params.project_code):
        print(f"Creating project '{params.project_code}'...")
        workbench.create_project(params.project_code)
        print(f"Project '{params.project_code}' created successfully.")
    else:
        print(f"Project '{params.project_code}' already exists.")

    # Create scan if it doesn't exist (original logic with enhanced feedback)
    scan_exists = workbench.check_if_scan_exists(params.scan_code)
    if not scan_exists:
        print(f"Scan with code '{params.scan_code}' does not exist. Creating it...")
        workbench.create_webapp_scan(
            params.scan_code,  # Positional: scan_code
            params.project_code,  # Positional: project_code
            getattr(params, "target_path", None),  # Positional: target_path
        )
        print(f"Scan '{params.scan_code}' created successfully.")
    else:
        print(f"Scan with code '{params.scan_code}' already exists. Proceeding to upload...")

    # Handle blind scan differently from regular scan (original logic with timing)
    if getattr(params, "blind_scan", False):
        # Upload temporary file with blind scan hashes
        print(f"\n--- Uploading Hash File ---")
        print("Parsed path: ", params.path)
        upload_start_time = time.time()
        workbench.upload_files(params.scan_code, blind_scan_result_path)
        durations["upload"] = time.time() - upload_start_time
        print(f"Hash file uploaded in {format_duration(durations['upload'])}.")

        # Delete .fossid file containing hashes (after upload to scan)
        if os.path.isfile(blind_scan_result_path):
            os.remove(blind_scan_result_path)
            print("Temporary hash file cleaned up.")
        else:
            print(f"Can not delete the file {blind_scan_result_path} as it doesn't exists")

    # Handle normal scanning (original logic with enhanced feedback and timing)
    elif not getattr(params, "target_path", None):
        print(f"\n--- Uploading Code Files ---")
        upload_start_time = time.time()

        if not os.path.isdir(params.path):
            # The given path is an actual file path. Only this file will be uploaded
            print(f"Uploading file indicated in --path parameter: {params.path}")
            workbench.upload_files(
                params.scan_code, params.path, getattr(params, "chunked_upload", False)
            )
        else:
            # Get all files found at given path (including in subdirectories). Exclude directories
            print(
                f"Uploading files found in directory indicated in --path parameter: {params.path}"
            )
            counter_files = 0
            for root, directories, filenames in os.walk(params.path):
                for filename in filenames:
                    if not os.path.isdir(os.path.join(root, filename)):
                        counter_files = counter_files + 1
                        workbench.upload_files(
                            params.scan_code,
                            os.path.join(root, filename),
                            getattr(params, "chunked_upload", False),
                        )
            print(f"A total of {counter_files} files uploaded")

        durations["upload"] = time.time() - upload_start_time
        print(f"File upload completed in {format_duration(durations['upload'])}.")

        print("\n--- Extracting Archives ---")
        print("Calling API scans->extracting_archives")
        extraction_start_time = time.time()
        workbench.extract_archives(
            params.scan_code,
            getattr(params, "recursively_extract_archives", False),
            getattr(params, "jar_file_extraction", False),
        )
        durations["extraction"] = time.time() - extraction_start_time
        print(f"Archive extraction completed in {format_duration(durations['extraction'])}.")

    # If --run_only_dependency_analysis parameter is true ONLY run dependency analysis, no KB scanning
    if getattr(params, "run_only_dependency_analysis", False):
        print("\n--- Running Dependency Analysis Only ---")
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print(f"Starting dependency analysis for scan: {params.scan_code}")
        workbench.start_dependency_analysis(params.scan_code)

        # Check if finished with enhanced progress notifications
        da_status_data, da_duration = workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS",
            params.scan_code,
            getattr(params, "scan_number_of_tries", 960),
            getattr(params, "scan_wait_time", 30),
        )
        durations["dependency_analysis"] = da_duration
        print(f"Dependency Analysis completed in {format_duration(da_duration)}.")
    # Run scan
    else:
        print("\n--- Running KB Scan ---")
        workbench.run_scan(
            params.scan_code,
            getattr(params, "limit", 10),
            getattr(params, "sensitivity", 10),
            getattr(params, "auto_identification_detect_declaration", False),
            getattr(params, "auto_identification_detect_copyright", False),
            getattr(params, "auto_identification_resolve_pending_ids", False),
            getattr(params, "delta_only", False),
            getattr(params, "reuse_identifications", False),
            getattr(params, "identification_reuse_type", "any"),
            getattr(params, "specific_code", None),
            getattr(params, "advanced_match_scoring", True),
            getattr(params, "match_filtering_threshold", -1),
        )

        # Check if finished with enhanced progress notifications
        scan_status_data, scan_duration = workbench.wait_for_scan_to_finish(
            "SCAN",
            params.scan_code,
            getattr(params, "scan_number_of_tries", 960),
            getattr(params, "scan_wait_time", 30),
        )
        durations["kb_scan"] = scan_duration
        print(f"KB Scan completed in {format_duration(scan_duration)}.")

    # If --run_dependency_analysis parameter is true run also dependency analysis
    if getattr(params, "run_dependency_analysis", False):
        print("\n--- Running Dependency Analysis ---")
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print(f"Starting dependency analysis for scan: {params.scan_code}")
        workbench.start_dependency_analysis(params.scan_code)

        # Check if finished with enhanced progress notifications
        da_status_data, da_duration = workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS",
            params.scan_code,
            getattr(params, "scan_number_of_tries", 960),
            getattr(params, "scan_wait_time", 30),
        )
        durations["dependency_analysis"] = da_duration
        print(f"Dependency Analysis completed in {format_duration(da_duration)}.")

    # Enhanced operation summary (new feature)
    print("\n--- Legacy Scan Operation Summary ---")
    scan_completed = durations.get("kb_scan", 0) > 0 or getattr(
        params, "run_only_dependency_analysis", False
    )
    da_completed = durations.get("dependency_analysis", 0) > 0

    print(f"Project: {params.project_code}")
    print(f"Scan: {params.scan_code}")
    print(f"Operations performed:")

    if getattr(params, "blind_scan", False):
        print(
            f"  - Hash Generation: Yes (Duration: {format_duration(durations.get('hash_generation', 0))})"
        )
    if durations.get("upload", 0) > 0:
        print(f"  - File Upload: Yes (Duration: {format_duration(durations.get('upload', 0))})")
    if durations.get("extraction", 0) > 0:
        print(
            f"  - Archive Extraction: Yes (Duration: {format_duration(durations.get('extraction', 0))})"
        )
    if durations.get("kb_scan", 0) > 0:
        print(f"  - KB Scan: Yes (Duration: {format_duration(durations.get('kb_scan', 0))})")
    elif not getattr(params, "run_only_dependency_analysis", False):
        print(f"  - KB Scan: No")
    if da_completed:
        print(
            f"  - Dependency Analysis: Yes (Duration: {format_duration(durations.get('dependency_analysis', 0))})"
        )
    else:
        print(f"  - Dependency Analysis: No")

    total_duration = sum(durations.values())
    print(f"Total Operation Time: {format_duration(total_duration)}")
    print("------------------------------------")

    # Result collection (original script logic)
    print("\n--- Collecting Results ---")
    if getattr(params, "get_scan_identified_components", False):
        print("Identified components: ")
        identified_components = workbench.get_scan_identified_components(params.scan_code)
        print(json.dumps(identified_components))
        save_results(params, identified_components)
        return True

    elif getattr(params, "scans_get_policy_warnings_counter", False):
        if not params.project_code:
            print(
                "Parameter project_code missing!\n"
                "In order for the scans->get_policy_warnings_counter to be called a project code is required."
            )
            return False
        print(f"Scan: {params.scan_code} policy warnings info: ")
        info_policy = workbench.scans_get_policy_warnings_counter(params.scan_code)
        print(json.dumps(info_policy))
        save_results(params, info_policy)
        return True

    elif getattr(params, "projects_get_policy_warnings_info", False):
        if not params.project_code:
            print(
                "Parameter project_code missing!\n"
                "In order for the projects->get_policy_warnings_info to be called a project code is required."
            )
            return False
        print(f"Project {params.project_code} policy warnings info: ")
        info_policy = workbench.projects_get_policy_warnings_info(params.project_code)
        print(json.dumps(info_policy))
        save_results(params, info_policy)
        return True

    elif getattr(params, "scans_get_results", False):
        print(f"Scan {params.scan_code} results: ")
        results = workbench.get_results(params.scan_code)
        print(json.dumps(results))
        save_results(params, results)
        return True

    else:
        print("Identified licenses: ")
        identified_licenses = workbench.get_scan_identified_licenses(params.scan_code)
        print(json.dumps(identified_licenses))
        save_results(params, identified_licenses)
        return True
