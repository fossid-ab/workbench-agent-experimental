import argparse
import json
import logging
import os
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

from workbench_agent.exceptions import (
    ApiError,
    NetworkError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")

# --- Workbench UI Link Generation ---


def get_workbench_links(api_url: str, scan_id: int) -> Dict[str, Dict[str, str]]:
    """
    Get all Workbench UI links and messages for a scan.

    Args:
        api_url: The Workbench API URL (includes /api.php)
        scan_id: The scan ID

    Returns:
        Dict with link types as keys, each containing 'url' and 'message'
        Example: {
            "main": {"url": "https://...", "message": "View scan results..."},
            "pending": {"url": "https://...", "message": "Review Pending IDs..."},
            "policy": {"url": "https://...", "message": "Review policy warnings..."}
        }
    """
    # Link type configuration
    link_config = {
        "main": {"view_param": None, "message": "View scan results in Workbench"},
        "pending": {"view_param": "pending_items", "message": "Review Pending IDs in Workbench"},
        "policy": {
            "view_param": "mark_as_identified",
            "message": "Review policy warnings in Workbench",
        },
    }

    # Build base URL once
    base_url = api_url.replace("/api.php", "").rstrip("/")

    # Build all links
    links = {}
    for link_type, config in link_config.items():
        url = f"{base_url}/index.html?form=main_interface&action=scanview&sid={scan_id}"
        if config["view_param"]:
            url += f"&current_view={config['view_param']}"

        links[link_type] = {"url": url, "message": config["message"]}

    return links


# --- Scan Configuration and Execution ---


def determine_scans_to_run(params: argparse.Namespace) -> Dict[str, bool]:
    """
    Determines which scan processes to run based on the provided parameters.
    """
    run_dependency_analysis = getattr(params, "run_dependency_analysis", False)
    dependency_analysis_only = getattr(params, "dependency_analysis_only", False)
    scan_operations = {"run_kb_scan": True, "run_dependency_analysis": False}
    if run_dependency_analysis and dependency_analysis_only:
        print(
            "\nWARNING: Both --dependency-analysis-only and --run-dependency-analysis were specified. Using --dependency-analysis-only mode (skipping KB scan)."
        )
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif dependency_analysis_only:
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif run_dependency_analysis:
        scan_operations["run_kb_scan"] = True
        scan_operations["run_dependency_analysis"] = True
    logger.debug(f"Determined scan operations: {scan_operations}")
    return scan_operations


# --- Result Fetching, Display, and Saving ---


def fetch_results(
    workbench: "WorkbenchAPI", params: argparse.Namespace, scan_code: str
) -> Dict[str, Any]:
    """
    Fetches requested scan results based on --show-* flags.
    """
    should_fetch_licenses = getattr(params, "show_licenses", False)
    should_fetch_components = getattr(params, "show_components", False)
    should_fetch_dependencies = getattr(params, "show_dependencies", False)
    should_fetch_metrics = getattr(params, "show_scan_metrics", False)
    should_fetch_policy = getattr(params, "show_policy_warnings", False)
    should_fetch_vulnerabilities = getattr(params, "show_vulnerabilities", False)

    if not any(
        [
            should_fetch_licenses,
            should_fetch_components,
            should_fetch_dependencies,
            should_fetch_metrics,
            should_fetch_policy,
            should_fetch_vulnerabilities,
        ]
    ):
        print("\n=== No Results Requested ===")
        print("Add flags like --show-licenses, --show-vulnerabilities, etc. to see results.")
        return {}

    logger.debug("\n=== Fetching Requested Results ===")
    collected_results = {}

    if should_fetch_licenses or should_fetch_dependencies:
        try:
            da_results = workbench.get_dependency_analysis_results(scan_code)
            if da_results:
                collected_results["dependency_analysis"] = da_results
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch Dependency Analysis results: {e}")

    if should_fetch_licenses:
        try:
            kb_licenses = workbench.get_scan_identified_licenses(scan_code)
            if kb_licenses:
                collected_results["kb_licenses"] = sorted(
                    kb_licenses, key=lambda x: x.get("identifier", "").lower()
                )
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch KB Identified Licenses: {e}")

    if should_fetch_components:
        try:
            kb_components = workbench.get_scan_identified_components(scan_code)
            if kb_components:
                collected_results["kb_components"] = sorted(
                    kb_components, key=lambda x: (x.get("name", "").lower(), x.get("version", ""))
                )
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch KB Identified Scan Components: {e}")

    if should_fetch_metrics:
        try:
            collected_results["scan_metrics"] = workbench.get_scan_folder_metrics(scan_code)
        except (ApiError, NetworkError, ScanNotFoundError) as e:
            print(f"Warning: Could not fetch Scan File Metrics: {e}")

    if should_fetch_policy:
        try:
            collected_results["policy_warnings"] = workbench.get_policy_warnings_counter(scan_code)
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch Scan Policy Warnings: {e}")

    if should_fetch_vulnerabilities:
        try:
            vulnerabilities = workbench.list_vulnerabilities(scan_code)
            if vulnerabilities:
                collected_results["vulnerabilities"] = vulnerabilities
        except (ApiError, NetworkError, ScanNotFoundError) as e:
            print(f"Warning: Could not fetch Vulnerabilities: {e}")

    return collected_results


def display_results(collected_results: Dict[str, Any], params: argparse.Namespace) -> bool:
    """
    Displays scan results based on the collected data and user preferences.
    """
    should_fetch_licenses = getattr(params, "show_licenses", False)
    should_fetch_components = getattr(params, "show_components", False)
    should_fetch_dependencies = getattr(params, "show_dependencies", False)
    should_fetch_metrics = getattr(params, "show_scan_metrics", False)
    should_fetch_policy = getattr(params, "show_policy_warnings", False)
    should_fetch_vulnerabilities = getattr(params, "show_vulnerabilities", False)

    da_results_data = collected_results.get("dependency_analysis")
    kb_licenses_data = collected_results.get("kb_licenses")
    kb_components_data = collected_results.get("kb_components")
    scan_metrics_data = collected_results.get("scan_metrics")
    policy_warnings_data = collected_results.get("policy_warnings")
    vulnerabilities_data = collected_results.get("vulnerabilities")

    print("\n--- Results Summary ---")
    displayed_something = False

    # Display Scan Metrics
    if should_fetch_metrics:
        print("\n=== Scan File Metrics ===")
        displayed_something = True
        if scan_metrics_data:
            total = scan_metrics_data.get("total", "N/A")
            pending = scan_metrics_data.get("pending_identification", "N/A")
            identified = scan_metrics_data.get("identified_files", "N/A")
            no_match = scan_metrics_data.get("without_matches", "N/A")
            print(f"  - Total Files Scanned: {total}")
            print(f"  - Files Pending Identification: {pending}")
            print(f"  - Files Identified: {identified}")
            print(f"  - Files Without Matches: {no_match}")
            print("-" * 25)
        else:
            print("Scan metrics data could not be fetched or was empty.")

    # Display Licenses
    if should_fetch_licenses:
        print("\n=== Identified Licenses ===")
        displayed_something = True
        kb_licenses_found = bool(kb_licenses_data)
        da_licenses_found = False

        if kb_licenses_found:
            print("Unique Licenses in Identified Components):")
            for lic in kb_licenses_data:
                identifier = lic.get("identifier", "N/A")
                name = lic.get("name", "N/A")
                print(f"  - {identifier}:{name}")
            print("-" * 25)

        if da_results_data:
            da_lic_names = sorted(
                list(
                    set(
                        comp.get("license_identifier", "N/A")
                        for comp in da_results_data
                        if comp.get("license_identifier")
                    )
                )
            )
            # Check if any valid licenses were found in DA data
            if da_lic_names and any(lic != "N/A" for lic in da_lic_names):
                print("Unique Licenses in Dependencies:")
                da_licenses_found = True
                for lic_name in da_lic_names:
                    if lic_name and lic_name != "N/A":
                        print(f"  - {lic_name}")
                print("-" * 25)

        if not kb_licenses_found and not da_licenses_found:
            print("No Licenses to report.")

    # Display KB Components
    if should_fetch_components:
        print("\n=== Identified Components ===")
        displayed_something = True
        if kb_components_data:
            print("From Signature Scanning:")
            for comp in kb_components_data:
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')}")
            print("-" * 25)
        else:
            print("No KB Scan Components found to report.")

    # Display Dependencies
    if should_fetch_dependencies:
        print("\n=== Dependency Analysis Results ===")
        displayed_something = True
        if da_results_data:
            print("Component, Version, Scope, and License of Dependencies:")
            da_results_data.sort(key=lambda x: (x.get("name", "").lower(), x.get("version", "")))
            for comp in da_results_data:
                scopes_display = "N/A"
                scopes_str = comp.get("projects_and_scopes")
                if scopes_str:
                    try:
                        scopes_data = json.loads(scopes_str)
                        scopes_list = sorted(
                            list(
                                set(
                                    p_info.get("scope")
                                    for p_info in scopes_data.values()
                                    if isinstance(p_info, dict) and p_info.get("scope")
                                )
                            )
                        )
                        if scopes_list:
                            scopes_display = ", ".join(scopes_list)
                    except (json.JSONDecodeError, AttributeError, TypeError) as scope_err:
                        logger.debug(
                            f"Could not parse scopes for DA component {comp.get('name')}: {scope_err}"
                        )
                        pass
                print(
                    f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')} "
                    f"(Scope: {scopes_display}, License: {comp.get('license_identifier', 'N/A')})"
                )
            print("-" * 25)
        else:
            print("No Components found through Dependency Analysis.")

    # Display Policy Warnings
    if should_fetch_policy:
        print("\n=== Policy Warnings Summary ===")
        displayed_something = True
        if policy_warnings_data is not None:
            # Check if we have real data with non-zero values
            total_warnings = int(policy_warnings_data.get("policy_warnings_total", 0))
            files_with_warnings = int(policy_warnings_data.get("identified_files_with_warnings", 0))
            deps_with_warnings = int(policy_warnings_data.get("dependencies_with_warnings", 0))

            if total_warnings > 0:
                print(
                    f"There are {total_warnings} policy warnings: "
                    f"{files_with_warnings} in Identified Files, and "
                    f"{deps_with_warnings} in Dependencies."
                )
            else:
                print("No policy warnings found.")
        else:
            print("Policy warnings counter data could not be fetched or was empty.")
        print("-" * 25)

    # Display Vulnerability Summary
    if should_fetch_vulnerabilities:
        print("\n=== Vulnerability Summary ===")
        displayed_something = True
        if vulnerabilities_data:
            num_cves = len(vulnerabilities_data)
            unique_components = set()
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "Unknown")
                comp_version = vuln.get("component_version", "Unknown")
                unique_components.add(f"{comp_name}:{comp_version}")
                severity = vuln.get("severity", "UNKNOWN").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            num_unique_components = len(unique_components)
            print(
                f"There are {num_cves} vulnerabilities affecting {num_unique_components} components."
            )
            print(
                f"By CVSS Score, "
                f"{severity_counts['CRITICAL']} are Critical, "
                f"{severity_counts['HIGH']} are High, "
                f"{severity_counts['MEDIUM']} are Medium, and "
                f"{severity_counts['LOW']} are Low."
            )

            if severity_counts["UNKNOWN"] > 0:
                print(f"  - Unknown:  {severity_counts['UNKNOWN']}")

        if vulnerabilities_data:
            print("\n=== Top Vulnerable Components ===")
            components_vulns = {}
            # Group vulnerabilities by component:version
            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "UnknownComponent")
                comp_version = vuln.get("component_version", "UnknownVersion")
                comp_key = f"{comp_name}:{comp_version}"
                if comp_key not in components_vulns:
                    components_vulns[comp_key] = []
                components_vulns[comp_key].append(vuln)

            # Sort components by the number of vulnerabilities (descending)
            sorted_components = sorted(
                components_vulns.items(), key=lambda item: len(item[1]), reverse=True
            )

            # Define severity order for sorting vulnerabilities within each component
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

            for comp_key, vulns_list in sorted_components:
                print(f"\n{comp_key} - {len(vulns_list)} vulnerabilities")

                # Sort vulnerabilities within this component by severity
                sorted_vulns_list = sorted(
                    vulns_list,
                    key=lambda v: severity_order.get(v.get("severity", "UNKNOWN").upper(), 0),
                    reverse=True,
                )

                # Display top 5 vulnerabilities for each component
                for i, vuln in enumerate(sorted_vulns_list[:5]):
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    cve = vuln.get("cve", "NO_CVE_ID")
                    print(f"  - [{severity}] {cve}")
                if len(sorted_vulns_list) > 5:
                    print(f"  ... and {len(sorted_vulns_list) - 5} more.")
        else:
            print("No vulnerabilities found.")
        print("-" * 25)

    if not displayed_something:
        print("No results were successfully fetched or displayed for the specified flags.")
    print("------------------------------------")

    return displayed_something


def save_results_to_file(filepath: str, results: Dict, scan_code: str):
    """Helper to save collected results dictionary to a JSON file."""
    output_dir = os.path.dirname(filepath) or "."
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Saved results to: {filepath}")
    except (IOError, OSError) as e:
        print(f"\nWarning: Failed to save results to {filepath}: {e}")


def fetch_display_save_results(
    workbench: "WorkbenchAPI", params: argparse.Namespace, scan_code: str
):
    """
    Orchestrates fetching, displaying, and saving scan results.
    """
    any_results_requested = any(
        getattr(params, flag, False)
        for flag in [
            "show_licenses",
            "show_components",
            "show_dependencies",
            "show_scan_metrics",
            "show_policy_warnings",
            "show_vulnerabilities",
        ]
    )

    collected_results = fetch_results(workbench, params, scan_code)

    if any_results_requested:
        display_results(collected_results, params)

    save_path = getattr(params, "result_save_path", None)
    if save_path:
        if collected_results:
            print(f"\nSaving collected results to '{save_path}'...")
            save_results_to_file(save_path, collected_results, scan_code)
        else:
            print("\nNo results were successfully collected, skipping save.")


# --- Formatting and Summaries ---


def format_duration(duration_seconds: Optional[Union[int, float]]) -> str:
    """Formats a duration in seconds into a 'X minutes, Y seconds' string."""
    if duration_seconds is None:
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds))
    except (ValueError, TypeError):
        return "Invalid Duration"

    minutes, seconds = divmod(int(duration_seconds), 60)
    if minutes > 0 and seconds > 0:
        return f"{minutes} minutes, {seconds} seconds"
    elif minutes > 0:
        return f"{minutes} minutes"
    elif seconds == 1:
        return "1 second"
    else:
        return f"{seconds} seconds"


def print_operation_summary(
    params: argparse.Namespace,
    da_completed: bool,
    project_code: str,
    scan_code: str,
    durations: Dict[str, float] = None,
):
    """
    Prints a standardized summary of the scan operations performed and settings used.

    Args:
        params: Command line parameters
        da_completed: Whether dependency analysis completed successfully
        project_code: Project code associated with the scan
        scan_code: Scan code of the operation
        durations: Dictionary containing operation durations in seconds
    """
    durations = durations or {}  # Initialize to empty dict if None

    print("\n--- Operation Summary ---")

    print("Workbench Agent Operation Details:")
    if params.command == "scan":
        print("  - Method: Code Upload (using --path)")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
        print(
            f"  - Recursive Archive Extraction: {getattr(params, 'recursively_extract_archives', 'N/A')}"
        )
        print(f"  - JAR File Extraction: {getattr(params, 'jar_file_extraction', 'N/A')}")
    elif params.command == "scan-git":
        print("  - Method: Git Scan")
        print(f"  - Git Repository URL: {getattr(params, 'git_url', 'N/A')}")
        if getattr(params, "git_tag", None):
            print(f"  - Git Tag: {params.git_tag}")
        elif getattr(params, "git_branch", None):
            print(f"  - Git Branch: {params.git_branch}")
        elif getattr(params, "git_commit", None):
            print(f"  - Git Commit: {params.git_commit}")
        else:
            print("  - Git Branch/Tag/Commit: Not Specified")
        if getattr(params, "git_depth", None) is not None:
            print(f"  - Git Clone Depth: {params.git_depth}")
    elif params.command == "blind-scan":
        print("  - Method: Blind Scan (hash-based scanning)")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
        print(f"  - FossID CLI Path: {getattr(params, 'fossid_cli_path', '/usr/bin/fossid-cli')}")
    elif params.command == "import-da":
        print("  - Method: Dependency Analysis Import")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
    elif params.command == "import-sbom":
        print("  - Method: SBOM Import")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
    else:
        print(f"  - Method: Unknown ({params.command})")

    if params.command in ["scan", "scan-git", "blind-scan"]:
        print("\nScan Parameters:")
        print(
            f"  - Auto-ID File Licenses: {'Yes' if getattr(params, 'autoid_file_licenses', False) else 'No'}"
        )
        print(
            f"  - Auto-ID File Copyrights: {'Yes' if getattr(params, 'autoid_file_copyrights', False) else 'No'}"
        )
        print(
            f"  - Auto-ID Pending IDs: {'Yes' if getattr(params, 'autoid_pending_ids', False) else 'No'}"
        )
        print(f"  - Delta Scan: {'Yes' if getattr(params, 'delta_scan', False) else 'No'}")
        print(f"  - Identification Reuse: {'Yes' if getattr(params, 'id_reuse', False) else 'No'}")
        if getattr(params, "id_reuse", False):
            print(f"    - Reuse Type: {getattr(params, 'id_reuse_type', 'N/A')}")
            if getattr(params, "id_reuse_type", "") in {"project", "scan"}:
                print(f"    - Reuse Source Name: {getattr(params, 'id_reuse_source', 'N/A')}")

    print("\nAnalysis Performed:")

    # Determine what scans were actually performed using the same logic as the handlers
    scan_operations = determine_scans_to_run(params)
    kb_scan_performed = scan_operations.get("run_kb_scan", False)
    da_requested = scan_operations.get("run_dependency_analysis", False)

    # Add durations to output only for KB scan and Dependency Analysis
    if kb_scan_performed:
        kb_duration_str = (
            format_duration(durations.get("kb_scan", 0)) if durations.get("kb_scan") else "N/A"
        )
        print(f"  - Signature Scan: Yes (Duration: {kb_duration_str})")
    else:
        print(f"  - Signature Scan: No")

    if da_completed:
        da_duration_str = (
            format_duration(durations.get("dependency_analysis", 0))
            if durations.get("dependency_analysis")
            else "N/A"
        )
        print(f"  - Dependency Analysis: Yes (Duration: {da_duration_str})")
    elif params.command == "import-da":
        print(f"  - Dependency Analysis: Imported")
    elif params.command == "import-sbom":
        print(f"  - SBOM Imported: Yes")
    elif da_requested and not da_completed:
        print(f"  - Dependency Analysis: Requested but failed/incomplete")
    else:
        print(f"  - Dependency Analysis: No")

    print("------------------------------------")
