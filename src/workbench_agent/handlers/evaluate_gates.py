# workbench_agent/handlers/evaluate_gates.py

import argparse
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

from workbench_agent.exceptions import ApiError, NetworkError, ProcessError, ProcessTimeoutError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.scan_workflows import get_workbench_links

logger = logging.getLogger("workbench-agent")

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

# Constants
MAX_DISPLAY_FILES = 10
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


@dataclass
class GateResult:
    """Data class to represent the result of a gate check."""

    passed: bool
    count: int
    message: str
    link_key: Optional[str] = None


@dataclass
class GateResults:
    """Container for all gate check results."""

    pending_files: GateResult
    policy_warnings: GateResult
    vulnerabilities: GateResult

    @property
    def all_passed(self) -> bool:
        return (
            self.pending_files.passed
            and self.policy_warnings.passed
            and self.vulnerabilities.passed
        )


def _extract_policy_count(policy_data: Any) -> int:
    """
    Extract policy warning count from API response, handling different response formats.

    Args:
        policy_data: The API response data

    Returns:
        int: The policy warning count
    """
    if not isinstance(policy_data, dict):
        logger.warning(f"Unexpected policy warnings data format: {policy_data}")
        return 0

    # Handle nested data structure
    if "data" in policy_data and isinstance(policy_data["data"], dict):
        return policy_data["data"].get("policy_warnings_total", 0)

    # Handle flat structure with fallback
    return policy_data.get("policy_warnings_total", policy_data.get("total", 0))


def _display_pending_files(pending_files: Dict[str, str], count: int, show_files: bool) -> None:
    """
    Display pending files information.

    Args:
        pending_files: Dictionary of file IDs to file paths
        count: Total count of pending files
        show_files: Whether to show individual file paths
    """
    if not show_files or count == 0:
        return

    print("\nPending Files:")
    file_items = list(pending_files.items())

    for i, (_, file_path) in enumerate(file_items):
        if i >= MAX_DISPLAY_FILES:
            break
        print(f"  {file_path}")

    if count > MAX_DISPLAY_FILES:
        remaining = count - MAX_DISPLAY_FILES
        print(
            f"  ... and {remaining} more files (showing first {MAX_DISPLAY_FILES} of {count} total)"
        )


def _display_vulnerability_breakdown(vuln_counts: Dict[str, int]) -> None:
    """
    Display vulnerability counts by severity.

    Args:
        vuln_counts: Dictionary of severity levels to counts
    """
    total_vulns = sum(vuln_counts.values())
    print(f"\n⚠️ Warning: Found {total_vulns} vulnerabilities. By CVSS Score:")

    for severity in SEVERITY_ORDER:
        if vuln_counts[severity] > 0:
            print(f" - {severity.upper()}: {vuln_counts[severity]}")


def _check_pending_files_gate(
    workbench: "WorkbenchAPI", scan_code: str, params: "argparse.Namespace"
) -> GateResult:
    """
    Check the pending files gate.

    Args:
        workbench: The Workbench API client
        scan_code: The scan identifier
        params: Command line parameters

    Returns:
        GateResult: The result of the pending files check
    """
    print("\nChecking for pending files...")
    pending_files = {}
    count = 0

    try:
        pending_files = workbench.get_pending_files(scan_code)
        count = len(pending_files)
    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for pending files: {e}")
        logger.warning(f"Error checking pending files for scan '{scan_code}': {e}")

        if params.fail_on_pending:
            return GateResult(
                passed=False,
                count=0,
                message="❌ Gate Failed: Unable to verify pending files status due to API error",
            )

    # Determine gate result
    if count > 0:
        _display_pending_files(pending_files, count, getattr(params, "show_pending_files", False))

        if params.fail_on_pending:
            return GateResult(
                passed=False,
                count=count,
                message=f"❌ Gate Failed: Found {count} pending files that require identification.",
                link_key="pending",
            )
        else:
            print(f"\n⚠️ Warning: Found {count} pending files that require identification.")
            print(
                "Note: Gate is not set to fail on pending files (--fail-on-pending not specified)."
            )
            return GateResult(
                passed=True, count=count, message=f"Found {count} pending files", link_key="pending"
            )
    else:
        print("\n✅ No pending files found - all files have been identified.")
        return GateResult(passed=True, count=0, message="No pending files found")


def _check_policy_warnings_gate(
    workbench: "WorkbenchAPI", scan_code: str, params: "argparse.Namespace"
) -> GateResult:
    """
    Check the policy warnings gate.

    Args:
        workbench: The Workbench API client
        scan_code: The scan identifier
        params: Command line parameters

    Returns:
        GateResult: The result of the policy warnings check
    """
    print("\nChecking for license policy warnings...")

    try:
        policy_data = workbench.get_policy_warnings_counter(scan_code)
        count = _extract_policy_count(policy_data)

        if count > 0:
            if params.fail_on_policy:
                return GateResult(
                    passed=False,
                    count=count,
                    message=f"❌ Gate Failed: Found {count} policy warnings.",
                    link_key="policy",
                )
            else:
                print(f"\n⚠️ Warning: Found {count} license policy warnings.")
                print(
                    "Note: Gate is not set to fail on license policy warnings (--fail-on-policy not specified)."
                )
                return GateResult(
                    passed=True,
                    count=count,
                    message=f"Found {count} policy warnings",
                    link_key="policy",
                )
        else:
            print("\n✅ No policy warnings found.")
            return GateResult(passed=True, count=0, message="No policy warnings found")

    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for policy warnings: {e}")
        logger.warning(f"Error checking policy warnings for scan '{scan_code}': {e}")

        if params.fail_on_policy:
            return GateResult(
                passed=False,
                count=0,
                message="❌ Gate Failed: Unable to verify policy warnings status due to API error",
            )
        else:
            return GateResult(passed=True, count=0, message="Policy check failed")


def _check_vulnerabilities_gate(
    workbench: "WorkbenchAPI", scan_code: str, params: "argparse.Namespace"
) -> GateResult:
    """
    Check the vulnerabilities gate.

    Args:
        workbench: The Workbench API client
        scan_code: The scan identifier
        params: Command line parameters

    Returns:
        GateResult: The result of the vulnerabilities check
    """
    print("\nChecking for vulnerabilities...")

    try:
        vulnerabilities = workbench.list_vulnerabilities(scan_code)

        # Count vulnerabilities by severity
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
            else:
                vuln_counts["other"] += 1

        total_vulns = sum(vuln_counts.values())

        if total_vulns > 0:
            # Check if we should fail based on severity threshold
            if params.fail_on_vuln_severity:
                threshold_idx = SEVERITY_ORDER.index(params.fail_on_vuln_severity)

                for severity in SEVERITY_ORDER[: threshold_idx + 1]:
                    if vuln_counts[severity] > 0:
                        _display_vulnerability_breakdown(vuln_counts)
                        return GateResult(
                            passed=False,
                            count=total_vulns,
                            message=f"❌ Gate Failed: Found vulnerabilities with severity {severity.upper()} (threshold: {params.fail_on_vuln_severity.upper()})",
                            link_key="vulnerabilities",
                        )

                print(
                    f"\n✅ No vulnerabilities found with severity {params.fail_on_vuln_severity.upper()} or higher."
                )
                if total_vulns > 0:
                    _display_vulnerability_breakdown(vuln_counts)
                return GateResult(
                    passed=True,
                    count=total_vulns,
                    message=f"Found {total_vulns} vulnerabilities below threshold",
                )
            else:
                _display_vulnerability_breakdown(vuln_counts)
                print(
                    "Note: Gate is not set to fail on vulnerabilities (--fail-on-vuln-severity not specified)."
                )
                return GateResult(
                    passed=True, count=total_vulns, message=f"Found {total_vulns} vulnerabilities"
                )
        else:
            print("\n✅ No vulnerabilities found.")
            return GateResult(passed=True, count=0, message="No vulnerabilities found")

    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for vulnerabilities: {e}")
        logger.warning(f"Error checking vulnerabilities for scan '{scan_code}': {e}")

        if params.fail_on_vuln_severity:
            return GateResult(
                passed=False,
                count=0,
                message="❌ Gate Failed: Unable to verify vulnerabilities status due to API error",
            )
        else:
            return GateResult(passed=True, count=0, message="Vulnerability check failed")


def _display_workbench_links(
    workbench_links: Optional[Dict[str, Any]], results: GateResults
) -> None:
    """
    Display relevant Workbench links based on gate results.

    Args:
        workbench_links: Dictionary of workbench links
        results: The gate results containing link information
    """
    if not workbench_links:
        return

    # Show specific links for failed or warning gates
    for result in [results.pending_files, results.policy_warnings, results.vulnerabilities]:
        if result.link_key and result.link_key in workbench_links and result.count > 0:
            link_info = workbench_links[result.link_key]
            print(f"\n🔗 {link_info['message']}: {link_info['url']}")


def _print_gate_summary(params: "argparse.Namespace", results: GateResults) -> None:
    """
    Print the final gate evaluation summary.

    Args:
        params: Command line parameters
        results: The gate results
    """
    print("\n" + "=" * 50)
    print("Gate Evaluation Summary:")
    print("=" * 50)

    # Pending files summary
    if params.fail_on_pending:
        status = "✅ PASSED" if results.pending_files.passed else "❌ FAILED"
        print(f"Pending Files Gate: {status} ({results.pending_files.count} pending files)")
    else:
        icon = "✅" if results.pending_files.count == 0 else "⚠️"
        print(f"Pending Files: {results.pending_files.count} files {icon}")

    # Policy warnings summary
    if params.fail_on_policy:
        status = "✅ PASSED" if results.policy_warnings.passed else "❌ FAILED"
        print(f"Policy Warnings Gate: {status} ({results.policy_warnings.count} warnings)")
    else:
        icon = "✅" if results.policy_warnings.count == 0 else "⚠️"
        print(f"Policy Warnings: {results.policy_warnings.count} warnings {icon}")

    # Vulnerabilities summary
    if params.fail_on_vuln_severity:
        status = "✅ PASSED" if results.vulnerabilities.passed else "❌ FAILED"
        print(f"Vulnerability Gate: {status} (Threshold: {params.fail_on_vuln_severity.upper()})")
    else:
        icon = "✅" if results.vulnerabilities.count == 0 else "⚠️"
        print(f"Vulnerabilities: {results.vulnerabilities.count} {icon}")

    print("=" * 50)
    status = "✅ PASSED" if results.all_passed else "❌ FAILED"
    print(f"Overall Gate Status: {status}")
    print("=" * 50)


@handler_error_wrapper
def handle_evaluate_gates(workbench: "WorkbenchAPI", params: "argparse.Namespace") -> bool:
    """
    Handler for the 'evaluate-gates' command.
    Checks scan status and evaluates policy warnings.

    Args:
        workbench: The Workbench API client
        params: Command line parameters

    Returns:
        bool: True if all gates passed, False if any gate failed

    Raises:
        Various exceptions based on errors that occur during the process
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Resolve project and scan (find only)
    print("\nResolving scan for gate evaluation...")
    project_code = workbench.resolve_project(params.project_name, create_if_missing=False)
    scan_code, scan_id = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=False,
        params=params,
    )

    # Ensure scan processes are idle before evaluating gates
    print("\nEnsuring scans finished before evaluating gates...")
    try:
        workbench.check_and_wait_for_process(
            process_types=["SCAN", "DEPENDENCY_ANALYSIS"],
            scan_code=scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )
        logging.info("Verified all Scan processes are idle. Checking gates...")
    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        print(f"\n❌ Gate Evaluation Failed: Could not verify scan completion: {e}")
        return False

    # Generate all Workbench links once for use throughout the handler
    workbench_links = None
    try:
        workbench_links = get_workbench_links(workbench.api_url, scan_id)
    except Exception as e:
        logger.debug(f"Failed to generate Workbench links: {e}")

    # Run all gate checks
    results = GateResults(
        pending_files=_check_pending_files_gate(workbench, scan_code, params),
        policy_warnings=_check_policy_warnings_gate(workbench, scan_code, params),
        vulnerabilities=_check_vulnerabilities_gate(workbench, scan_code, params),
    )

    # Display any relevant Workbench links
    _display_workbench_links(workbench_links, results)

    # Print final summary
    _print_gate_summary(params, results)

    # Show main scan link for users to review results
    if workbench_links and "main" in workbench_links:
        print(f"\n🔗 {workbench_links['main']['message']}: {workbench_links['main']['url']}")

    return results.all_passed
