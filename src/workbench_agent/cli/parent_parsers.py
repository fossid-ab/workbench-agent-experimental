# workbench_agent/cli/parent_parsers.py

"""
Parent parser definitions for CLI argument groups.

This module contains all the parent parsers that define common argument groups
used across different CLI commands.
"""

import argparse
import os

from .parser import TrackingArgumentParser


def create_workbench_connection_parser():
    """Create parent parser for Workbench connection arguments."""
    workbench_connection_parent = TrackingArgumentParser(add_help=False)
    workbench_connection_args = workbench_connection_parent.add_argument_group(
        "Workbench Connection"
    )
    workbench_connection_args.add_argument(
        "--api-url",
        help="API Endpoint URL (e.g., https://workbench.example.com/api.php). Overrides WORKBENCH_URL env var.",
        default=os.getenv("WORKBENCH_URL"),
        required=not os.getenv("WORKBENCH_URL"),
        metavar="URL",
    )
    workbench_connection_args.add_argument(
        "--api-user",
        help="Workbench Username. Overrides WORKBENCH_USER env var.",
        default=os.getenv("WORKBENCH_USER"),
        required=not os.getenv("WORKBENCH_USER"),
        metavar="USER",
    )
    workbench_connection_args.add_argument(
        "--api-token",
        help="Workbench API Token. Overrides WORKBENCH_TOKEN env var.",
        default=os.getenv("WORKBENCH_TOKEN"),
        required=not os.getenv("WORKBENCH_TOKEN"),
        metavar="TOKEN",
    )
    return workbench_connection_parent


def create_cli_behaviors_parser():
    """Create parent parser for Workbench Agent behavior arguments."""
    cli_behaviors_parent = TrackingArgumentParser(add_help=False)
    cli_behaviors_args = cli_behaviors_parent.add_argument_group("CLI Behavior")
    cli_behaviors_args.add_argument(
        "--log",
        help="Logging level (Default: WARNING)",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
    )
    return cli_behaviors_parent


def create_id_assist_control_parser():
    """Create parent parser for ID Assist control arguments."""
    id_assist_control_parent = TrackingArgumentParser(add_help=False)
    id_assist_control_args = id_assist_control_parent.add_argument_group("ID Assist Controls")
    id_assist_control_args.add_argument(
        "--no-advanced-match-scoring",
        help="Disable advanced match scoring (enabled by default).",
        dest="advanced_match_scoring",
        action="store_false",
        default=True,
    )
    id_assist_control_args.add_argument(
        "--match-filtering-threshold",
        help="Minimum snippet length in characters for match filtering. Set to 0 to disable (Default: uses server config).",
        type=int,
        metavar="CHARS",
    )
    ## TODO: Add ProjectScan Control
    return id_assist_control_parent


def create_identification_control_parser():
    """Create parent parser for identification control arguments."""
    identification_control_parent = TrackingArgumentParser(add_help=False)
    identification_control_args = identification_control_parent.add_argument_group(
        "Identification Controls"
    )
    identification_control_args.add_argument(
        "--autoid-file-licenses",
        help="Auto-Identify license declarations in files.",
        action="store_true",
        default=False,
    )
    identification_control_args.add_argument(
        "--autoid-file-copyrights",
        help="Auto-Identify copyright statements in files.",
        action="store_true",
        default=False,
    )
    identification_control_args.add_argument(
        "--autoid-pending-ids",
        help="Auto-Identify pending files using the Top Match.",
        action="store_true",
        default=False,
    )

    # Mutually exclusive group for identification reuse options
    reuse_group = identification_control_parent.add_mutually_exclusive_group()
    reuse_group.add_argument(
        "--reuse-any-identification",
        help="Reuse any existing identification from the system.",
        action="store_true",
        default=False,
    )
    reuse_group.add_argument(
        "--reuse-my-identifications",
        help="Only reuse identifications made by the current user.",
        action="store_true",
        default=False,
    )
    reuse_group.add_argument(
        "--reuse-scan-ids",
        help="Reuse identifications from a specific scan.",
        metavar="SCAN_NAME",
    )
    reuse_group.add_argument(
        "--reuse-project-ids",
        help="Reuse identifications from a specific project.",
        metavar="PROJECT_NAME",
    )

    identification_control_args.add_argument(
        "--replace-existing-identifications",
        help="Replace existing identifications during scan.",
        action="store_true",
        default=False,
    )
    return identification_control_parent


def create_scan_control_parser():
    """Create parent parser for scan control arguments."""
    scan_control_parent = TrackingArgumentParser(add_help=False)
    scan_control_args = scan_control_parent.add_argument_group("Scan Configuration")
    scan_control_args.add_argument(
        "--limit", help="Limits KB scan results (Default: 10)", type=int, default=10
    )
    scan_control_args.add_argument(
        "--sensitivity",
        help="Sets Snippet Detection sensitivity (Default: 10)",
        type=int,
        default=10,
    )

    return scan_control_parent


def create_scan_operations_parser():
    """Create parent parser for scan operation control arguments."""
    scan_operations_parent = TrackingArgumentParser(add_help=False)
    scan_ops_args = scan_operations_parent.add_argument_group("Scan Operations")
    scan_ops_args.add_argument(
        "--run-dependency-analysis",
        help="Run dependency analysis after KB scan.",
        action="store_true",
        default=False,
    )
    scan_ops_args.add_argument(
        "--dependency-analysis-only",
        help="Run dependency analysis without performing a KB scan. Mutually exclusive with --run-dependency-analysis.",
        action="store_true",
        default=False,
    )
    scan_ops_args.add_argument(
        "--no-wait",
        help="Exit after confirming scan has started instead of waiting for completion.",
        action="store_true",
        default=False,
    )
    scan_ops_args.add_argument(
        "--delta-scan",
        help="For recurring scans, only scan new/modified files.",
        action="store_true",
        default=False,
    )
    scan_ops_args.add_argument(
        "--recursively-extract-archives",
        help="Recursively extract nested archives (Default: True).",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    scan_ops_args.add_argument(
        "--jar-file-extraction",
        help="Control extraction of jar files (Default: False).",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    scan_ops_args.add_argument(
        "--scan-failed-only",
        help="Only scan files that failed in the previous scan.",
        action="store_true",
        default=False,
    )
    scan_ops_args.add_argument(
        "--full-file-only",
        help="Return only full file matches regardless of sensitivity setting.",
        action="store_true",
        default=False,
    )
    return scan_operations_parent


def create_monitoring_parser():
    """Create parent parser for monitoring options."""
    monitoring_parent = TrackingArgumentParser(add_help=False)
    monitor_args = monitoring_parent.add_argument_group("Scan Monitoring Options")
    monitor_args.add_argument(
        "--scan-number-of-tries",
        help="Number of status checks before timeout (Default: 960)",
        type=int,
        default=960,
    )
    monitor_args.add_argument(
        "--scan-wait-time", help="Seconds between status checks (Default: 30)", type=int, default=30
    )
    return monitoring_parent


def create_result_options_parser():
    """Create parent parser for result display and save options."""
    result_options_parent = TrackingArgumentParser(add_help=False)
    results_display_args = result_options_parent.add_argument_group("Result Display & Save Options")
    results_display_args.add_argument(
        "--show-licenses",
        help="Shows all licenses found by the identification process.",
        action="store_true",
        default=False,
    )
    results_display_args.add_argument(
        "--show-components",
        help="Shows all components found by the identification process.",
        action="store_true",
        default=False,
    )
    results_display_args.add_argument(
        "--show-dependencies",
        help="Shows all components found by Dependency Analysis.",
        action="store_true",
        default=False,
    )
    results_display_args.add_argument(
        "--show-scan-metrics",
        help="Show metrics on file identifications (total files, pending id, identified, no matches).",
        action="store_true",
        default=False,
    )
    results_display_args.add_argument(
        "--show-policy-warnings",
        help="Shows Policy Warnings in identified components or dependencies.",
        action="store_true",
        default=False,
    )
    results_display_args.add_argument(
        "--show-vulnerabilities",
        help="Shows a summary of vulnerabilities found in the scan.",
        action="store_true",
        default=False,
    )
    results_display_args.add_argument(
        "--result-save-path",
        help="Save the requested results to this file/directory (JSON format).",
        metavar="PATH",
    )
    return result_options_parent


def create_project_scan_target_parser():
    """Create parent parser for project and scan target options."""
    project_scan_target_parent = TrackingArgumentParser(add_help=False)
    target_args = project_scan_target_parent.add_argument_group("Project & Scan Target")
    target_args.add_argument(
        "--project-name",
        help="The Name of the Workbench Project to interact with.",
        required=True,
        metavar="NAME",
    )
    target_args.add_argument(
        "--scan-name",
        help="The Name of the Workbench Scan to interact with.",
        required=True,
        metavar="NAME",
    )
    return project_scan_target_parent


def create_git_options_parser():
    """Create parent parser for Git scanning options."""
    git_options_parent = TrackingArgumentParser(add_help=False)
    git_args = git_options_parent.add_argument_group("Git Scanning Options")
    git_args.add_argument(
        "--git-url", help="URL of the Git repository to scan.", type=str, required=True
    )
    git_args.add_argument(
        "--git-depth", help="Specify clone depth (integer, optional).", type=int, metavar="DEPTH"
    )

    # Use mutually exclusive group for git references
    ref_group = git_options_parent.add_mutually_exclusive_group(required=True)
    ref_group.add_argument(
        "--git-branch", help="The git branch to scan.", type=str, metavar="BRANCH"
    )
    ref_group.add_argument(
        "--git-tag", help="The git tag to scan.", type=str, metavar="TAG"
    )
    ref_group.add_argument(
        "--git-commit", help="The git commit to scan.", type=str, metavar="COMMIT"
    )
    return git_options_parent


def create_common_parent_parsers():
    """
    Create parent parsers for common argument groups.

    Returns:
        dict: Dictionary of parent parsers keyed by name
    """
    return {
        "workbench_connection": create_workbench_connection_parser(),
        "cli_behaviors": create_cli_behaviors_parser(),
        "id_assist_control": create_id_assist_control_parser(),
        "identification_control": create_identification_control_parser(),
        "scan_control": create_scan_control_parser(),
        "scan_operations": create_scan_operations_parser(),
        "monitoring": create_monitoring_parser(),
        "result_options": create_result_options_parser(),
        "project_scan_target": create_project_scan_target_parser(),
        "git_options": create_git_options_parser(),
    }
