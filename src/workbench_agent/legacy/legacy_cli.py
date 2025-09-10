# workbench_agent/legacy_cli.py

import argparse
import logging
import os
import sys
import warnings
from argparse import RawTextHelpFormatter

from workbench_agent.exceptions import ValidationError

logger = logging.getLogger("workbench-agent")


# Validation functions for legacy CLI (self-contained)
def positive_int(value):
    """Validate that a value is a positive integer."""
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f"Invalid positive integer: {value}")
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid positive integer: {value}")


def non_negative_int(value):
    """Validate that a value is a non-negative integer."""
    try:
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError(f"Invalid non-negative integer: {value}")
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid non-negative integer: {value}")


def non_empty_string(value):
    """Validate that a value is a non-empty string."""
    if not value or not value.strip():
        raise argparse.ArgumentTypeError("Value cannot be empty")
    return value.strip()


def create_legacy_parser():
    """
    Create parser for legacy usage with flat arguments (no subcommands).
    Matches the original wb-agent.py argument structure for backward compatibility.

    Returns:
        argparse.ArgumentParser: Parser configured for legacy usage with flat arguments
    """
    parser = argparse.ArgumentParser(
        description="FossID Workbench Agent - Legacy Mode (DEPRECATED)",
        formatter_class=RawTextHelpFormatter,
        epilog="""
Legacy Usage Examples (DEPRECATED - please migrate to modern commands):
  # Standard scan (legacy)  
  workbench-agent --project_code MYPROJ --scan_code MYSCAN01 --path ./src --run_dependency_analysis

  # Blind scan (legacy)
  workbench-agent --project_code MYPROJ --scan_code MYSCAN01 --path ./src --blind_scan

MIGRATION GUIDE:
  Old: workbench-agent --blind_scan         → New: workbench-agent blind-scan
  Old: workbench-agent --project_code ...   → New: workbench-agent scan --project-name "..."
  Old: --project_code MYPROJ                → New: --project-name "My Project"
  Old: --scan_code MYSCAN01                 → New: --scan-name "My Scan v1.0"

Environment Variables for Credentials:
  WORKBENCH_URL    : API Endpoint URL (e.g., https://workbench.example.com/api.php)
  WORKBENCH_USER   : Workbench Username
  WORKBENCH_TOKEN  : Workbench API Token
""",
    )

    # Required arguments (legacy underscore format)
    required = parser.add_argument_group("Required Arguments")
    required.add_argument(
        "--api_url",
        help="API Endpoint URL (e.g., https://workbench.example.com/api.php). Overrides WORKBENCH_URL env var.",
        default=os.getenv("WORKBENCH_URL"),
        required=not os.getenv("WORKBENCH_URL"),
        type=non_empty_string,
        metavar="URL",
    )
    required.add_argument(
        "--api_user",
        help="Workbench Username. Overrides WORKBENCH_USER env var.",
        default=os.getenv("WORKBENCH_USER"),
        required=not os.getenv("WORKBENCH_USER"),
        type=non_empty_string,
        metavar="USER",
    )
    required.add_argument(
        "--api_token",
        help="Workbench API Token. Overrides WORKBENCH_TOKEN env var.",
        default=os.getenv("WORKBENCH_TOKEN"),
        required=not os.getenv("WORKBENCH_TOKEN"),
        type=non_empty_string,
        metavar="TOKEN",
    )
    required.add_argument(
        "--project_code",
        help="[DEPRECATED] Project code to associate the scan with. Use modern commands with --project-name instead.",
        type=non_empty_string,
        required=True,
        metavar="CODE",
    )
    required.add_argument(
        "--scan_code",
        help="[DEPRECATED] Scan code to create or use. Use modern commands with --scan-name instead.",
        type=non_empty_string,
        required=True,
        metavar="CODE",
    )
    required.add_argument(
        "--path",
        help="Path of the directory where the files to be scanned reside",
        type=str,
        required=True,
    )

    # Optional arguments - ALL legacy underscore format
    optional = parser.add_argument_group("Optional Arguments")
    optional.add_argument(
        "--log",
        help="Logging level (Default: ERROR)",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="ERROR",
    )

    # Scan Options (legacy underscore format)
    scan_opts = parser.add_argument_group("Scan Options")
    scan_opts.add_argument(
        "--limit", help="Limits KB scan results (Default: 10)", type=positive_int, default=10
    )
    scan_opts.add_argument(
        "--sensitivity",
        help="Sets KB snippet sensitivity (Default: 10)",
        type=positive_int,
        default=10,
    )
    scan_opts.add_argument(
        "--recursively_extract_archives",
        help="Recursively extract nested archives. Default false.",
        action="store_true",
        default=False,
    )
    scan_opts.add_argument(
        "--jar_file_extraction",
        help="Control default behavior related to extracting jar files. Default false.",
        action="store_true",
        default=False,
    )

    # Dependency Analysis (legacy underscore format)
    da_opts = parser.add_argument_group("Dependency Analysis Options")
    da_opts.add_argument(
        "--run_dependency_analysis",
        help="Initiate dependency analysis after finishing scanning for matches in KB.",
        action="store_true",
        default=False,
    )
    da_opts.add_argument(
        "--run_only_dependency_analysis",
        help="Scan only for dependencies, no results from KB.",
        action="store_true",
        default=False,
    )

    # Auto-ID Options (legacy underscore format)
    autoid_opts = parser.add_argument_group("Auto-Identification Options")
    autoid_opts.add_argument(
        "--auto_identification_detect_declaration",
        help="Automatically detect license declaration inside files.",
        action="store_true",
        default=False,
    )
    autoid_opts.add_argument(
        "--auto_identification_detect_copyright",
        help="Automatically detect copyright statements inside files.",
        action="store_true",
        default=False,
    )
    autoid_opts.add_argument(
        "--auto_identification_resolve_pending_ids",
        help="Automatically resolve pending identifications.",
        action="store_true",
        default=False,
    )
    autoid_opts.add_argument(
        "--delta_only",
        help="Scan only delta (newly added files from last scan).",
        action="store_true",
        default=False,
    )

    # ID Reuse Options (legacy underscore format)
    reuse_group = parser.add_argument_group("Identification Reuse Options")
    reuse_group.add_argument(
        "--reuse_identifications",
        help="Enable reuse of existing identifications to speed up scan process.",
        action="store_true",
        default=False,
    )
    reuse_group.add_argument(
        "--identification_reuse_type",
        help="Specify the source type for identification reuse:\n"
        "  'any'              - use any existing identification in the system\n"
        "  'only_me'          - only reuse identifications made by the current user token\n"
        "  'specific_project' - reuse identifications from a specific project (requires --specific_code)\n"
        "  'specific_scan'    - reuse identifications from a specific scan (requires --specific_code)",
        choices=["any", "only_me", "specific_project", "specific_scan"],
        default="any",
    )
    reuse_group.add_argument(
        "--specific_code",
        help="Name of the project or scan to reuse identifications from.\n"
        "Required when --identification_reuse_type is 'specific_project' or 'specific_scan'.",
    )

    # Advanced Options (legacy underscore format)
    advanced_opts = parser.add_argument_group("Advanced Options")
    advanced_opts.add_argument(
        "--no_advanced_match_scoring",
        help="Disable advanced match scoring which by default is enabled.",
        dest="advanced_match_scoring",
        action="store_false",
    )
    advanced_opts.add_argument(
        "--match_filtering_threshold",
        help="Minimum length, in characters, of the snippet to be considered valid after applying match filtering.",
        type=non_negative_int,
        default=-1,
    )
    advanced_opts.add_argument(
        "--chunked_upload",
        help="For files bigger than 8 MB uploading will be done using chunks.",
        action="store_true",
        default=False,
    )

    # Result Options (legacy underscore format)
    result_opts = parser.add_argument_group("Result Options")
    result_opts.add_argument(
        "--path-result",
        help="Save results to specified path",
        type=str,
    )

    # CLI options for blind scan (legacy underscore format)
    cli_args = parser.add_argument_group("CLI Options (for blind scan)")
    cli_args.add_argument(
        "--cli_path",
        help="Path to fossid-cli executable (Default: /usr/bin/fossid-cli)",
        type=str,
        default="/usr/bin/fossid-cli",
    )
    cli_args.add_argument(
        "--config_path",
        help="Path to fossid.conf configuration file (Default: /etc/fossid.conf)",
        type=str,
        default="/etc/fossid.conf",
    )

    # Monitoring options (legacy underscore format)
    monitor_args = parser.add_argument_group("Scan Monitoring Options")
    monitor_args.add_argument(
        "--scan_number_of_tries",
        help="Number of status checks before timeout (Default: 960)",
        type=positive_int,
        default=960,
    )
    monitor_args.add_argument(
        "--scan_wait_time",
        help="Seconds between status checks (Default: 30)",
        type=positive_int,
        default=30,
    )

    # Legacy-specific options
    legacy_group = parser.add_argument_group("Legacy Options")
    legacy_group.add_argument(
        "--blind_scan",
        help="Use CLI to generate file hashes and upload hash file (legacy mode). Use 'blind-scan' command instead.",
        action="store_true",
        default=False,
    )

    # Result retrieval options (from original script)
    result_group = parser.add_argument_group("Result Retrieval Options")
    result_group.add_argument(
        "--get_scan_identified_components",
        help="Retrieve the list of identified components instead of licenses.",
        action="store_true",
        default=False,
    )
    result_group.add_argument(
        "--scans_get_policy_warnings_counter",
        help="Retrieve policy warnings information at scan level.",
        action="store_true",
        default=False,
    )
    result_group.add_argument(
        "--projects_get_policy_warnings_info",
        help="Retrieve policy warnings information at project level.",
        action="store_true",
        default=False,
    )
    result_group.add_argument(
        "--scans_get_results",
        help="Retrieve scan results/matches.",
        action="store_true",
        default=False,
    )

    return parser


def validate_reuse_parameters(args):
    """
    Validate ID reuse parameters for legacy interface.

    Args:
        args: Parsed arguments namespace

    Raises:
        ValidationError: If validation fails
    """
    if getattr(args, "reuse_identifications", False):
        reuse_type = getattr(args, "identification_reuse_type", None)
        specific_code = getattr(args, "specific_code", None)

        if reuse_type in ["specific_project", "specific_scan"] and not specific_code:
            raise ValidationError(
                "Specific code is required when identification_reuse_type is 'specific_project' or 'specific_scan'"
            )

        # Add warning for conflicting arguments
        if reuse_type not in ["specific_project", "specific_scan"] and specific_code:
            logger.warning(
                f"--specific_code ('{specific_code}') provided but --identification_reuse_type is '{reuse_type}'. Source code will be ignored."
            )
            args.specific_code = None


def parse_legacy_args():
    """
    Parse legacy command line arguments with flat structure (no subcommands).

    Returns:
        argparse.Namespace: Parsed arguments with legacy underscore format

    Raises:
        ValidationError: If validation fails
    """
    # Enhanced deprecation warning
    warnings.warn(
        "Legacy argument style is deprecated and will be removed in a future version. "
        "Please migrate to modern command-based interface. "
        "Example: workbench-agent scan --project-name 'Project' --scan-name 'Scan'",
        DeprecationWarning,
        stacklevel=3,
    )

    parser = create_legacy_parser()
    args = parser.parse_args()

    # Legacy-specific validation
    validate_reuse_parameters(args)

    # Path validation for both regular and blind scan
    if not getattr(args, "run_only_dependency_analysis", False) and not args.path:
        raise ValidationError("Path is required unless using --run_only_dependency_analysis")

    if args.path and not os.path.exists(args.path):
        raise ValidationError(f"Path does not exist: {args.path}")

    if getattr(args, "run_dependency_analysis", False) and getattr(
        args, "run_only_dependency_analysis", False
    ):
        raise ValidationError(
            "Cannot use both --run_dependency_analysis and --run_only_dependency_analysis"
        )

    # Create aliases for handler compatibility
    # Map legacy underscore to both dash and underscore for maximum compatibility
    args.project_name = getattr(args, "project_code", None)
    args.scan_name = getattr(args, "scan_code", None)
    args.id_reuse = getattr(args, "reuse_identifications", False)
    args.id_reuse_type = getattr(args, "identification_reuse_type", "any")
    args.id_reuse_source = getattr(args, "specific_code", None)
    args.autoid_file_licenses = getattr(args, "auto_identification_detect_declaration", False)
    args.autoid_file_copyrights = getattr(args, "auto_identification_detect_copyright", False)
    args.autoid_pending_ids = getattr(args, "auto_identification_resolve_pending_ids", False)
    args.delta_scan = getattr(args, "delta_only", False)
    args.dependency_analysis_only = getattr(args, "run_only_dependency_analysis", False)
    args.no_wait = False  # Legacy doesn't support no-wait
    args.path_result = getattr(args, "path-result", None)

    # Map legacy API credentials to modern format
    args.api_url = getattr(args, "api_url", None)
    args.api_user = getattr(args, "api_user", None)
    args.api_token = getattr(args, "api_token", None)

    return args
