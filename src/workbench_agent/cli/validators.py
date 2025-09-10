# workbench_agent/cli/validators.py

import logging
import os
from argparse import Namespace

from workbench_agent.exceptions import ValidationError

logger = logging.getLogger("workbench-agent")


def validate_parsed_args(args: Namespace) -> None:
    """
    Validate parsed command-line arguments.

    Args:
        args: Parsed arguments from argparse

    Raises:
        ValidationError: If validation fails
    """
    # Validate API credentials
    _validate_api_credentials(args)

    # Fix API URL format
    _fix_api_url_format(args)

    # Command-specific validation
    _validate_command_specific_args(args)


def _validate_api_credentials(args: Namespace) -> None:
    """Validate that required API credentials are provided."""
    api_url = getattr(args, "api_url", None)
    api_user = getattr(args, "api_user", None)
    api_token = getattr(args, "api_token", None)

    if not api_url or not api_user or not api_token:
        raise ValidationError("API URL, user, and token must be provided")


def _fix_api_url_format(args: Namespace) -> None:
    """Ensure API URL ends with '/api.php'."""
    api_url = getattr(args, "api_url", None)

    if api_url and not api_url.endswith("/api.php"):
        if api_url.endswith("/"):
            api_url = api_url + "api.php"
        else:
            api_url = api_url + "/api.php"
        args.api_url = api_url


def _validate_command_specific_args(args: Namespace) -> None:
    """Validate command-specific arguments."""
    command = getattr(args, "command", None)

    if command in ["scan", "scan-git", "blind-scan"]:
        _validate_scan_commands(args)
    elif command in ["import-da", "import-sbom"]:
        _validate_import_commands(args)
    elif command == "download-reports":
        _validate_download_reports_command(args)
    elif command == "show-results":
        _validate_show_results_command(args)
    elif command == "quick-scan":
        _validate_quick_scan_command(args)


def _validate_scan_commands(args: Namespace) -> None:
    """Validate scan-related commands."""
    command = args.command

    # Validate path for local scan commands
    if command in ["scan", "blind-scan"]:
        path = getattr(args, "path", None)
        if not path:
            raise ValidationError(f"Path is required for {command} command.")
        if not os.path.exists(path):
            raise ValidationError(f"Path does not exist: {path}")

    # Validate ID reuse parameters
    _validate_id_reuse_args(args)


def _validate_id_reuse_args(args: Namespace) -> None:
    """
    Validate new identification reuse arguments.

    Since the new arguments are mutually exclusive at the argparse level,
    validation is mainly about ensuring required parameters are provided.
    The argparse mutually exclusive group handles most validation automatically.
    """
    # Check if any reuse argument is provided
    reuse_args = [
        getattr(args, "reuse_any_identification", False),
        getattr(args, "reuse_my_identifications", False),
        getattr(args, "reuse_scan_ids", None),
        getattr(args, "reuse_project_ids", None),
    ]

    # Count how many reuse arguments are provided (mutually exclusive should ensure max 1)
    provided_reuse_args = sum(1 for arg in reuse_args if arg)

    if provided_reuse_args > 1:
        # This should not happen due to mutually exclusive group, but safety check
        raise ValidationError(
            "Multiple identification reuse arguments provided. Only one reuse option is allowed."
        )

    # Validate that required parameters are provided for arguments that need them
    if getattr(args, "reuse_scan_ids", None) is not None and not args.reuse_scan_ids.strip():
        raise ValidationError("--reuse-scan-ids requires a non-empty scan name.")

    if getattr(args, "reuse_project_ids", None) is not None and not args.reuse_project_ids.strip():
        raise ValidationError("--reuse-project-ids requires a non-empty project name.")


def _validate_import_commands(args: Namespace) -> None:
    """Validate import commands (import-da, import-sbom)."""
    command = args.command
    path = getattr(args, "path", None)

    if not path:
        raise ValidationError(f"Path is required for {command} command")
    if not os.path.exists(path):
        raise ValidationError(f"Path does not exist: {path}")


def _validate_download_reports_command(args: Namespace) -> None:
    """Validate download-reports command."""
    report_scope = getattr(args, "report_scope", None)
    project_name = getattr(args, "project_name", None)
    scan_name = getattr(args, "scan_name", None)

    if report_scope == "project" and not project_name:
        raise ValidationError(
            "Project name is required for project scope report"
        )
    if report_scope == "scan" and not scan_name:
        raise ValidationError("Scan name is required for scan scope report")


def _validate_show_results_command(args: Namespace) -> None:
    """Validate show-results command."""
    show_flags = [
        getattr(args, "show_licenses", False),
        getattr(args, "show_components", False),
        getattr(args, "show_dependencies", False),
        getattr(args, "show_scan_metrics", False),
        getattr(args, "show_policy_warnings", False),
        getattr(args, "show_vulnerabilities", False),
    ]
    if not any(show_flags):
        raise ValidationError("At least one '--show-*' flag must be provided")


def _validate_quick_scan_command(args: Namespace) -> None:
    """Validate quick-scan command."""
    # Allow either positional 'file' or --path
    path = getattr(args, "path", None) or getattr(args, "file", None)
    if not path:
        raise ValidationError("A file must be provided (positional FILE or --path)")
    if not os.path.exists(path) or not os.path.isfile(path):
        raise ValidationError(f"Path does not exist or is not a file: {path}")
    # Normalize to args.path so downstream code can rely on it
    args.path = path
