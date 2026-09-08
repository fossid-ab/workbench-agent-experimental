# workbench_agent/cli/validators.py

import logging
import os
from argparse import Namespace
from typing import Optional

from workbench_agent.api.validation.field_limits import validate_project_scan_target_fields
from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.ecosystem import validate_analyze_ecosystem

logger = logging.getLogger("workbench-agent")


def _strip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


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


def _validate_project_scan_target(args: Namespace, *, scan_required: bool) -> None:
    """Validate project/scan target flag combinations."""
    project_name = _strip(getattr(args, "project_name", None))
    project_code = _strip(getattr(args, "project_code", None))
    scan_name = _strip(getattr(args, "scan_name", None))
    scan_code = _strip(getattr(args, "scan_code", None))

    if project_name and project_code:
        raise ValidationError("Provide --project-name or --project-code (not both)")
    if not project_name and not project_code:
        raise ValidationError("Provide --project-name or --project-code")

    if scan_required:
        if scan_name and scan_code:
            raise ValidationError("Provide --scan-name or --scan-code (not both)")
        if not scan_name and not scan_code:
            raise ValidationError("Provide --scan-name or --scan-code")
        if project_name and scan_code:
            raise ValidationError(
                "Cannot combine --project-name with --scan-code; "
                "use --project-code with --scan-code, or use "
                "--project-name with --scan-name"
            )
        if scan_code and not project_code:
            raise ValidationError(
                "Cannot use --scan-code without --project-code; "
                "use --project-code with --scan-code, or use "
                "--project-name with --scan-name"
            )

    validate_project_scan_target_fields(
        project_name=project_name,
        project_code=project_code,
        scan_name=scan_name,
        scan_code=scan_code,
        scan_required=scan_required,
    )


def _validate_command_specific_args(args: Namespace) -> None:
    """Validate command-specific arguments."""
    command = getattr(args, "command", None)

    if command in ["scan", "scan-git", "blind-scan"]:
        _validate_project_scan_target(args, scan_required=True)
        _validate_scan_commands(args)
    elif command == "analyze":
        _validate_analyze_command(args)
    elif command in ["import-da", "import-sbom"]:
        _validate_project_scan_target(args, scan_required=True)
        _validate_import_commands(args)
    elif command == "download-reports":
        _validate_download_reports_command(args)
    elif command == "show-results":
        _validate_project_scan_target(args, scan_required=True)
        _validate_show_results_command(args)
    elif command == "delete-scan":
        _validate_project_scan_target(args, scan_required=True)
    elif command == "evaluate-gates":
        _validate_project_scan_target(args, scan_required=True)
    elif command == "quick-scan":
        _validate_quick_scan_command(args)


def _validate_analyze_command(args: Namespace) -> None:
    """Validate the analyze command (Toolbox DA pipeline + first-party KB scan)."""
    path = getattr(args, "path", None) or "."
    args.path = path
    if not os.path.exists(path):
        raise ValidationError(f"Path does not exist: {path}")
    if not os.path.isdir(path):
        raise ValidationError(
            f"analyze --path must be a project directory: {path}"
        )

    validate_analyze_ecosystem(args)

    da_timeout = getattr(args, "da_timeout", None)
    if da_timeout is not None and da_timeout <= 0:
        raise ValidationError("--da-timeout must be a positive integer.")

    fossid_conf_path = getattr(args, "fossid_conf_path", None)
    if fossid_conf_path and not os.path.isfile(fossid_conf_path):
        raise ValidationError(f"fossid.conf not found: {fossid_conf_path}")

    toolbox_timeout = getattr(args, "fossid_toolbox_timeout", None)
    if toolbox_timeout is not None and toolbox_timeout <= 0:
        raise ValidationError("fossid-toolbox-timeout must be a positive integer.")

    if getattr(args, "dependency_analysis_only", False) and getattr(
        args, "blind_scan", False
    ):
        raise ValidationError(
            "--dependency-analysis-only cannot be combined with --blind-scan "
            "(there is no first-party source scan to hash)."
        )

    _validate_id_reuse_args(args)


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
        if command == "blind-scan":
            if not os.path.isdir(path) and not path.endswith(".fossid"):
                raise ValidationError("blind-scan path must be a directory or a " ".fossid file.")
            timeout = getattr(args, "fossid_toolbox_timeout", None)
            if timeout is not None and timeout <= 0:
                raise ValidationError("fossid-toolbox-timeout must be a positive integer.")

    # Validate ID reuse parameters
    _validate_id_reuse_args(args)


def _validate_id_reuse_args(args: Namespace) -> None:
    """
    Validate new identification reuse arguments.

    Since the new arguments are mutually exclusive at the argparse level,
    validation is mainly about ensuring required parameters are provided.
    The argparse mutually exclusive group handles most validation.
    """
    # Check if any reuse argument is provided
    reuse_args = [
        getattr(args, "reuse_any_identification", False),
        getattr(args, "reuse_my_identifications", False),
        getattr(args, "reuse_scan_ids", None),
        getattr(args, "reuse_project_ids", None),
    ]

    # Count reuse arguments provided (mutually exclusive ensures max 1)
    provided_reuse_args = sum(1 for arg in reuse_args if arg)

    if provided_reuse_args > 1:
        # This should not happen due to mutually exclusive group
        raise ValidationError("Multiple ID Reuse arguments provided. Only one option is allowed.")

    # Validate required parameters are provided for arguments that need them
    if getattr(args, "reuse_scan_ids", None) is not None and not args.reuse_scan_ids.strip():
        raise ValidationError("--reuse-scan-ids requires a non-empty scan code or name.")

    if getattr(args, "reuse_project_ids", None) is not None and not args.reuse_project_ids.strip():
        raise ValidationError("--reuse-project-ids requires a non-empty project code or name.")


def _validate_import_commands(args: Namespace) -> None:
    """Validate import commands (import-da, import-sbom)."""
    command = args.command
    path = getattr(args, "path", None)

    if not path:
        raise ValidationError(f"Path is required for {command} command")
    if not os.path.exists(path):
        raise ValidationError(f"Path does not exist: {path}")

    # Command-specific validation
    if command == "import-da":
        _validate_da_results_file(path)
    # Future: add import-sbom specific validation here if needed


def _validate_da_results_file(path: str) -> None:
    """
    Best effort validation that the DA results come from ORT or FossID-DA.

    Validates:
    - Path must be a file (not a directory)
    - Filename must be 'analyzer-results.json'

    Args:
        path: Path to the dependency analysis results file

    Raises:
        ValidationError: If validation fails
    """
    if not os.path.isfile(path):
        raise ValidationError(f"The provided path must be a file: {path}")

    filename = os.path.basename(path)
    if filename != "analyzer-result.json":
        raise ValidationError(
            f"The analyzer result must be named 'analyzer-result.json'. "
            f"Provided filename: {filename}"
        )


def _validate_download_reports_command(args: Namespace) -> None:
    """Validate download-reports command."""
    report_scope = getattr(args, "report_scope", None) or "scan"
    scan_required = report_scope == "scan"
    _validate_project_scan_target(args, scan_required=scan_required)


def _validate_show_results_command(args: Namespace) -> None:
    """Validate show-results command."""
    show_flags = [
        getattr(args, "show_licenses", False),
        getattr(args, "show_components", False),
        getattr(args, "show_matches", False),
        getattr(args, "show_dependencies", False),
        getattr(args, "show_scan_metrics", False),
        getattr(args, "show_policy_warnings", False),
        getattr(args, "show_project_policy_warnings", False),
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
