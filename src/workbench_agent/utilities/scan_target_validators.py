"""
Scan target validation utilities for the Workbench Agent.

This module contains functions for validating scan targets and their configurations,
including compatibility checks and ID reuse validation.
"""

import argparse
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from workbench_agent.exceptions import (
    ApiError,
    CompatibilityError,
    ConfigurationError,
    NetworkError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchAgentError,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-agent")


def ensure_scan_compatibility(
    workbench: "WorkbenchAPI", params: argparse.Namespace, scan_code: str
):
    """
    Checks if the existing scan configuration is compatible with the current command.
    Fetches scan information directly from the API.

    Args:
        workbench: WorkbenchAPI instance to fetch scan information
        params: Command line parameters
        scan_code: Code of the scan to check

    Raises:
        CompatibilityError: If the scan is incompatible with the requested operation
    """
    logger.debug(
        f"\nVerifying if the '{scan_code}' scan is compatible with the current operation..."
    )

    try:
        # Fetch scan information from the API
        existing_scan_info = workbench.get_scan_information(scan_code)
    except ScanNotFoundError:
        logger.warning(f"Scan '{scan_code}' not found during compatibility check.")
        return
    except (ApiError, NetworkError) as e:
        logger.warning(f"Error fetching scan information during compatibility check: {e}")
        print(f"Warning: Could not verify scan compatibility due to API error: {e}")
        return

    # --- Read existing scan info ---
    existing_git_repo = existing_scan_info.get("git_repo_url", existing_scan_info.get("git_url"))
    # The API puts both branch and tag *values* in the 'git_branch' field
    existing_git_ref_value = existing_scan_info.get("git_branch")
    existing_git_ref_type = existing_scan_info.get(
        "git_ref_type"
    )  # Directly get the type ('tag' or 'branch')
    existing_is_from_report = existing_scan_info.get(
        "is_from_report", "0"
    )  # Default to "0" if not present

    # Convert string to boolean for easier comparison
    existing_is_report_scan = existing_is_from_report in ["1", 1, True, "true"]

    # --- Read current command info ---
    current_command = params.command
    current_uses_git = current_command == "scan-git"
    current_git_url = getattr(params, "git_url", None)
    current_git_branch = getattr(params, "git_branch", None)
    current_git_tag = getattr(params, "git_tag", None)
    # Determine requested type and value based on flags
    current_git_ref_type = "tag" if current_git_tag else ("branch" if current_git_branch else None)
    current_git_ref_value = current_git_tag if current_git_tag else current_git_branch

    error_message = None

    # --- Compatibility Checks ---
    if current_command == "scan":
        if existing_is_report_scan:
            error_message = f"Scan '{scan_code}' was created for SBOM import and cannot be reused for code upload via --path."
        elif existing_git_repo:
            error_message = f"Scan '{scan_code}' was created for Git scanning (Repo: {existing_git_repo}) and cannot be reused for code upload via --path."
    elif current_command == "scan-git":
        if existing_is_report_scan:
            error_message = f"Scan '{scan_code}' was created for SBOM import and cannot be reused for Git scanning."
        elif not existing_git_repo:
            error_message = f"Scan '{scan_code}' was created for code upload (using --path) and cannot be reused for Git scanning."
        elif existing_git_repo != current_git_url:
            error_message = (
                f"Scan '{scan_code}' already exists but is configured for a different Git repository "
                f"(Existing: '{existing_git_repo}', Requested: '{current_git_url}'). "
                f"Please use a different --scan-name to create a new scan."
            )
        # --- Comparison using corrected existing_git_ref_type ---
        elif (
            current_git_ref_type
            and existing_git_ref_type
            and existing_git_ref_type.lower() != current_git_ref_type.lower()
        ):  # Compare ignoring case
            error_message = (
                f"Scan '{scan_code}' exists with ref type '{existing_git_ref_type}', but current command specified ref type '{current_git_ref_type}'. "
                f"Please use a different --scan-name or use a matching ref type."
            )
        # --- Comparison using corrected existing_git_ref_value ---
        elif existing_git_ref_value != current_git_ref_value:
            error_message = (
                f"Scan '{scan_code}' already exists for {existing_git_ref_type or 'ref'} '{existing_git_ref_value}', "
                f"but current command specified {current_git_ref_type or 'ref'} '{current_git_ref_value}'. "
                f"Please use a different --scan-name or use the matching ref."
            )
    elif current_command == "import-da":
        if existing_is_report_scan:
            error_message = f"Scan '{scan_code}' was created for SBOM import and cannot be reused for dependency analysis import."
    elif current_command == "import-sbom":
        if not existing_is_report_scan:
            error_message = f"Scan '{scan_code}' was not created for SBOM import and cannot be reused for SBOM import. Only scans created with 'import-sbom' can be reused for SBOM operations."

    # --- Error Handling ---
    if error_message:
        print(f"\nError: Incompatible scan usage detected.")
        logger.error(f"Compatibility check failed for scan '{scan_code}': {error_message}")
        raise CompatibilityError(
            f"Incompatible usage for existing scan '{scan_code}': {error_message}"
        )
    else:
        print("Compatibility check passed! Proceeding...")
        # Log reuse notes
        if current_uses_git and existing_git_repo:
            ref_display = f"{existing_git_ref_type or 'ref'} '{existing_git_ref_value}'"  # Use corrected values
            logger.debug(
                f"Reusing existing scan '{scan_code}' configured for Git repository '{existing_git_repo}' ({ref_display})."
            )
        elif current_command == "scan" and not existing_git_repo:
            logger.debug(f"Reusing existing scan '{scan_code}' configured for code upload.")
        elif current_command == "import-da":
            logger.debug(f"Reusing existing scan '{scan_code}' for DA import.")
        elif current_command == "import-sbom":
            logger.debug(
                f"Reusing existing scan '{scan_code}' for SBOM import (report scan: {existing_is_report_scan})."
            )


def validate_reuse_source(
    workbench: "WorkbenchAPI", params: argparse.Namespace
) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates ID reuse source (project or scan) before uploading code or
    starting a scan to prevent unnecessary work if the source doesn't exist.

    Args:
        workbench: The Workbench API client
        params: Command line parameters with id_reuse settings

    Returns:
        Tuple[Optional[str], Optional[str]]: (api_reuse_type, resolved_specific_code_for_reuse)

    Raises:
        ValidationError: If the reuse source specified does not exist
        ConfigurationError: If required parameters are missing
    """
    # Return immediately if ID reuse is not enabled
    if not getattr(params, "id_reuse", False):
        return None, None

    api_reuse_type = None
    resolved_specific_code_for_reuse = None

    user_provided_name_for_reuse = params.id_reuse_source
    user_reuse_type = params.id_reuse_type

    if user_reuse_type == "project":
        if not user_provided_name_for_reuse:
            raise ConfigurationError(
                "Missing project name in --id-reuse-source for ID reuse type 'project'."
            )

        logger.debug(f"Validating project for ID reuse: '{user_provided_name_for_reuse}'...")
        logger.debug(
            f"Resolving project code for ID reuse source project: '{user_provided_name_for_reuse}'..."
        )
        try:
            resolved_specific_code_for_reuse = workbench.resolve_project(
                user_provided_name_for_reuse, create_if_missing=False
            )
            logger.debug(f"Found project code for reuse: '{resolved_specific_code_for_reuse}'")
            api_reuse_type = "specific_project"
            print(f"Successfully validated ID reuse project '{user_provided_name_for_reuse}'")
        except ProjectNotFoundError:
            logger.error(f"Project not found for ID reuse: '{user_provided_name_for_reuse}'")
            raise ValidationError(
                f"The project specified as an identification reuse source '{user_provided_name_for_reuse}' does not exist in Workbench. "
                f"Please verify the project name is correct and try again."
            )
        except (ApiError, NetworkError) as e:
            raise ApiError(f"Error looking up project code for reuse: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error looking up project code for reuse: {e}", exc_info=True)
            raise WorkbenchAgentError(
                f"Unexpected error looking up project code for reuse: {e}",
                details={"error": str(e)},
            ) from e

    elif user_reuse_type == "scan":
        if not user_provided_name_for_reuse:
            raise ConfigurationError(
                "Missing scan name in --id-reuse-source for ID reuse type 'scan'."
            )

        logger.debug(f"Validating scan for ID reuse: '{user_provided_name_for_reuse}'...")
        try:
            # Step 1: Try to find the reuse source scan within the CURRENT project first
            logger.debug(
                f"Searching for the reuse source scan '{user_provided_name_for_reuse}' within the current project '{params.project_name}'..."
            )
            resolved_specific_code_for_reuse, _ = workbench.resolve_scan(
                scan_name=user_provided_name_for_reuse,
                project_name=params.project_name,  # Use current project name
                create_if_missing=False,
                params=params,  # Pass params for logging context if needed
            )
            logger.debug(
                f"Found reuse source scan '{user_provided_name_for_reuse}' with code '{resolved_specific_code_for_reuse}' within the current project."
            )
            api_reuse_type = "specific_scan"  # API expects this value
            logger.debug(
                f"Successfully validated ID reuse scan '{user_provided_name_for_reuse}' in project '{params.project_name}'"
            )

        except (ScanNotFoundError, ValidationError) as e:  # Catch if not found in current project
            # Step 2: If not found in the current project, try a global search.
            logger.warning(
                f"The reuse source scan '{user_provided_name_for_reuse}' cannot be found in the '{params.project_name}' project. Attempting global search..."
            )
            try:
                resolved_specific_code_for_reuse, _ = workbench.resolve_scan(
                    scan_name=user_provided_name_for_reuse,
                    project_name=None,  # Perform global search; no project name provided.
                    create_if_missing=False,
                    params=params,
                )
                logger.debug(
                    f"Found reuse source scan '{user_provided_name_for_reuse}' with code '{resolved_specific_code_for_reuse}' globally."
                )
                api_reuse_type = "specific_scan"  # API expects this value
                print(
                    f"Successfully validated ID reuse scan '{user_provided_name_for_reuse}' globally"
                )
            except (ScanNotFoundError, ValidationError, ApiError) as global_e:
                # If global search also fails (not found or ambiguous globally), raise an error.
                err_msg = (
                    f"The scan specified as an identification reuse source '{user_provided_name_for_reuse}' does not exist in Workbench. "
                    f"Please verify the scan name is correct and try again."
                )
                logger.error(
                    f"Error looking up scan code '{user_provided_name_for_reuse}' for reuse: "
                    f"Not found in project '{params.project_name}' and global search failed: {global_e}"
                )
                # Raise ValidationError as it's an input/setup issue
                raise ValidationError(err_msg) from global_e
        except (ApiError, NetworkError) as e:
            # Catch other potential errors during the initial local lookup
            raise ApiError(f"Error looking up scan code for reuse within project: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error looking up scan code for reuse: {e}", exc_info=True)
            raise WorkbenchAgentError(
                f"Unexpected error looking up scan code for reuse: {e}", details={"error": str(e)}
            ) from e

    return api_reuse_type, resolved_specific_code_for_reuse
