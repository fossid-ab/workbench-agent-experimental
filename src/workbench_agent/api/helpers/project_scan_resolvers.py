import argparse
import logging
import time
from typing import Any, Dict, Optional, Tuple

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.api.helpers.generate_download_report import ReportHelper
from workbench_agent.exceptions import (
    ApiError,
    ConfigurationError,
    ProjectExistsError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
)

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-agent")


class ResolveWorkbenchProjectScan(BaseAPI, ReportHelper):
    """
    Workbench API Scan Target Resolution Operations - handles resolving project names to codes
    and scan names to codes/IDs, with optional creation functionality.

    This class requires the implementing class to provide project and scan API methods
    (typically through WorkbenchAPI's multiple inheritance).
    """

    def resolve_project(self, project_name: str, create_if_missing: bool = False) -> str:
        """Find a project by name, optionally creating it if not found."""
        # Look for existing project
        projects = self.list_projects()
        project = next((p for p in projects if p.get("project_name") == project_name), None)

        if project:
            return project["project_code"]

        # Create if requested
        if create_if_missing:
            print(f"Creating project '{project_name}'...")
            try:
                return self.create_project(project_name)
            except ProjectExistsError:
                # Handle race condition
                projects = self.list_projects()
                project = next((p for p in projects if p.get("project_name") == project_name), None)
                if project:
                    return project["project_code"]
                raise ApiError(
                    f"Failed to resolve project '{project_name}' after creation conflict"
                )

        raise ProjectNotFoundError(f"Project '{project_name}' not found")

    def resolve_scan(
        self,
        scan_name: str,
        project_name: Optional[str],
        create_if_missing: bool,
        params: argparse.Namespace,
        import_from_report: bool = False,
    ) -> Tuple[str, int]:
        """Find a scan by name, optionally creating it if not found."""
        if project_name:
            # Look in specific project
            project_code = self.resolve_project(project_name, create_if_missing)
            scan_list = self.get_project_scans(project_code)

            # Look for exact match only
            scan = next((s for s in scan_list if s.get("name") == scan_name), None)
            if scan:
                return scan["code"], int(scan["id"])

            # Create if requested
            if create_if_missing:
                print(f"Creating scan '{scan_name}' in project '{project_name}'...")
                self._create_scan_for_project(
                    project_code=project_code,
                    scan_name=scan_name,
                    params=params,
                    import_from_report=import_from_report,
                )
                time.sleep(2)  # Brief wait for creation to process

                # Get the newly created scan
                scan_list = self.get_project_scans(project_code)
                scan = next((s for s in scan_list if s.get("name") == scan_name), None)
                if scan:
                    return scan["code"], int(scan["id"])
                raise ApiError(f"Failed to retrieve newly created scan '{scan_name}'")

            raise ScanNotFoundError(f"Scan '{scan_name}' not found in project '{project_name}'")

        else:
            # Global search
            if create_if_missing:
                raise ConfigurationError("Cannot create a scan without specifying a project")

            scan_list = self.list_scans()
            found = [s for s in scan_list if s.get("name") == scan_name]

            if len(found) == 1:
                scan = found[0]
                return scan["code"], int(scan["id"])
            elif len(found) > 1:
                projects = sorted(set(s.get("project_code", "Unknown") for s in found))
                raise ValidationError(
                    f"Multiple scans found with name '{scan_name}' in projects: {', '.join(projects)}"
                )

            raise ScanNotFoundError(f"Scan '{scan_name}' not found in any project")

    def _get_git_params(self, params: argparse.Namespace) -> Dict[str, Any]:
        """Get git parameters if this is a git scan."""
        if getattr(params, "command", None) == "scan-git":
            return {
                "git_url": getattr(params, "git_url", None),
                "git_branch": getattr(params, "git_branch", None),
                "git_tag": getattr(params, "git_tag", None),
                "git_depth": getattr(params, "git_depth", None),
            }
        return {}

    def _create_scan_for_project(
        self,
        project_code: str,
        scan_name: str,
        params: argparse.Namespace,
        import_from_report: bool = False,
    ) -> bool:
        """
        Create a new scan for a project with business logic and payload assembly.

        Args:
            project_code: Project code where the scan should be created
            scan_name: Name for the new scan
            params: Command line parameters containing Git and other options
            import_from_report: Whether to import the scan from an existing report

        Returns:
            True if the scan was successfully created

        Raises:
            ScanExistsError: If a scan with this name already exists
            ApiError: If there are API issues
        """
        # Extract git parameters from command line args
        git_params = self._get_git_params(params)

        # Build the data payload with all business logic
        data_payload = self._build_create_scan_data(
            scan_name=scan_name,
            project_code=project_code,
            import_from_report=import_from_report,
            description=getattr(params, "description", None),
            **git_params,
        )

        # Execute the API call using the centralized logic
        return self.create_scan(data_payload)

    def _build_create_scan_data(
        self,
        scan_name: str,
        project_code: str,
        git_url: Optional[str] = None,
        git_branch: Optional[str] = None,
        git_tag: Optional[str] = None,
        git_commit: Optional[str] = None,
        git_depth: Optional[int] = None,
        import_from_report: bool = False,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build the data portion for scan creation with all business logic.

        This method encapsulates all the complex Git parameter handling
        and data construction logic, returning only the 'data' part of the payload.
        """
        logger.debug(f"Building create scan payload for '{scan_name}' in project '{project_code}'")

        payload_data = {
            "scan_name": scan_name,
            "project_code": project_code,
        }

        # Add optional metadata fields
        if description:
            payload_data["description"] = description
            logger.debug(f"  Setting scan description: {description}")

        # Add import_from_report parameter if specified
        if import_from_report:
            payload_data["import_from_report"] = "1"
            logger.debug("  Setting scan for report import mode")

        # --- Complex Git Parameter Handling ---
        git_ref_value = None
        git_ref_type = None

        if git_tag:
            git_ref_value = git_tag
            git_ref_type = "tag"
            logger.debug(f"  Including Git Tag: {git_tag}")
        elif git_branch:
            git_ref_value = git_branch
            git_ref_type = "branch"
            logger.debug(f"  Including Git Branch: {git_branch}")
        elif git_commit:
            git_ref_value = git_commit
            git_ref_type = "commit"
            logger.debug(f"  Including Git Commit: {git_commit}")

        if git_url:
            # Include Git parameters only if a Git URL is provided
            payload_data["git_repo_url"] = git_url
            logger.debug(f"  Including Git URL: {git_url}")
            if git_ref_value:
                # API uses 'git_branch' field for BOTH branch and tag values
                payload_data["git_branch"] = git_ref_value
                if git_ref_type:
                    # Explicit ref_type helps Workbench know if it's a branch or tag
                    payload_data["git_ref_type"] = git_ref_type
                    logger.debug(f"  Setting Git Ref Type to: {git_ref_type}")
                if git_depth is not None:
                    # Only include depth if a positive number is provided
                    payload_data["git_depth"] = str(git_depth)
                    logger.debug(f"  Setting Git Clone Depth to: {git_depth}")
            elif git_depth is not None:
                # If depth is provided but no ref type, we need to set a default
                if not git_ref_type:
                    logger.warning(
                        "Git depth specified, but no branch or tag provided. "
                        "Setting ref type to 'branch' as a default."
                    )
                    payload_data["git_ref_type"] = "branch"
                payload_data["git_depth"] = str(git_depth)
                logger.debug(f"  Setting Git Clone Depth to: {git_depth}")

        return payload_data
