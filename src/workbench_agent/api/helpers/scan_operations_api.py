import logging
from typing import Any, Dict, Optional

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.api.helpers.process_waiters import ProcessWaiters
from workbench_agent.api.helpers.process_status_checkers import ProcessStatusCheckers
from workbench_agent.exceptions import (
    ApiError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")


class ScanOperationsAPI(BaseAPI, ProcessWaiters, ProcessStatusCheckers):
    """
    Extended API base class for operations that require scan status checking
    and process waiting capabilities.

    This class combines BaseAPI's core functionality with scan-specific
    operations like status checking, process waiting, and scan lifecycle
    management.

    Use this as the base class for APIs that need to:
    - Check scan status
    - Wait for long-running processes
    - Ensure scans are idle before operations
    - Monitor scan progress
    """

    def translate_reuse_arguments(self, args) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Translate new CLI identification reuse arguments to internal format.

        This function converts the new mutually exclusive CLI arguments into the
        internal format expected by the API payload builder.

        Args:
            args: Parsed command-line arguments containing new reuse options

        Returns:
            tuple: (id_reuse, id_reuse_type, id_reuse_source)
                - id_reuse: Whether to enable identification reuse
                - id_reuse_type: Type of reuse ("any", "only_me", "project", "scan")
                - id_reuse_source: Source name for project/scan reuse types
        """
        # Check which reuse argument was provided
        if getattr(args, "reuse_any_identification", False):
            return True, "any", None
        elif getattr(args, "reuse_my_identifications", False):
            return True, "only_me", None
        elif getattr(args, "reuse_scan_ids", None) is not None:
            return True, "scan", args.reuse_scan_ids
        elif getattr(args, "reuse_project_ids", None) is not None:
            return True, "project", args.reuse_project_ids
        else:
            # No reuse argument provided - return defaults
            return False, "any", None

    def build_run_scan_data(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        autoid_file_licenses: bool,
        autoid_file_copyrights: bool,
        autoid_pending_ids: bool,
        delta_scan: bool,
        id_reuse: bool,
        id_reuse_type: Optional[str] = None,
        id_reuse_source: Optional[str] = None,
        run_dependency_analysis: Optional[bool] = None,
        replace_existing_identifications: bool = False,
        scan_failed_only: bool = False,
        full_file_only: bool = False,
        advanced_match_scoring: bool = True,
        match_filtering_threshold: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Build the data payload for the scans -> run API call.

        This method handles all the complex parameter transformation,
        validation, and conditional field addition for scan execution.

        Args:
            scan_code: The code of the scan to run
            limit: Maximum number of results to consider
            sensitivity: Scan sensitivity level
            autoid_file_licenses: Whether to auto-identify file licenses
            autoid_file_copyrights: Whether to auto-identify file copyrights
            autoid_pending_ids: Whether to auto-identify pending IDs
            delta_scan: Whether to run a delta scan
            id_reuse: Whether to reuse identifications from other scans
            id_reuse_type: Type of identification reuse
            id_reuse_source: Source to reuse identifications from
            run_dependency_analysis: Whether to run dependency analysis
            replace_existing_identifications: Whether to replace existing IDs
            scan_failed_only: Whether to only scan files that failed
            full_file_only: Whether to return only full file matches
            advanced_match_scoring: Whether to use advanced match scoring
            match_filtering_threshold: Minimum snippet length for filtering

        Returns:
            Dict[str, Any]: Data payload for scan execution (data field only)
        """
        data = {
            "scan_code": scan_code,
            "limit": limit,
            "sensitivity": sensitivity,
            "auto_identification_detect_declaration": int(autoid_file_licenses),
            "auto_identification_detect_copyright": int(autoid_file_copyrights),
            "auto_identification_resolve_pending_ids": int(autoid_pending_ids),
            "delta_only": int(delta_scan),
            "replace_existing_identifications": int(replace_existing_identifications),
            "scan_failed_only": int(scan_failed_only),
            "full_file_only": int(full_file_only),
            "advanced_match_scoring": int(advanced_match_scoring),
        }

        # Add match filtering threshold if specified
        if match_filtering_threshold is not None:
            data["match_filtering_threshold"] = match_filtering_threshold

        if id_reuse:
            # Determine the value to send to the API based on the user input
            api_reuse_type_value = id_reuse_type

            if id_reuse_type == "project":
                api_reuse_type_value = "specific_project"
            elif id_reuse_type == "scan":
                api_reuse_type_value = "specific_scan"
            elif id_reuse_type == "only_me":
                api_reuse_type_value = "only_me"
            else:
                api_reuse_type_value = "any"  # Default to "any"

            # Safety check: ensure specific_code is provided for
            # project/scan reuse
            if (
                api_reuse_type_value in ["specific_project", "specific_scan"]
                and not id_reuse_source
            ):
                logger.warning(
                    f"ID reuse disabled because no source was provided "
                    f"for {id_reuse_type} reuse type."
                )
                # Skip adding reuse parameters
            else:
                # Add ID reuse parameters to the payload
                data["reuse_identification"] = "1"
                data["identification_reuse_type"] = api_reuse_type_value

                # Include specific_code for project/scan reuse types
                if api_reuse_type_value in ["specific_project", "specific_scan"]:
                    data["specific_code"] = id_reuse_source

        # Add dependency analysis parameter if requested
        if run_dependency_analysis:
            data["run_dependency_analysis"] = "1"

        return data

    def execute_run_scan(self, payload: Dict[str, Any]) -> None:
        """
        Execute a run_scan API call with the provided payload.

        This method handles the core API interaction for running scans,
        providing centralized execution logic that can be called with
        pre-constructed payloads.

        Args:
            payload: The complete API payload for the run_scan request

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                scan_code = payload.get("data", {}).get("scan_code", "unknown")
                print(f"KB Scan initiated for scan '{scan_code}'.")
                return  # Success
            else:
                error_msg = response.get("error", "Unknown error")
                scan_code = payload.get("data", {}).get("scan_code", "unknown")
                if "Scan not found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")
                raise ApiError(f"Failed to run scan '{scan_code}': {error_msg}", details=response)
        except (ScanNotFoundError, ApiError):
            raise  # Re-raise specific errors
        except Exception as e:
            # Catch other errors like network issues from _send_request
            scan_code = payload.get("data", {}).get("scan_code", "unknown")
            logger.error(f"Unexpected error trying to run scan '{scan_code}': {e}", exc_info=True)
            raise ApiError(f"Failed to run scan '{scan_code}': {e}") from e

    def build_extract_archives_data(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ) -> Dict[str, Any]:
        """
        Build data payload for archive extraction operation.

        Args:
            scan_code: Code of the scan to extract archives for
            recursively_extract_archives: Whether to recursively extract archives
            jar_file_extraction: Whether to extract JAR files

        Returns:
            Dict[str, Any]: Data payload for archive extraction (data field only)
        """
        return {
            "scan_code": scan_code,
            "recursively_extract_archives": str(recursively_extract_archives).lower(),
            "jar_file_extraction": str(jar_file_extraction).lower(),
        }

    def build_dependency_analysis_data(
        self,
        scan_code: str,
        import_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Build data payload for dependency analysis operation.

        Args:
            scan_code: Code of the scan to start dependency analysis for
            import_only: Whether to only import results without running analysis

        Returns:
            Dict[str, Any]: Data payload for dependency analysis (data field only)
        """
        return {
            "scan_code": scan_code,
            "import_only": "1" if import_only else "0",
        }
