import logging
import functools
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Union

from workbench_agent.exceptions import (
    ApiError,
    NetworkError,
    UnsupportedStatusCheck,
)

logger = logging.getLogger("workbench-agent")


@dataclass
class StatusResult:
    """Standardized result from status checking operations."""

    status: str  # Normalized status (FINISHED, RUNNING, FAILED, etc.)
    raw_data: Dict[str, Any]  # Original response data
    is_finished: bool = False
    is_failed: bool = False
    error_message: Optional[str] = None
    progress_info: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Auto-calculate convenience flags based on status."""
        normalized_status = self.status.upper()
        self.is_finished = normalized_status == "FINISHED"
        self.is_failed = normalized_status in {"FAILED", "CANCELLED", "ERROR"}

        # Extract error message if failed
        if self.is_failed and not self.error_message:
            self.error_message = self.raw_data.get(
                "error", self.raw_data.get("message", self.raw_data.get("info", ""))
            )

        # Extract progress information
        if not self.progress_info:
            progress_data = {}
            for key in ["state", "current_step", "percentage_done", "total_files", "current_file"]:
                if key in self.raw_data:
                    progress_data[key] = self.raw_data[key]
            self.progress_info = progress_data if progress_data else None


def handle_unsupported_status_check(func: Callable) -> Callable:
    """
    Decorator that intercepts API errors and raises UnsupportedStatusCheck
    for unsupported operations.

    This decorator analyzes API error responses and converts specific
    "unsupported operation type" errors into UnsupportedStatusCheck
    exceptions, allowing calling code to handle them gracefully.

    Args:
        func: The status check function to wrap

    Returns:
        Wrapped function that raises UnsupportedStatusCheck for
        unsupported operations
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except (ApiError, NetworkError) as e:
            # Check for unsupported operation type error patterns
            error_str = str(e).lower()
            if (
                ("field_not_valid_option" in error_str and "type" in error_str)
                or ("not support" in error_str)
                or ("invalid type" in error_str)
            ):
                # Extract operation type from kwargs or args for better
                # error message
                operation_type = kwargs.get("scan_type", kwargs.get("process_type", "UNKNOWN"))
                if not operation_type and len(args) >= 2:
                    operation_type = args[1] if hasattr(args[1], "upper") else "UNKNOWN"

                raise UnsupportedStatusCheck(
                    f"Operation type '{operation_type}' not supported on "
                    f"this Workbench version",
                    details={
                        "operation_type": operation_type,
                        "original_error": str(e),
                        "function": func.__name__,
                    },
                ) from e
            # Re-raise other API errors as-is
            raise

    return wrapper


# Constants for operation categorization
GIT_OPERATIONS = {"GIT_CLONE"}
STANDARD_CHECK_STATUS_OPERATIONS = {
    "SCAN",
    "DEPENDENCY_ANALYSIS",
    "EXTRACT_ARCHIVES",
    "REPORT_IMPORT",
    "NOTICE_EXTRACT_FILE",
    "NOTICE_EXTRACT_COMPONENT",
    "NOTICE_EXTRACT_AGGREGATE",
    "REPORT_GENERATION",
    "DELETE_SCAN",
}

PROJECT_OPERATIONS = {
    "PROJECT_REPORT_GENERATION",
}


class ProcessStatusCheckers:
    """
    Core status checking logic for scan and Git operations.

    This class provides pure status checking functions that return standardized
    StatusResult objects. No waiting or retry logic - just status extraction.
    """

    # Note: This class expects to be mixed into classes that provide:
    # - check_status(scan_code, operation_type, process_id=None) -> dict
    # - check_status_download_content_from_git(scan_code) -> dict
    # - check_project_report_status(process_id, project_code) -> dict

    def _git_status_accessor(self, data: Union[Dict[str, Any], str]) -> str:
        """
        Status accessor for git clone operations.

        Git clone operations have a simpler response format where the
        status is either a direct string or nested under a 'data' key in
        the response dictionary.

        This method handles Git clone status formats and normalizes them:
        1. Accepts both string status (direct) and dict format (legacy)
        2. Treats "NOT STARTED" as idle/finished (process hasn't started)
        3. Returns "ACCESS_ERROR" for unexpected data types
        4. Returns uppercase normalized status strings

        Args:
            data: Response data - can be a dictionary (legacy) or direct
                  status string (new)

        Returns:
            str: Normalized uppercase status string ("FINISHED", "RUNNING",
                 "QUEUED", "FAILED", etc.)
        """
        try:
            if isinstance(data, str):
                raw_status = data.upper()
            elif isinstance(data, dict):
                raw_status = str(data.get("data", "UNKNOWN")).upper()
            else:
                logger.warning(f"Unexpected data type for git status: {type(data)}")
                return "ACCESS_ERROR"

            # CRITICAL: Treat "NOT STARTED" as idle/finished state
            # A "NOT STARTED" process hasn't started yet, so it's
            # effectively idle. This prevents infinite waiting in
            # ensure_processes_are_idle
            if raw_status == "NOT STARTED":
                logger.debug(
                    "Git operation status is NOT STARTED (not started) - " "treating as idle"
                )
                return "FINISHED"

            return raw_status

        except Exception as e:
            logger.warning(f"Error processing git status data: {e}")
            return "ACCESS_ERROR"

    def _standard_scan_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Status accessor for standard scan operations using
        scans->check_status API.

        Standard scan operations have complex response formats with
        different status indicators depending on the operation type and
        phase. This method handles multiple status sources and provides
        consistent normalization.

        Status Priority Order:
        1. progress_state (for REPORT_GENERATION operations)
        2. status field (standard operations)
        3. Fallback to "UNKNOWN"

        Special Handling:
        - "NEW" status/progress_state treated as idle/finished
          (process hasn't started)
        - Complex state validation with is_finished flags where available
        - Error states normalized to uppercase

        Args:
            data: Response data dictionary from a scans->check_status API call

        Returns:
            str: Normalized uppercase status string ("FINISHED",
                 "RUNNING", "QUEUED", "FAILED", etc.)
        """
        try:
            # Check progress_state first (used by REPORT_GENERATION)
            progress_state = data.get("progress_state")
            if progress_state:
                progress_state_upper = str(progress_state).upper()

                # CRITICAL: Treat "NEW" as idle/finished state
                # A "NEW" process hasn't started yet, so it's effectively idle
                # This prevents infinite waiting in ensure_processes_are_idle
                if progress_state_upper == "NEW":
                    logger.debug(
                        "Scan progress_state is NEW (not started yet) - "
                        "treating as idle/finished"
                    )
                    return "FINISHED"

                return progress_state_upper

            # Check is_finished flag (boolean completion indicator)
            is_finished = data.get("is_finished")
            if is_finished is not None:
                # Handle both boolean and string representations
                if (isinstance(is_finished, bool) and is_finished) or (
                    isinstance(is_finished, str) and is_finished.lower() in ("1", "true")
                ):
                    return "FINISHED"
                # If is_finished exists but is False/0, process is still running
                # Continue to check other status indicators

            # Fall back to status field (standard operations)
            status = data.get("status")
            if status:
                status_upper = str(status).upper()

                # CRITICAL: Treat "NEW" as idle/finished state
                if status_upper == "NEW":
                    logger.debug(
                        "Scan status is NEW (process not started yet) - "
                        "treating as idle/finished"
                    )
                    return "FINISHED"

                return status_upper

            # No status information found
            logger.warning(f"No status information found in scan data: {data}")
            return "UNKNOWN"

        except Exception as e:
            logger.warning(f"Error processing scan status data: {e}")
            return "ACCESS_ERROR"  # Use the ACCESS_ERROR state

    def _project_report_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Status accessor for projects->check_status API operations
        (project reports).

        Project report operations use a simpler response format with just
        'progress_state'. Unlike scan operations, they don't have
        'is_finished' flags or complex status structures.

        This method handles project report status formats and normalizes them:
        1. Checks 'progress_state' field (primary status for project reports)
        2. Treats "NEW" progress_state as idle/finished (process hasn't
           started yet)
        3. Returns "UNKNOWN" if progress_state is not available
        4. Handles errors gracefully by returning "ACCESS_ERROR"

        Args:
            data: Response data dictionary from a projects->check_status
                  API call

        Returns:
            str: Normalized uppercase status string ("FINISHED",
                 "RUNNING", "QUEUED", "FAILED", etc.)
        """
        try:
            # Project reports primarily use progress_state field
            progress_state = data.get("progress_state")
            if progress_state:
                progress_state_upper = str(progress_state).upper()

                # CRITICAL: Treat "NEW" as idle/finished state
                # A "NEW" process hasn't started yet, so it's effectively idle
                # This prevents infinite waiting in ensure_processes_are_idle
                if progress_state_upper == "NEW":
                    logger.debug(
                        "Project report progress_state is NEW (not started) - " "treating as idle"
                    )
                    return "FINISHED"

                return progress_state_upper

            # No progress_state found
            logger.warning(f"No progress_state found in project report data: {data}")
            return "UNKNOWN"

        except Exception as e:
            logger.warning(f"Error processing project report status data: {e}")
            return "ACCESS_ERROR"  # Use the ACCESS_ERROR state

    def check_git_clone_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a Git clone operation for a scan.

        Args:
            scan_code: The scan code to check Git clone status for

        Returns:
            StatusResult: Standardized status result with Git clone information

        Raises:
            UnsupportedStatusCheck: If Git clone status checking is not
                                   supported
        """
        # Get raw status data from the API
        status_data = self.check_status_download_content_from_git(scan_code)

        # Extract and normalize status
        normalized_status = self._git_status_accessor(status_data)

        # Create standardized result
        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"data": status_data}),
        )

    # Specialized status checking methods for each process type

    def check_scan_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a scan operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with scan information
        """
        status_data = self.check_status(scan_code, "SCAN")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_dependency_analysis_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a dependency analysis operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with dependency
                         analysis information
        """
        status_data = self.check_status(scan_code, "DEPENDENCY_ANALYSIS")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_extract_archives_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of an archive extraction operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with archive
                         extraction information
        """
        status_data = self.check_status(scan_code, "EXTRACT_ARCHIVES")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_scan_report_status(self, scan_code: str, process_id: str) -> StatusResult:
        """
        Check the status of a scan report generation operation.

        Args:
            scan_code: The scan code to check
            process_id: The process ID of the report generation

        Returns:
            StatusResult: Standardized status result with scan report
                         information
        """
        status_data = self.check_status(scan_code, "REPORT_GENERATION", process_id=process_id)
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_project_report_generation_status(self, process_id: str) -> StatusResult:
        """
        Check the status of a project report generation operation.

        Args:
            process_id: The process ID of the project report generation

        Returns:
            StatusResult: Standardized status result with project report
                         information
        """
        # Call the underlying API method - this method name should exist
        # in the implementing class. The implementing class (like ProjectsAPI)
        # provides this method
        raw_status_data = self.check_project_report_status(
            process_id=int(process_id), project_code="N/A"
        )
        normalized_status = self._project_report_status_accessor(raw_status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(
                raw_status_data
                if isinstance(raw_status_data, dict)
                else {"status": raw_status_data}
            ),
        )

    def check_report_import_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a report import operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with report import
                         information
        """
        status_data = self.check_status(scan_code, "REPORT_IMPORT")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_notice_extract_file_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a notice extract file operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with notice extract
                         file information
        """
        status_data = self.check_status(scan_code, "NOTICE_EXTRACT_FILE")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_notice_extract_component_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a notice extract component operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with notice extract
                         component information
        """
        status_data = self.check_status(scan_code, "NOTICE_EXTRACT_COMPONENT")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_notice_extract_aggregate_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a notice extract aggregate operation.

        Args:
            scan_code: The scan code to check

        Returns:
            StatusResult: Standardized status result with notice extract
                         aggregate information
        """
        status_data = self.check_status(scan_code, "NOTICE_EXTRACT_AGGREGATE")
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )

    def check_delete_scan_status(self, scan_code: str, process_id: str) -> StatusResult:
        """
        Check the status of a delete scan operation.

        Args:
            scan_code: The scan code to check
            process_id: The process ID of the delete operation

        Returns:
            StatusResult: Standardized status result with delete scan
                         information
        """
        status_data = self.check_status(scan_code, "DELETE_SCAN", process_id=process_id)
        normalized_status = self._standard_scan_status_accessor(status_data)

        return StatusResult(
            status=normalized_status,
            raw_data=(status_data if isinstance(status_data, dict) else {"status": status_data}),
        )
