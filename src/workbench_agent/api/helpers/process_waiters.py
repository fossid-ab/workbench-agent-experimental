import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

from workbench_agent.exceptions import (
    ProcessError,
    ProcessTimeoutError,
    UnsupportedStatusCheck,
)
from .process_status_checkers import StatusResult

logger = logging.getLogger("workbench-agent")


@dataclass
class WaitResult:
    """Result from a waiting operation."""

    status_data: Dict[str, Any]
    duration: Optional[float] = None  # Server-side process execution time
    success: bool = True
    error_message: Optional[str] = None


class ProcessWaiters:
    """
    Generic waiting engine for scan operations.

    This class provides standardized retry and waiting logic that can be used
    with any status checking function. It focuses purely on the waiting mechanics
    and delegates actual status checking to provided functions.
    """

    def _extract_server_duration(self, raw_data: Dict[str, Any]) -> Optional[float]:
        """
        Extract actual process duration from server timestamps.

        This method only works for scan operations that have started/finished
        timestamps. Git operations use a different response format and don't
        provide duration information.

        Args:
            raw_data: Raw response data from the API

        Returns:
            float: Server-side duration in seconds, or None if timestamps unavailable
        """
        if not isinstance(raw_data, dict):
            return None

        # Check if this is a git operation response format
        # Git responses look like: {"data": "FINISHED"}
        if len(raw_data) == 1 and "data" in raw_data and isinstance(raw_data["data"], str):
            logger.debug("Git operation detected - no server duration available")
            return None

        started = raw_data.get("started")
        finished = raw_data.get("finished")

        if not started or not finished:
            return None

        try:
            # Parse timestamps in format "2025-08-08 00:43:31"
            started_dt = datetime.strptime(started, "%Y-%m-%d %H:%M:%S")
            finished_dt = datetime.strptime(finished, "%Y-%m-%d %H:%M:%S")

            server_duration = (finished_dt - started_dt).total_seconds()
            logger.debug(
                f"Extracted server duration: {server_duration:.2f}s (started: {started}, finished: {finished})"
            )
            return server_duration

        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse server timestamps: {e}")
            return None

    def wait_for_completion(
        self,
        check_function: Callable[[], StatusResult],
        max_tries: int,
        wait_interval: int,
        operation_name: str,
        progress_callback: Optional[Callable[[StatusResult, int, int], None]] = None,
    ) -> WaitResult:
        """
        Generic completion waiting engine.

        This is the universal waiting engine that handles retry logic, timeout detection,
        and progress reporting. It delegates actual status checking to the provided function
        and uses StatusResult objects for standardized processing.

        Args:
            check_function: Function that returns StatusResult when called
            max_tries: Maximum number of attempts before timeout
            wait_interval: Seconds to wait between attempts
            operation_name: Human-readable operation name for messages
            progress_callback: Optional callback for custom progress reporting

        Returns:
            WaitResult: Result containing final status data and duration

        Raises:
            ProcessTimeoutError: If max_tries is reached without completion
            ProcessError: If the operation fails
            UnsupportedStatusCheck: If the operation type is not supported
        """
        logger.debug(f"Starting to wait for {operation_name} completion...")

        start_time = time.time()
        last_status = "UNKNOWN"

        for attempt in range(1, max_tries + 1):
            try:
                # Get current status
                status_result = check_function()

                # Handle successful completion
                if status_result.is_finished:
                    server_duration = self._extract_server_duration(status_result.raw_data)

                    # Add server duration to status data if available
                    if isinstance(status_result.raw_data, dict) and server_duration is not None:
                        status_result.raw_data["_duration_seconds"] = server_duration

                    # Only show completion message if we actually waited
                    if attempt > 1:
                        if server_duration is not None:
                            print(
                                f"\n{operation_name} completed successfully ({server_duration:.2f}s)"
                            )
                        else:
                            print(f"\n{operation_name} completed successfully")

                    if server_duration is not None:
                        logger.debug(
                            f"{operation_name} completed successfully (Duration: {server_duration:.2f}s)"
                        )
                    else:
                        logger.debug(f"{operation_name} completed successfully")

                    return WaitResult(
                        status_data=status_result.raw_data,
                        duration=server_duration,
                        success=True,
                    )

                # Handle failures
                if status_result.is_failed:
                    error_msg = status_result.error_message or f"{operation_name} failed"
                    raise ProcessError(error_msg, details=status_result.raw_data)

                # Progress reporting
                if progress_callback:
                    progress_callback(status_result, attempt, max_tries)
                else:
                    # Default progress reporting
                    if status_result.status != last_status or attempt == 1 or attempt % 10 == 0:
                        print()
                        print(
                            f"{operation_name} status: {status_result.status}. Attempt {attempt}/{max_tries}",
                            end="",
                            flush=True,
                        )
                        last_status = status_result.status
                    else:
                        print(".", end="", flush=True)

                # Wait before next attempt (except on last attempt)
                if attempt < max_tries:
                    time.sleep(wait_interval)

            except UnsupportedStatusCheck:
                # Handle unsupported operations gracefully
                logger.warning(
                    f"{operation_name} status checking not supported on this Workbench version"
                )
                print(
                    f"\nNOTE: {operation_name} status checking not supported on this Workbench version - continuing..."
                )

                return WaitResult(
                    status_data={
                        "status": "FINISHED",
                        "message": "Skipped - unsupported operation",
                    },
                    duration=time.time() - start_time,
                    success=True,
                )

            except Exception as e:
                logger.error(f"Error during {operation_name} status check: {e}", exc_info=True)
                # For unexpected errors, continue retrying if we have attempts left
                if attempt < max_tries:
                    print(
                        f"\nAttempt {attempt}/{max_tries}: Error checking {operation_name} status: {e}"
                    )
                    print(f"Retrying in {wait_interval} seconds...")
                    time.sleep(wait_interval)
                    continue
                else:
                    # Last attempt - raise the error
                    raise ProcessError(
                        f"Error during {operation_name} operation", details={"error": str(e)}
                    )

        # If we reach here, we've exceeded max_tries
        duration = time.time() - start_time
        print(f"\nTimed out waiting for {operation_name} to complete")
        raise ProcessTimeoutError(
            f"{operation_name} timed out after {max_tries} attempts",
            details={
                "operation_name": operation_name,
                "max_tries": max_tries,
                "wait_interval": wait_interval,
                "duration": duration,
                "last_status": last_status,
            },
        )

    # Specialized waiters for each process type

    def wait_for_scan_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
        should_track_files: bool = False,
    ) -> WaitResult:
        """
        Wait for a scan (KB scan) operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts
            should_track_files: Whether to show file progress information

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_scan_status(scan_code)

        # Create custom progress callback for scan operations
        def scan_progress_callback(status_result: StatusResult, attempt: int, max_tries: int):
            self._handle_scan_progress(
                status_result, attempt, max_tries, "KB Scan", should_track_files
            )

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"KB Scan for scan '{scan_code}'",
            progress_callback=scan_progress_callback,
        )

    def wait_for_dependency_analysis_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a dependency analysis operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_dependency_analysis_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Dependency Analysis for scan '{scan_code}'",
        )

    def wait_for_extract_archives_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for an archive extraction operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_extract_archives_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Archive Extraction for scan '{scan_code}'",
        )

    def wait_for_scan_report_completion(
        self,
        scan_code: str,
        process_id: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a scan report generation operation to complete.

        Args:
            scan_code: Code of the scan
            process_id: Process ID of the report generation
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_scan_report_status(scan_code, process_id)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Scan Report Generation for scan '{scan_code}'",
        )

    def wait_for_project_report_completion(
        self,
        process_id: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a project report generation operation to complete.

        Args:
            process_id: Process ID of the project report generation
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_project_report_generation_status(process_id)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Project Report Generation (process {process_id})",
        )

    def wait_for_report_import_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a report import operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_report_import_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Report Import for scan '{scan_code}'",
        )

    def wait_for_notice_extract_file_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a notice extract file operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_notice_extract_file_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Notice Extract File for scan '{scan_code}'",
        )

    def wait_for_notice_extract_component_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a notice extract component operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_notice_extract_component_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Notice Extract Component for scan '{scan_code}'",
        )

    def wait_for_notice_extract_aggregate_completion(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a notice extract aggregate operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_notice_extract_aggregate_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Notice Extract Aggregate for scan '{scan_code}'",
        )

    def wait_for_delete_scan_completion(
        self,
        scan_code: str,
        process_id: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a delete scan operation to complete.

        Args:
            scan_code: Code of the scan
            process_id: Process ID of the delete operation
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_delete_scan_status(scan_code, process_id)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Delete Scan '{scan_code}' (process {process_id})",
        )

    def wait_for_git_clone(
        self,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
    ) -> WaitResult:
        """
        Wait for a Git clone operation to complete.

        This method creates a Git-specific check function and delegates to the
        universal waiting engine with simple progress reporting.

        Args:
            scan_code: Code of the scan to check Git clone for
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts

        Returns:
            WaitResult: Result containing final status data and duration
        """

        # Create check function that returns StatusResult
        def check_function() -> StatusResult:
            return self.check_git_clone_status(scan_code)

        return self.wait_for_completion(
            check_function=check_function,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Git clone for scan '{scan_code}'",
        )

    def _handle_scan_progress(
        self,
        status_result: StatusResult,
        attempt: int,
        max_tries: int,
        operation_name: str,
        should_track_files: bool = False,
    ):
        """
        Handle progress reporting for scan operations with rich file tracking.

        Args:
            status_result: Current status result
            attempt: Current attempt number
            max_tries: Maximum attempts
            operation_name: Name of the operation for display
            should_track_files: Whether to show file progress information
        """
        # Extract progress information
        progress_info = status_result.progress_info or {}
        current_state = progress_info.get("state", "")
        current_step = progress_info.get("current_step", "")

        # Extract percentage info (always available)
        percentage = progress_info.get("percentage_done", "")

        # File tracking for KB scans
        file_info = ""
        if should_track_files:
            total_files = progress_info.get("total_files", 0)
            current_file = progress_info.get("current_file", 0)

            if total_files and int(total_files) > 0:
                file_info = f" - File {current_file}/{total_files}"
                if percentage:
                    file_info += f" ({percentage})"

        # Determine if we should show detailed progress
        should_print_details = (
            attempt == 1  # First check
            or attempt % 10 == 0  # Periodic updates
            or status_result.status != getattr(self, "_progress_last_status", None)
            or current_state != getattr(self, "_progress_last_state", None)
            or current_step != getattr(self, "_progress_last_step", None)
        )

        if should_print_details:
            print()
            status_msg = f"{operation_name} status: {status_result.status}"
            if current_state:
                status_msg += f" ({current_state})"
            if file_info:
                status_msg += file_info
            elif percentage:
                status_msg += f" - Progress: {percentage}"
            if current_step:
                status_msg += f" - Step: {current_step}"

            print(f"{status_msg}. Attempt {attempt}/{max_tries}", end="", flush=True)

            # Store for next comparison
            self._progress_last_status = status_result.status
            self._progress_last_state = current_state
            self._progress_last_step = current_step
        else:
            print(".", end="", flush=True)

    # Unified waiter interface
    def check_and_wait_for_process(
        self,
        process_types: Union[str, List[str]],
        scan_code: Optional[str] = None,
        process_id: Optional[str] = None,
        max_tries: int = 10,
        wait_interval: int = 5,
        should_track_files: bool = False,
    ) -> Union[WaitResult, Dict[str, WaitResult]]:
        """
        Unified interface for waiting for one or multiple process types to complete.

        This method provides a single entry point for waiting for any process type(s)
        to complete, automatically delegating to the appropriate specialized waiters.

        Args:
            process_types: Single process type (str) or list of process types to wait for
            scan_code: Scan code (required for scan-related processes)
            process_id: Process ID (required for report generation processes)
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts
            should_track_files: Whether to show file progress (for scan operations)

        Returns:
            WaitResult: If single process type provided
            Dict[str, WaitResult]: If list of process types provided

        Raises:
            ValueError: If required parameters are missing for specific process types
        """
        # Handle single process type
        if isinstance(process_types, str):
            return self._wait_for_single_process_type(
                process_types, scan_code, process_id, max_tries, wait_interval, should_track_files
            )

        # Handle multiple process types
        results = {}
        for process_type in process_types:
            try:
                results[process_type] = self._wait_for_single_process_type(
                    process_type,
                    scan_code,
                    process_id,
                    max_tries,
                    wait_interval,
                    should_track_files,
                )
            except Exception as e:
                # Store error in results for comprehensive reporting
                results[process_type] = WaitResult(
                    status="ERROR",
                    duration=0.0,
                    raw_data={"error": str(e), "process_type": process_type},
                    error_message=str(e),
                )

        return results

    def _wait_for_single_process_type(
        self,
        process_type: str,
        scan_code: Optional[str] = None,
        process_id: Optional[str] = None,
        max_tries: int = 10,
        wait_interval: int = 5,
        should_track_files: bool = False,
    ) -> WaitResult:
        """
        Internal method for waiting for a single process type.

        Args:
            process_type: Type of process to wait for
            scan_code: Scan code (required for scan-related processes)
            process_id: Process ID (required for report generation processes)
            max_tries: Maximum number of attempts
            wait_interval: Seconds to wait between attempts
            should_track_files: Whether to show file progress (for scan operations)

        Returns:
            WaitResult: Result containing final status data and duration

        Raises:
            ValueError: If required parameters are missing for specific process types
        """
        if process_type == "SCAN":
            if not scan_code:
                raise ValueError("scan_code is required for SCAN process type")
            return self.wait_for_scan_completion(
                scan_code, max_tries, wait_interval, should_track_files
            )

        elif process_type == "DEPENDENCY_ANALYSIS":
            if not scan_code:
                raise ValueError("scan_code is required for DEPENDENCY_ANALYSIS " "process type")
            return self.wait_for_dependency_analysis_completion(scan_code, max_tries, wait_interval)

        elif process_type == "EXTRACT_ARCHIVES":
            if not scan_code:
                raise ValueError("scan_code is required for EXTRACT_ARCHIVES process type")
            return self.wait_for_extract_archives_completion(scan_code, max_tries, wait_interval)

        elif process_type == "GIT_CLONE":
            if not scan_code:
                raise ValueError("scan_code is required for GIT_CLONE process type")
            return self.wait_for_git_clone(scan_code, max_tries, wait_interval)

        elif process_type == "SCAN_REPORT_GENERATION":
            if not scan_code or not process_id:
                raise ValueError(
                    "scan_code and process_id are required for "
                    "SCAN_REPORT_GENERATION process type"
                )
            return self.wait_for_scan_report_completion(
                scan_code, process_id, max_tries, wait_interval
            )

        elif process_type == "PROJECT_REPORT_GENERATION":
            if not process_id:
                raise ValueError(
                    "process_id is required for PROJECT_REPORT_GENERATION " "process type"
                )
            return self.wait_for_project_report_completion(process_id, max_tries, wait_interval)

        elif process_type == "REPORT_IMPORT":
            if not scan_code:
                raise ValueError("scan_code is required for REPORT_IMPORT process type")
            return self.wait_for_report_import_completion(scan_code, max_tries, wait_interval)

        elif process_type == "NOTICE_EXTRACT_FILE":
            if not scan_code:
                raise ValueError("scan_code is required for NOTICE_EXTRACT_FILE " "process type")
            return self.wait_for_notice_extract_file_completion(scan_code, max_tries, wait_interval)

        elif process_type == "NOTICE_EXTRACT_COMPONENT":
            if not scan_code:
                raise ValueError(
                    "scan_code is required for NOTICE_EXTRACT_COMPONENT " "process type"
                )
            return self.wait_for_notice_extract_component_completion(
                scan_code, max_tries, wait_interval
            )

        elif process_type == "NOTICE_EXTRACT_AGGREGATE":
            if not scan_code:
                raise ValueError(
                    "scan_code is required for NOTICE_EXTRACT_AGGREGATE " "process type"
                )
            return self.wait_for_notice_extract_aggregate_completion(
                scan_code, max_tries, wait_interval
            )

        elif process_type == "DELETE_SCAN":
            if not scan_code or not process_id:
                raise ValueError(
                    "scan_code and process_id are required for DELETE_SCAN " "process type"
                )
            return self.wait_for_delete_scan_completion(
                scan_code, process_id, max_tries, wait_interval
            )

        else:
            # Unknown process type - raise explicit error
            supported_types = [
                "SCAN",
                "DEPENDENCY_ANALYSIS",
                "EXTRACT_ARCHIVES",
                "GIT_CLONE",
                "SCAN_REPORT_GENERATION",
                "PROJECT_REPORT_GENERATION",
                "REPORT_IMPORT",
                "NOTICE_EXTRACT_FILE",
                "NOTICE_EXTRACT_COMPONENT",
                "NOTICE_EXTRACT_AGGREGATE",
                "DELETE_SCAN",
            ]
            raise ValueError(
                f"Unsupported process type: '{process_type}'. "
                f"Supported types: {', '.join(supported_types)}"
            )
