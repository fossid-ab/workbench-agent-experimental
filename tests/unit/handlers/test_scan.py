# tests/unit/handlers/test_scan.py

import os
from unittest.mock import MagicMock, call, patch

import pytest

from workbench_agent.exceptions import (
    ApiError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchAgentError,
)

# Import handler and dependencies
from workbench_agent.handlers.scan import handle_scan
from workbench_agent.api.helpers.process_waiters import WaitResult


class TestScanHandler:
    """Test cases for the scan handler."""

    @patch("workbench_agent.handlers.scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.scan.print_operation_summary")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_success_full_scan(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests successful scan with both KB scan and dependency analysis."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = True

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = True

        # Mock unified waiting interface
        extraction_result = WaitResult(status_data={}, duration=5.0, success=True)
        scan_results = {
            "SCAN": WaitResult(status_data={}, duration=30.0, success=True),
            "DEPENDENCY_ANALYSIS": WaitResult(status_data={}, duration=15.0, success=True),
        }
        mock_workbench.check_and_wait_for_process.side_effect = [
            None,  # First call for idle check (returns None)
            extraction_result,  # Archive extraction
            None,  # Second idle check (returns None)
            scan_results,  # KB scan + DA
        ]

        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.resolve_project.assert_called_once_with(
            "ScanProject", create_if_missing=True
        )
        mock_workbench.resolve_scan.assert_called_once_with(
            scan_name="ScanTest",
            project_name="ScanProject",
            create_if_missing=True,
            params=mock_params,
        )
        mock_workbench.upload_scan_target.assert_called_once_with("SCAN_CODE", "/test/path")
        mock_workbench.extract_archives.assert_called_once_with(
            "SCAN_CODE", mock_params.recursively_extract_archives, mock_params.jar_file_extraction
        )
        mock_workbench.run_scan.assert_called_once()
        # Should have 4 calls to check_and_wait_for_process (2 idle checks + extraction + scan+DA)
        assert mock_workbench.check_and_wait_for_process.call_count == 4
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch("workbench_agent.handlers.scan.print_operation_summary")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_no_wait(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_workbench,
        mock_params,
    ):
        """Tests scan with no-wait mode."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False  # No extraction needed

        # Mock unified waiting interface (only idle checks, no actual waiting)
        mock_workbench.check_and_wait_for_process.return_value = None

        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.run_scan.assert_called_once()
        # Should only have idle checks in no-wait mode, no actual waiting
        assert mock_workbench.check_and_wait_for_process.call_count >= 1

    @patch("workbench_agent.handlers.scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.scan.print_operation_summary")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_dependency_analysis_only(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests scan with dependency analysis only."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = True

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False

        # Mock unified waiting interface
        da_result = WaitResult(status_data={}, duration=15.0, success=True)
        mock_workbench.check_and_wait_for_process.side_effect = [
            None,  # First idle check before uploading code
            None,  # Second idle check after upload to verify scan can start
            da_result,  # DA waiting
        ]

        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {"run_kb_scan": False, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with(
            "SCAN_CODE", import_only=False
        )
        mock_workbench.run_scan.assert_not_called()  # Should not run KB scan
        # Should have 3 calls: 2 idle checks + DA waiting
        assert mock_workbench.check_and_wait_for_process.call_count == 3
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_dependency_analysis_only_no_wait(
        self, mock_exists, mock_ensure_compat, mock_determine_scans, mock_workbench, mock_params
    ):
        """Tests scan with dependency analysis only and no-wait mode."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False

        # Mock unified waiting interface (only idle checks, no actual waiting)
        mock_workbench.check_and_wait_for_process.return_value = None

        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {"run_kb_scan": False, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with(
            "SCAN_CODE", import_only=False
        )
        # Should only have idle checks in no-wait mode, no actual waiting
        assert mock_workbench.check_and_wait_for_process.call_count >= 1

    def test_handle_scan_no_path(self, mock_workbench, mock_params):
        """Tests validation error when no path is provided."""
        # Configure params
        mock_params.command = "scan"
        mock_params.path = None

        # Execute and verify exception
        with pytest.raises(ValidationError, match="A path must be provided"):
            handle_scan(mock_workbench, mock_params)

    @patch("os.path.exists", return_value=False)
    def test_handle_scan_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = "scan"
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_scan(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_project_not_found(
        self, mock_exists, mock_ensure_compat, mock_workbench, mock_params
    ):
        """Tests scan when project resolution fails."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.id_reuse = False

        # Configure mocks
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_scan(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.scan.validate_reuse_source")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_with_id_reuse(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_validate_reuse,
        mock_workbench,
        mock_params,
    ):
        """Tests scan with ID reuse enabled."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = True
        # Set CLI argument that triggers ID reuse
        mock_params.reuse_project_ids = "REUSE_CODE"

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        mock_validate_reuse.return_value = ("project", "REUSE_CODE")

        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_validate_reuse.assert_called_once_with(mock_workbench, mock_params)
        mock_workbench.run_scan.assert_called_once()
        # Check that ID reuse parameters were passed (positional args)
        call_args = mock_workbench.run_scan.call_args
        args = call_args[0]
        assert args[7] is True  # id_reuse parameter (7th index)
        assert args[8] == "project"  # api_reuse_type parameter (8th index)
        assert args[9] == "REUSE_CODE"  # resolved_specific_code_for_reuse (9th index)

    @patch("workbench_agent.handlers.scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.scan.print_operation_summary")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_clear_content_fails(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests scan when clearing existing content fails."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.remove_uploaded_content.side_effect = Exception("Clear failed")
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False

        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute the handler - should continue despite clear failure
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.remove_uploaded_content.assert_called_once_with("SCAN_CODE", "")
        mock_workbench.upload_scan_target.assert_called_once()  # Should continue with upload

    @patch("workbench_agent.handlers.scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.scan.print_operation_summary")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_kb_scan_timeout(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests scan when KB scan times out."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False

        # Mock unified waiting interface to timeout on scan waiting
        mock_workbench.check_and_wait_for_process.side_effect = [
            None,  # Idle check passes
            ProcessTimeoutError("Scan timed out"),  # Scan waiting times out
        ]

        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute and verify exception
        with pytest.raises(ProcessTimeoutError):
            handle_scan(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.scan.print_operation_summary")
    @patch("workbench_agent.handlers.scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.scan.ensure_scan_compatibility")
    @patch("os.path.exists", return_value=True)
    def test_handle_scan_no_show_flags(
        self,
        mock_exists,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests scan when no show flags are provided."""
        # Configure params
        mock_params.command = "scan"
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = False
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False

        # Configure mocks
        mock_workbench.resolve_project.return_value = "SCAN_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False

        # Mock unified waiting interface
        scan_result = {"SCAN": WaitResult(status_data={}, duration=30.0, success=True)}
        mock_workbench.check_and_wait_for_process.side_effect = [
            None,  # Idle check
            scan_result,  # KB scan only
        ]

        # Mock scan operations to run KB scan only
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_print_summary.assert_called_once()
        # Should not fetch results when no show flags are provided
        mock_fetch.assert_not_called()
