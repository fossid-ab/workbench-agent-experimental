# tests/unit/handlers/test_blind_scan.py

import os
import tempfile
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
from workbench_agent.handlers.blind_scan import cleanup_temp_file, handle_blind_scan
from workbench_agent.api.helpers.process_waiters import WaitResult


class TestBlindScanHandler:
    """Test cases for the blind scan handler."""

    @patch("workbench_agent.handlers.blind_scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.blind_scan.print_operation_summary")
    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_success_full_scan(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests successful blind scan with both KB scan and dependency analysis."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = True
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"
        mock_params.run_dependency_analysis = True  # This is what gets passed to CLI wrapper

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None

        # Mock unified waiting interface
        scan_results = {
            "SCAN": WaitResult(status_data={}, duration=30.0, success=True),
            "DEPENDENCY_ANALYSIS": WaitResult(status_data={}, duration=15.0, success=True),
        }
        mock_workbench.check_and_wait_for_process.side_effect = [
            None,  # First idle check
            None,  # Second idle check
            scan_results,  # KB scan + DA
        ]

        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True

        # Verify CLI wrapper initialization and usage
        mock_cli_wrapper_class.assert_called_once_with(cli_path="/usr/bin/fossid-cli")
        mock_cli_wrapper.get_version.assert_called_once()
        mock_cli_wrapper.blind_scan.assert_called_once_with(
            path="/test/path",
            run_dependency_analysis=True,  # Should match params.run_dependency_analysis
        )

        # Verify workbench API calls
        mock_workbench.resolve_project.assert_called_once_with(
            "BlindScanProject", create_if_missing=True
        )
        mock_workbench.resolve_scan.assert_called_once_with(
            scan_name="BlindScanTest",
            project_name="BlindScanProject",
            create_if_missing=True,
            params=mock_params,
        )
        mock_workbench.upload_scan_target.assert_called_once_with(
            "BLIND_SCAN_CODE", "/tmp/hash_file.json"
        )
        mock_workbench.run_scan.assert_called_once()
        # Should have 3 calls to check_and_wait_for_process (2 idle checks + scan+DA)
        assert mock_workbench.check_and_wait_for_process.call_count == 3

        # Verify summary and results
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch("workbench_agent.handlers.blind_scan.print_operation_summary")
    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_no_wait(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan with no-wait mode."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None

        # Mock unified waiting interface (only idle checks, no actual waiting)
        mock_workbench.check_and_wait_for_process.return_value = None

        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.run_scan.assert_called_once()
        # Should only have idle checks in no-wait mode, no actual waiting
        assert mock_workbench.check_and_wait_for_process.call_count >= 1

    @patch("workbench_agent.handlers.blind_scan.fetch_display_save_results")
    @patch("workbench_agent.handlers.blind_scan.print_operation_summary")
    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_dependency_analysis_only(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan with dependency analysis only."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = True
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None

        # Mock unified waiting interface
        da_result = WaitResult(status_data={}, duration=15.0, success=True)
        mock_workbench.check_and_wait_for_process.side_effect = [
            None,  # First idle check before starting operations
            None,  # Second idle check after upload but before scan operations
            da_result,  # DA waiting
        ]

        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {"run_kb_scan": False, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with(
            "BLIND_SCAN_CODE", import_only=False
        )
        mock_workbench.run_scan.assert_not_called()  # Should not run KB scan
        # Should have 3 calls: 2 idle checks + DA waiting
        assert mock_workbench.check_and_wait_for_process.call_count == 3
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_dependency_analysis_only_no_wait(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan with dependency analysis only and no-wait mode."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None

        # Mock unified waiting interface (only idle checks, no actual waiting)
        mock_workbench.check_and_wait_for_process.return_value = None

        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {"run_kb_scan": False, "run_dependency_analysis": True}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with(
            "BLIND_SCAN_CODE", import_only=False
        )
        # Should only have idle checks in no-wait mode, no actual waiting
        assert mock_workbench.check_and_wait_for_process.call_count >= 1

    def test_handle_blind_scan_no_path(self, mock_workbench, mock_params):
        """Tests validation error when no path is provided."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.path = None

        # Execute and verify exception
        with pytest.raises(ValidationError, match="A path must be provided"):
            handle_blind_scan(mock_workbench, mock_params)

    @patch("os.path.exists", return_value=False)
    def test_handle_blind_scan_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_blind_scan(mock_workbench, mock_params)

    @patch("os.path.isdir", return_value=False)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_path_not_directory(
        self, mock_exists, mock_isdir, mock_workbench, mock_params
    ):
        """Tests validation error when path exists but is not a directory."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.path = "/path/to/file.txt"

        # Execute and verify exception
        with pytest.raises(
            ValidationError, match="The provided path must be a directory for blind-scan operations"
        ):
            handle_blind_scan(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_project_not_found(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan when project resolution fails."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.id_reuse = False
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"

        # Configure mocks
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_blind_scan(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_cli_version_warning(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan when CLI version check fails but continues."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.id_reuse = False
        mock_params.no_wait = True
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock with version failure
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.side_effect = Exception("CLI not found")
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None

        # Should continue despite CLI version warning
        result = handle_blind_scan(mock_workbench, mock_params)
        assert result is True
        mock_cli_wrapper.blind_scan.assert_called_once()

    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_cli_hash_generation_failure(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan when hash generation fails."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.id_reuse = False
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock with hash generation failure
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.side_effect = ProcessError("Hash generation failed")

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)

        # Execute and verify exception propagates
        with pytest.raises(ProcessError, match="Hash generation failed"):
            handle_blind_scan(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.blind_scan.validate_reuse_source")
    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_with_id_reuse(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_validate_reuse,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan with ID reuse enabled."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = True
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"
        # Set CLI argument that triggers ID reuse
        mock_params.reuse_project_ids = "REUSE_CODE"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_validate_reuse.return_value = ("project", "REUSE_CODE")

        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_validate_reuse.assert_called_once_with(mock_workbench, mock_params)
        mock_workbench.run_scan.assert_called_once()
        # Check that ID reuse parameters were passed
        call_args = mock_workbench.run_scan.call_args
        args = call_args[0]
        assert args[7] is True  # id_reuse parameter
        assert args[8] == "project"  # api_reuse_type parameter
        assert args[9] == "REUSE_CODE"  # resolved_specific_code_for_reuse

    @patch("workbench_agent.handlers.blind_scan.validate_reuse_source")
    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_id_reuse_validation_fails(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_validate_reuse,
        mock_workbench,
        mock_params,
    ):
        """Tests blind scan when ID reuse validation fails but continues without reuse."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = True
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"
        # Set CLI argument that triggers ID reuse
        mock_params.reuse_project_ids = "REUSE_CODE"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_validate_reuse.side_effect = ValidationError("ID reuse validation failed")

        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_validate_reuse.assert_called_once_with(mock_workbench, mock_params)
        # Should disable ID reuse and continue
        assert mock_params.id_reuse is False
        mock_workbench.run_scan.assert_called_once()
        # Check that ID reuse is disabled in the call
        call_args = mock_workbench.run_scan.call_args
        args = call_args[0]
        assert args[7] is False  # id_reuse parameter should be False

    @patch("workbench_agent.handlers.blind_scan.cleanup_temp_file")
    @patch("workbench_agent.handlers.blind_scan.print_operation_summary")
    @patch("workbench_agent.handlers.blind_scan.determine_scans_to_run")
    @patch("workbench_agent.handlers.blind_scan.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.blind_scan.CliWrapper")
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.exists", return_value=True)
    def test_handle_blind_scan_cleanup_called(
        self,
        mock_exists,
        mock_isdir,
        mock_cli_wrapper_class,
        mock_ensure_compat,
        mock_determine_scans,
        mock_print_summary,
        mock_cleanup,
        mock_workbench,
        mock_params,
    ):
        """Tests that cleanup is called in the finally block."""
        # Configure params
        mock_params.command = "blind-scan"
        mock_params.project_name = "BlindScanProject"
        mock_params.scan_name = "BlindScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        mock_params.fossid_cli_path = "/usr/bin/fossid-cli"

        # Configure CLI wrapper mock
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper_class.return_value = mock_cli_wrapper
        mock_cli_wrapper.get_version.return_value = "FossID CLI v2.1.0"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/hash_file.json"

        # Configure workbench mocks
        mock_workbench.resolve_project.return_value = "BLIND_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("BLIND_SCAN_CODE", 123)
        mock_workbench.upload_scan_target.return_value = None

        # Mock scan operations
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}

        # Execute the handler
        result = handle_blind_scan(mock_workbench, mock_params)

        # Verify cleanup was called
        assert result is True
        mock_cleanup.assert_called_once_with("/tmp/hash_file.json")


class TestCleanupTempFile:
    """Test cases for the cleanup_temp_file function."""

    @patch("os.path.exists", return_value=True)
    @patch("os.remove")
    def test_cleanup_temp_file_success(self, mock_remove, mock_exists):
        """Tests successful cleanup of temporary file."""
        result = cleanup_temp_file("/tmp/test_file.json")

        assert result is True
        mock_exists.assert_called_once_with("/tmp/test_file.json")
        mock_remove.assert_called_once_with("/tmp/test_file.json")

    @patch("os.path.exists", return_value=False)
    @patch("os.remove")
    def test_cleanup_temp_file_not_exists(self, mock_remove, mock_exists):
        """Tests cleanup when file doesn't exist."""
        result = cleanup_temp_file("/tmp/nonexistent_file.json")

        assert (
            result is True
        )  # Function returns True when file doesn't exist (already "cleaned up")
        mock_exists.assert_called_once_with("/tmp/nonexistent_file.json")
        mock_remove.assert_not_called()

    @patch("os.path.exists", return_value=True)
    @patch("os.remove", side_effect=OSError("Permission denied"))
    def test_cleanup_temp_file_failure(self, mock_remove, mock_exists):
        """Tests cleanup failure due to OS error."""
        result = cleanup_temp_file("/tmp/locked_file.json")

        assert result is False
        mock_exists.assert_called_once_with("/tmp/locked_file.json")
        mock_remove.assert_called_once_with("/tmp/locked_file.json")

    def test_cleanup_temp_file_none_path(self):
        """Tests cleanup with None path."""
        result = cleanup_temp_file(None)

        assert result is True  # Function returns True for None input (no-op cleanup)

    def test_cleanup_temp_file_empty_path(self):
        """Tests cleanup with empty path."""
        result = cleanup_temp_file("")

        assert result is True  # Function returns True for empty input (no-op cleanup)
