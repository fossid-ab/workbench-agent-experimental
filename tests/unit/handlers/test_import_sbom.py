# tests/unit/handlers/test_import_sbom.py

import os
from unittest.mock import MagicMock, call, patch

import pytest

from workbench_agent.exceptions import (
    ApiError,
    CompatibilityError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchAgentError,
)
from workbench_agent.handlers.import_sbom import (
    _get_project_and_scan_codes,
    _validate_sbom_file,
    handle_import_sbom,
)


class TestImportSBOMHandler:
    """Test cases for the import-sbom handler."""

    @patch("workbench_agent.handlers.import_sbom.fetch_display_save_results")
    @patch("workbench_agent.handlers.import_sbom.print_operation_summary")
    @patch("workbench_agent.handlers.import_sbom.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_success(
        self,
        mock_isfile,
        mock_exists,
        mock_validate_sbom,
        mock_ensure_compat,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests the successful execution of handle_import_sbom."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5

        # Configure mocks
        mock_validate_sbom.return_value = ("cyclonedx", "1.6", {"components_count": 42}, {})
        mock_workbench.resolve_project.return_value = "TEST_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("TEST_SCAN_CODE", 123)
        mock_workbench.check_and_wait_for_process.return_value = MagicMock(duration=5.0)

        # Execute the handler
        result = handle_import_sbom(mock_workbench, mock_params)

        # Verify the result and expected calls
        assert result is True
        mock_validate_sbom.assert_called_once_with("/path/to/sbom.json")
        mock_workbench.resolve_project.assert_called_once_with("SBOMProj", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with(
            "SBOMScan",
            "SBOMProj",
            create_if_missing=True,
            params=mock_params,
            import_from_report=True,
        )
        mock_ensure_compat.assert_called_once_with(mock_workbench, mock_params, "TEST_SCAN_CODE")
        mock_workbench.check_and_wait_for_process.assert_any_call(
            process_types=["REPORT_IMPORT"],
            scan_code="TEST_SCAN_CODE",
            max_tries=mock_params.scan_number_of_tries,
            wait_interval=mock_params.scan_wait_time,
        )
        mock_workbench.upload_sbom_file.assert_called_once_with(
            scan_code="TEST_SCAN_CODE", path="/path/to/sbom.json"
        )
        mock_workbench.import_report.assert_called_once_with(scan_code="TEST_SCAN_CODE")
        mock_workbench.check_and_wait_for_process.assert_any_call(
            process_types="REPORT_IMPORT",
            scan_code="TEST_SCAN_CODE",
            max_tries=mock_params.scan_number_of_tries,
            wait_interval=3,
        )
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch("os.path.exists", return_value=False)
    def test_handle_import_sbom_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_scan_not_found(
        self, mock_isfile, mock_exists, mock_validate_sbom, mock_workbench, mock_params
    ):
        """Tests the execution of handle_import_sbom with a scan not found."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5

        # Configure mocks
        mock_validate_sbom.return_value = ("cyclonedx", "1.5", {}, {})
        mock_workbench.resolve_project.return_value = "TEST_PROJ_CODE"
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

        # Execute and verify exception
        with pytest.raises(ScanNotFoundError):
            handle_import_sbom(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_project_not_found(
        self, mock_isfile, mock_exists, mock_validate_sbom, mock_workbench, mock_params
    ):
        """Tests the execution of handle_import_sbom with a project not found."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"

        # Configure mocks
        mock_validate_sbom.return_value = ("cyclonedx", "1.4", {}, {})
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_import_sbom(mock_workbench, mock_params)

    @patch("os.path.exists", return_value=False)
    def test_handle_import_sbom_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=False)
    def test_handle_import_sbom_path_not_file(
        self, mock_isfile, mock_exists, mock_workbench, mock_params
    ):
        """Tests validation error when path is not a file."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/path/to/directory"

        # Execute and verify exception
        with pytest.raises(ValidationError, match="must be a file"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch(
        "workbench_agent.handlers.import_sbom._validate_sbom_file",
        side_effect=ValidationError("Invalid SBOM format"),
    )
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_validation_error(
        self, mock_isfile, mock_exists, mock_validate_sbom, mock_workbench, mock_params
    ):
        """Tests handling of SBOM validation error."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/path/to/invalid.json"

        # Execute and verify exception
        with pytest.raises(ValidationError, match="Invalid SBOM format"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch(
        "workbench_agent.handlers.import_sbom.fetch_display_save_results",
        side_effect=ApiError("Error fetching results"),
    )
    @patch("workbench_agent.handlers.import_sbom.print_operation_summary")
    @patch("workbench_agent.handlers.import_sbom.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._prepare_spdx_for_upload")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_fetch_api_error(
        self,
        mock_isfile,
        mock_exists,
        mock_prepare_spdx,
        mock_validate_sbom,
        mock_ensure_compat,
        mock_print_summary,
        mock_fetch,
        mock_workbench,
        mock_params,
    ):
        """Tests handling of ApiError from fetch_display_save_results (should not fail the whole operation)."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/path/to/sbom.json"

        mock_spdx_doc = MagicMock()
        mock_spdx_doc.creation_info = MagicMock()
        mock_spdx_doc.files = []
        mock_spdx_doc.packages = []
        mock_spdx_doc.snippets = []
        mock_spdx_doc.extracted_licensing_info = []

        mock_validate_sbom.return_value = ("spdx", "2.3", {}, mock_spdx_doc)
        mock_prepare_spdx.return_value = "/path/to/sbom.json"  # Mock successful conversion
        mock_workbench.resolve_project.return_value = "TEST_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("TEST_SCAN_CODE", 123)
        mock_workbench.check_and_wait_for_process.return_value = MagicMock(duration=5.0)

        result = handle_import_sbom(mock_workbench, mock_params)

        assert result is True
        mock_fetch.assert_called_once()

    @patch("workbench_agent.handlers.import_sbom.print_operation_summary")
    @patch("workbench_agent.handlers.import_sbom.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._prepare_spdx_for_upload")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_upload_error(
        self,
        mock_isfile,
        mock_exists,
        mock_prepare_spdx,
        mock_validate_sbom,
        mock_ensure_compat,
        mock_print_summary,
        mock_workbench,
        mock_params,
    ):
        """Tests handling of upload error."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/path/to/sbom.json"

        mock_spdx_doc = MagicMock()
        mock_spdx_doc.creation_info = MagicMock()
        mock_spdx_doc.files = []
        mock_spdx_doc.packages = []
        mock_spdx_doc.snippets = []
        mock_spdx_doc.extracted_licensing_info = []

        mock_validate_sbom.return_value = ("spdx", "2.2", {}, mock_spdx_doc)
        mock_prepare_spdx.return_value = "/path/to/sbom.json"  # Mock successful conversion
        mock_workbench.resolve_project.return_value = "TEST_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("TEST_SCAN_CODE", 123)
        mock_workbench.upload_sbom_file.side_effect = ApiError("Upload failed")

        with pytest.raises(WorkbenchAgentError, match="Failed to upload SBOM file"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.import_sbom.print_operation_summary")
    @patch("workbench_agent.handlers.import_sbom.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_import_error(
        self,
        mock_isfile,
        mock_exists,
        mock_validate_sbom,
        mock_ensure_compat,
        mock_print_summary,
        mock_workbench,
        mock_params,
    ):
        """Tests handling of import_report error."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/path/to/sbom.json"
        mock_validate_sbom.return_value = ("cyclonedx", "1.5", {}, {})
        mock_workbench.resolve_project.return_value = "TEST_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("TEST_SCAN_CODE", 123)
        mock_workbench.import_report.side_effect = ApiError("Import failed")

        with pytest.raises(WorkbenchAgentError, match="Failed to start SBOM import"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch("workbench_agent.handlers.import_sbom.print_operation_summary")
    @patch("workbench_agent.handlers.import_sbom.ensure_scan_compatibility")
    @patch("workbench_agent.handlers.import_sbom._validate_sbom_file")
    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_handle_import_sbom_timeout_error(
        self,
        mock_isfile,
        mock_exists,
        mock_validate_sbom,
        mock_ensure_compat,
        mock_print_summary,
        mock_workbench,
        mock_params,
    ):
        """Tests handling of timeout during SBOM import."""
        # Configure params
        mock_params.command = "import-sbom"
        mock_params.path = "/path/to/sbom.json"
        mock_validate_sbom.return_value = ("cyclonedx", "1.4", {}, {})
        mock_workbench.resolve_project.return_value = "TEST_PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("TEST_SCAN_CODE", 123)
        mock_workbench.check_and_wait_for_process.side_effect = ProcessTimeoutError("Timed out")

        with pytest.raises(ProcessTimeoutError, match="Timed out"):
            handle_import_sbom(mock_workbench, mock_params)


class TestValidateSBOMFile:
    """Test cases for the _validate_sbom_file function."""

    @patch("workbench_agent.handlers.import_sbom.SBOMValidator.validate_sbom_file")
    def test_validate_sbom_file_success(self, mock_validator):
        """Tests successful SBOM validation."""
        mock_validator.return_value = (
            "cyclonedx",
            "1.6",
            {"components_count": 42},
            {"doc": "content"},
        )

        result = _validate_sbom_file("/path/to/sbom.json")

        assert result == ("cyclonedx", "1.6", {"components_count": 42}, {"doc": "content"})
        mock_validator.assert_called_once_with("/path/to/sbom.json")

    @patch("workbench_agent.handlers.import_sbom.SBOMValidator.validate_sbom_file")
    def test_validate_sbom_file_validation_error(self, mock_validator):
        """Tests SBOM validation error."""
        mock_validator.side_effect = ValidationError("Invalid format")

        with pytest.raises(ValidationError, match="Invalid format"):
            _validate_sbom_file("/path/to/invalid.json")

    @patch("workbench_agent.handlers.import_sbom.SBOMValidator.validate_sbom_file")
    def test_validate_sbom_file_unexpected_error(self, mock_validator):
        """Tests unexpected error during SBOM validation."""
        mock_validator.side_effect = Exception("Unexpected error")

        with pytest.raises(Exception, match="Unexpected error"):
            _validate_sbom_file("/path/to/sbom.json")


class TestGetProjectAndScanCodes:
    """Test cases for the _get_project_and_scan_codes function."""

    def test_get_project_and_scan_codes_success(self, mock_workbench, mock_params):
        """Tests successful project and scan code resolution."""
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"

        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 123)

        project_code, scan_code = _get_project_and_scan_codes(mock_workbench, mock_params)

        assert project_code == "PROJ_CODE"
        assert scan_code == "SCAN_CODE"
        mock_workbench.resolve_project.assert_called_once_with(
            "TestProject", create_if_missing=True
        )
        mock_workbench.resolve_scan.assert_called_once_with(
            "TestScan",
            "TestProject",
            create_if_missing=True,
            params=mock_params,
            import_from_report=True,
        )

    def test_get_project_and_scan_codes_project_error(self, mock_workbench, mock_params):
        """Tests project resolution error."""
        mock_params.project_name = "NonExistent"
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        with pytest.raises(ProjectNotFoundError):
            _get_project_and_scan_codes(mock_workbench, mock_params)

    def test_get_project_and_scan_codes_scan_error(self, mock_workbench, mock_params):
        """Tests scan resolution error."""
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"

        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

        with pytest.raises(ScanNotFoundError):
            _get_project_and_scan_codes(mock_workbench, mock_params)
