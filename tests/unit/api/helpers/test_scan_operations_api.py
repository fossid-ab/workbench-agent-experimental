# tests/unit/api/helpers/test_scan_operations_api.py

from unittest.mock import MagicMock, patch

import pytest
import requests

from workbench_agent.api.helpers.scan_operations_api import ScanOperationsAPI
from workbench_agent.api.helpers.process_waiters import WaitResult
from workbench_agent.api.helpers.process_status_checkers import StatusResult
from workbench_agent.exceptions import (
    ApiError,
    ProcessError,
    ProcessTimeoutError,
    ScanNotFoundError,
)


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def scan_operations_inst(mock_session):
    """Create a ScanOperationsAPI instance with a properly mocked session."""

    # Create a concrete instance for testing
    class TestScanOperationsAPI(ScanOperationsAPI):
        def __init__(self, api_url, api_user, api_token):
            self.api_url = api_url
            self.api_user = api_user
            self.api_token = api_token
            self.session = mock_session

        def _send_request(self, payload, timeout=1800):
            # Mock implementation
            return {"status": "1", "data": {}}

        def check_status(self, scan_code, operation_type, process_id=None):
            # Mock implementation for abstract method
            return {"status": "FINISHED"}

        def check_status_download_content_from_git(self, scan_code):
            # Mock implementation for abstract method
            return {"data": "FINISHED"}

        def check_project_report_status(self, process_id, project_code):
            # Mock implementation for abstract method
            return {"status": "FINISHED"}

    api = TestScanOperationsAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    return api


# --- Test build_run_scan_data ---
def test_build_run_scan_data_basic(scan_operations_inst):
    """Test building a basic scan payload."""
    result = scan_operations_inst.build_run_scan_data(
        scan_code="test_scan",
        limit=100,
        sensitivity=80,
        autoid_file_licenses=True,
        autoid_file_copyrights=False,
        autoid_pending_ids=True,
        delta_scan=False,
        id_reuse=False,
    )

    expected = {
        "scan_code": "test_scan",
        "limit": 100,
        "sensitivity": 80,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 0,
        "auto_identification_resolve_pending_ids": 1,
        "delta_only": 0,
        "replace_existing_identifications": 0,
        "scan_failed_only": 0,
        "full_file_only": 0,
        "advanced_match_scoring": 1,
    }

    assert result == expected


def test_build_run_scan_data_with_optional_params(scan_operations_inst):
    """Test building scan payload with optional parameters."""
    result = scan_operations_inst.build_run_scan_data(
        scan_code="test_scan",
        limit=50,
        sensitivity=90,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=True,
        id_reuse=True,
        id_reuse_type="full",
        id_reuse_source="previous_scan",
        run_dependency_analysis=True,
        replace_existing_identifications=True,
        scan_failed_only=True,
        full_file_only=True,
    )

    assert result["reuse_identification"] == "1"
    assert result["identification_reuse_type"] == "any"  # "full" maps to "any"
    # Note: specific_code is only included for specific_project/specific_scan types
    assert result["run_dependency_analysis"] == "1"  # String for this field
    assert result["replace_existing_identifications"] == 1
    assert result["scan_failed_only"] == 1
    assert result["full_file_only"] == 1


# --- Test build_extract_archives_data ---
def test_build_extract_archives_data_basic(scan_operations_inst):
    """Test building extract archives data."""
    result = scan_operations_inst.build_extract_archives_data(
        scan_code="test_scan", recursively_extract_archives=True, jar_file_extraction=False
    )

    expected = {
        "scan_code": "test_scan",
        "recursively_extract_archives": "true",
        "jar_file_extraction": "false",
    }

    assert result == expected


def test_build_extract_archives_data_with_options(scan_operations_inst):
    """Test building extract archives data with different options."""
    result = scan_operations_inst.build_extract_archives_data(
        scan_code="another_scan", recursively_extract_archives=False, jar_file_extraction=True
    )

    expected = {
        "scan_code": "another_scan",
        "recursively_extract_archives": "false",
        "jar_file_extraction": "true",
    }

    assert result == expected


# --- Test build_dependency_analysis_data ---
def test_build_dependency_analysis_data_basic(scan_operations_inst):
    """Test building dependency analysis data."""
    result = scan_operations_inst.build_dependency_analysis_data(
        scan_code="test_scan", import_only=False
    )

    expected = {"scan_code": "test_scan", "import_only": "0"}

    assert result == expected


def test_build_dependency_analysis_data_import_only(scan_operations_inst):
    """Test building dependency analysis data for import-only mode."""
    result = scan_operations_inst.build_dependency_analysis_data(
        scan_code="import_scan", import_only=True
    )

    expected = {"scan_code": "import_scan", "import_only": "1"}

    assert result == expected


# --- Test integration with ProcessWaiters and ProcessStatusCheckers ---
def test_inheritance_integration(scan_operations_inst):
    """Test that ScanOperationsAPI properly inherits from multiple classes."""
    # Should have methods from ProcessWaiters
    assert hasattr(scan_operations_inst, "wait_for_completion")
    assert hasattr(scan_operations_inst, "wait_for_scan_completion")

    # Should have methods from ProcessStatusCheckers
    assert hasattr(scan_operations_inst, "check_scan_status")
    assert hasattr(scan_operations_inst, "check_dependency_analysis_status")

    # Should have methods from BaseAPI
    assert hasattr(scan_operations_inst, "_send_request")


def test_scan_operations_api_method_resolution(scan_operations_inst, mocker):
    """Test that method resolution order works correctly."""
    # Mock the status checking method
    with patch.object(scan_operations_inst, "check_scan_status") as mock_check:
        mock_check.return_value = StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

        # Call a method that should use the status checker
        result = scan_operations_inst.check_scan_status("test_scan")

        assert isinstance(result, StatusResult)
        assert result.status == "FINISHED"
        mock_check.assert_called_once_with("test_scan")
